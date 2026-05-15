"""Round-trip tests: write terminfo binary, verify via curses in a subprocess.

Uses inline XTGETTCAP data collected from ucs-detect in May 2026.

Each terminal is verified in a separate subprocess because
``curses.setupterm()`` can only be called once per process.
"""

import json
import os
import subprocess
import sys
import tempfile
from typing import Any, Dict, List

import pytest

from ttyscan._terminfo import (
    _CANONICAL_BOOL_CAPS,
    _CANONICAL_NUM_CAPS,
    _CANONICAL_STR_CAPS,
    _build_terminfo_binary,
    sanitize_term_name,
    terminfo_path,
)

# Subprocess script that verifies compiled terminfo via curses.
_VERIFY_SCRIPT = r"""
import curses, json, os, sys
with open(sys.argv[1]) as f:
    expected = json.load(f)
curses.setupterm(expected['term_name'])
errors = []
for cap in expected['bool_caps']:
    val = curses.tigetflag(cap)
    if val != 1:
        errors.append(f'bool {cap}: expected 1, got {val}')
for cap, exp_val in expected['num_caps'].items():
    val = curses.tigetnum(cap)
    if val != exp_val:
        errors.append(f'num {cap}: expected {exp_val}, got {val}')
for cap, exp_val in expected['str_caps'].items():
    raw = curses.tigetstr(cap)
    if raw is None:
        errors.append(f'str {cap}: expected value, got None')
    else:
        val = raw.decode('utf-8', errors='replace')
        if val != exp_val:
            errors.append(f'str {cap}: expected {exp_val!r}, got {val!r}')
if errors:
    for err in errors:
        print(err, file=sys.stderr)
    sys.exit(1)
print('OK')
"""

# XTGETTCAP data collected from ucs-detect, May 2026.
# Only a subset of caps is included to keep the test data compact while
# still exercising the terminfo binary writer across all cap types.
_KITTY_XTGETTCAP = {
    'supported': True,
    'software_name': 'kitty',
    'capabilities': {
        'TN': 'xterm-kitty',
        'RGB': '8/8/8',
        # Boolean caps
        'am': '', 'bce': '', 'ccc': '', 'km': '', 'mc5i': '',
        'mir': '', 'msgr': '', 'npc': '', 'xenl': '',
        'hs': '', 'bw': '',
        # Numeric caps
        'colors': '256', 'cols': '80', 'lines': '24', 'pairs': '32767',
        'it': '8',
        # String caps (screen/output)
        'acsc': '++\\,,-..00``aaffgghhiijjkkllmmnnooppqqrrssttuuvvwwxxyyzz{{||}}~~',
        'bel': '\x07',
        'blink': '\x1b[5m',
        'bold': '\x1b[1m',
        'civis': '\x1b[?25l',
        'clear': '\x1b[H\x1b[2J',
        'cnorm': '\x1b[?12h\x1b[?25h',
        'cr': '\r',
        'csr': '\x1b[%i%p1%d;%p2%dr',
        'cub': '\x1b[%p1%dD',
        'cub1': '\x08',
        'cud': '\x1b[%p1%dB',
        'cud1': '\n',
        'cuf': '\x1b[%p1%dC',
        'cuf1': '\x1b[C',
        'cup': '\x1b[%i%p1%d;%p2%dH',
        'cuu': '\x1b[%p1%dA',
        'cuu1': '\x1b[A',
        'cvvis': '\x1b[?12;25h',
        'dch1': '\x1b[P',
        'dim': '\x1b[2m',
        'dl1': '\x1b[M',
        'ech': '\x1b[%p1%dX',
        'ed': '\x1b[J',
        'el': '\x1b[K',
        'el1': '\x1b[1K',
        'flash': '\x1b[?5h$<100/>\x1b[?5l',
        'home': '\x1b[H',
        'hpa': '\x1b[%i%p1%dG',
        'ht': '\t',
        'hts': '\x1bH',
        'il1': '\x1b[L',
        'ind': '\n',
        'op': '\x1b[39;49m',
        'rc': '\x1b8',
        'rev': '\x1b[7m',
        'ri': '\x1bM',
        'ritm': '\x1b[23m',
        'rmacs': '\x1b(B',
        'rmam': '\x1b[?7l',
        'rmcup': '\x1b[?1049l',
        'rmir': '\x1b[4l',
        'rmkx': '\x1b[?1l',
        'rmso': '\x1b[27m',
        'rmul': '\x1b[24m',
        'sc': '\x1b7',
        'sgr0': '\x1b(B\x1b[m',
        'sitm': '\x1b[3m',
        'smacs': '\x1b(0',
        'smam': '\x1b[?7h',
        'smcup': '\x1b[?1049h',
        'smir': '\x1b[4h',
        'smkx': '\x1b[?1h',
        'smso': '\x1b[7m',
        'smul': '\x1b[4m',
        'tbc': '\x1b[3g',
        'u6': '\x1b[%i%d;%dR',
        'u7': '\x1b[6n',
        'vpa': '\x1b[%i%p1%dd',
    },
}


def _classify_caps(capabilities: Dict[str, str]) -> Dict[str, Any]:
    """Classify capabilities like make_jinxed_capabilities() does."""
    bool_caps = set()
    num_caps: Dict[str, int] = {}
    str_caps: Dict[str, str] = {}

    bool_set = frozenset(_CANONICAL_BOOL_CAPS)
    num_set = frozenset(_CANONICAL_NUM_CAPS)
    str_set = frozenset(_CANONICAL_STR_CAPS)

    for name, value in capabilities.items():
        if name == 'RGB':
            continue
        if not value:
            if name in bool_set:
                bool_caps.add(name)
        elif name in num_set:
            if value.isdigit():
                num_caps[name] = int(value)
        elif name in str_set:
            str_caps[name] = value

    return {'bool_caps': bool_caps, 'num_caps': num_caps, 'str_caps': str_caps}


def _build_expected_json(term: str, classified: Dict[str, Any]) -> str:
    """Build the JSON payload for the verification subprocess."""
    expected = {
        'term_name': term,
        'bool_caps': sorted(classified['bool_caps']),
        'num_caps': classified['num_caps'],
        'str_caps': classified['str_caps'],
    }
    return json.dumps(expected)


def _verify_in_subprocess(term: str, classified: Dict[str, Any],
                          terminfo_dir: Any) -> subprocess.CompletedProcess:
    """Spawn a subprocess to verify the terminfo entry via curses."""
    json_payload = _build_expected_json(term, classified)
    with tempfile.NamedTemporaryFile(
        mode='w', suffix='.json', prefix='ttyscan_verify_', delete=False,
    ) as f:
        f.write(json_payload)
        json_path = f.name

    env = {**os.environ, 'TERMINFO': str(terminfo_dir), 'TERM': term}
    try:
        result = subprocess.run(
            [sys.executable, '-c', _VERIFY_SCRIPT, json_path],
            capture_output=True, text=True, timeout=30, env=env,
            check=False,
        )
    finally:
        try:
            os.unlink(json_path)
        except OSError:
            pass

    return result


@pytest.mark.parametrize('xtgettcap_data', [_KITTY_XTGETTCAP])
def test_roundtrip(xtgettcap_data, tmp_path):
    """Write terminfo binary and verify via curses subprocess."""
    caps = xtgettcap_data['capabilities']
    classified = _classify_caps(caps)
    tn = sanitize_term_name(caps.get('TN', xtgettcap_data['software_name']))

    data = _build_terminfo_binary(
        tn,
        str_caps=classified['str_caps'],
        num_caps=classified['num_caps'],
        bool_caps=classified['bool_caps'],
    )
    assert data is not None, "Failed to build terminfo binary"

    file_path = terminfo_path(tn, tmp_path)
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_bytes(data)

    result = _verify_in_subprocess(tn, classified, tmp_path)
    if result.returncode != 0:
        stderr = result.stderr.strip()
        assert False, (
            f"Round-trip verification failed for kitty ({tn}):\n{stderr}"
        )
