"""Round-trip tests: write terminfo binary, verify via curses in a subprocess.

Uses real XTGETTCAP data from ucs-detect YAML files.

Each terminal is verified in a separate subprocess because
``curses.setupterm()`` can only be called once per process.

Representative terminals are tested by default.  Run with ``--run-all-roundtrip``
to test all available terminals.
"""

import json
import os
import subprocess
import sys
import tempfile
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List

import pytest
import yaml

from ttyscan._terminfo import (
    _CANONICAL_BOOL_CAPS,
    _CANONICAL_NUM_CAPS,
    _CANONICAL_STR_CAPS,
    _build_terminfo_binary,
    sanitize_term_name,
    terminfo_path,
)

# Subprocess script that verifies compiled terminfo via curses.
# One subprocess per terminal since curses.setupterm() is single-call.
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

# Representative terminals covering minimal, medium, and full profiles.
_REPRESENTATIVE_TERMINALS = frozenset({
    'xterm.yaml',           # 95 caps, mostly keys
    'kitty.yaml',           # 221 caps, full terminfo
    'foot.yaml',            # 210 caps, full terminfo
    'AbsoluteTelnetSSH.yaml',  # 5 caps, bare minimum
    'mlterm.yaml',          # 39 caps, medium
})


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


@lru_cache(maxsize=1)
def _load_all_terminals() -> List[Dict[str, Any]]:
    """Load all terminals with non-empty XTGETTCAP data (cached)."""
    data_dir = Path(__file__).resolve().parent.parent.parent / 'ucs-detect' / 'data'
    terminals = []
    for yaml_file in sorted(data_dir.glob('*.yaml')):
        with open(yaml_file) as f:
            doc = yaml.safe_load(f)
        xt = doc.get('terminal_results', {}).get('xtgettcap', {})
        if xt.get('supported') and xt.get('capabilities'):
            terminals.append({
                'file': yaml_file.name,
                'software_name': doc.get('software_name', ''),
                'capabilities': xt['capabilities'],
            })
    return terminals


def _terminal_ids(config) -> List[str]:
    """Return terminal identifiers for parametrization."""
    all_terminals = _load_all_terminals()
    if config.getoption('--run-all-roundtrip'):
        return [t['file'] for t in all_terminals]
    return [t['file'] for t in all_terminals
            if t['file'] in _REPRESENTATIVE_TERMINALS]


def _get_terminal(yaml_file: str) -> Dict[str, Any]:
    """Get terminal data by YAML filename."""
    for t in _load_all_terminals():
        if t['file'] == yaml_file:
            return t
    raise ValueError(f"Terminal {yaml_file} not found")


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
                          terminfo_dir: Path) -> subprocess.CompletedProcess:
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


def pytest_generate_tests(metafunc):
    """Parametrize roundtrip tests dynamically."""
    if 'yaml_file' in metafunc.fixturenames:
        ids = _terminal_ids(metafunc.config)
        metafunc.parametrize('yaml_file', ids)


@pytest.mark.slow
def test_roundtrip(yaml_file, tmp_path, request):
    """Write terminfo binary and verify via curses subprocess."""
    terminal = _get_terminal(yaml_file)
    caps = terminal['capabilities']
    classified = _classify_caps(caps)
    tn = sanitize_term_name(caps.get('TN', terminal['software_name']))

    data = _build_terminfo_binary(
        tn,
        str_caps=classified['str_caps'],
        num_caps=classified['num_caps'],
        bool_caps=classified['bool_caps'],
    )
    assert data is not None, f"Failed to build terminfo binary for {yaml_file}"

    file_path = terminfo_path(tn, tmp_path)
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_bytes(data)

    result = _verify_in_subprocess(tn, classified, tmp_path)
    if result.returncode != 0:
        stderr = result.stderr.strip()
        assert False, (
            f"Round-trip verification failed for {yaml_file} ({tn}):\n{stderr}"
        )
