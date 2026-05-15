"""Build and install terminfo entries from XTGETTCAP capabilities.

Uses a pure-Python compiled terminfo writer (no external ``tic`` dependency)
validated against the ncurses 6.6 Caps canonical ordering.
"""

import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Set

from ._caps_data import _CANONICAL_BOOL_CAPS, _CANONICAL_NUM_CAPS, _CANONICAL_STR_CAPS


def _build_index(caps: List[str]) -> Dict[str, int]:
    """Build a name-to-index mapping from a canonical capability list."""
    return {name: idx for idx, name in enumerate(caps)}


_BOOL_INDEX: Dict[str, int] = _build_index(_CANONICAL_BOOL_CAPS)
_NUM_INDEX: Dict[str, int] = _build_index(_CANONICAL_NUM_CAPS)
_STR_INDEX: Dict[str, int] = _build_index(_CANONICAL_STR_CAPS)

_TERMINFO_MAGIC: int = 0o432  # 16-bit numerics
_TERMINFO_MAGIC2: int = 0o1036  # 32-bit numerics
_SENTINEL_ABSENT: int = -1    # 0xFFFF / 0xFFFFFFFF


def sanitize_term_name(name: str) -> str:
    """Sanitize a terminal name for use in file paths.

    Allows alphanumeric characters, hyphens, underscores, and dots.
    Ensures the name starts with an alphanumeric character (not dot).
    """
    cleaned = re.sub(r'[^a-zA-Z0-9._-]', '', name)
    cleaned = cleaned.lstrip('.')
    if not cleaned:
        return 'unknown'
    return cleaned


def has_terminfo(term: str) -> bool:
    """Return whether *term* has an entry in the curses terminfo database."""
    try:
        import curses  # pylint: disable=import-outside-toplevel
        curses.setupterm(term)
        return True
    except Exception:  # pylint: disable=broad-exception-caught
        return False


def build_terminfo_source(
    term: str,
    str_caps: Dict[str, str],
    num_caps: Dict[str, int],
    bool_caps: Set[str],
) -> str:
    """Build a terminfo source entry from classified capabilities."""
    lines = [f"{term}|XTGETTCAP-discovered terminal,"]

    for cap in sorted(bool_caps):
        lines.append(f"\t{cap},")
    for cap in sorted(num_caps):
        lines.append(f"\t{cap}#{num_caps[cap]},")
    for cap in sorted(str_caps):
        value = str_caps[cap]
        escaped = _escape_terminfo_value(value)
        lines.append(f"\t{cap}={escaped},")

    return "\n".join(lines)


def compile_terminfo(source: str, dest_dir: Path) -> bool:
    """Compile terminfo source into *dest_dir* using ``tic`` (fallback).

    Returns True on success.
    """
    tic = shutil.which("tic")
    if not tic:
        return False

    fd, source_path = tempfile.mkstemp(suffix=".ti", prefix="ttyscan_")
    os.write(fd, source.encode("utf-8"))
    os.close(fd)

    success = False
    try:
        result = subprocess.run(
            [tic, "-o", str(dest_dir), source_path],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        success = result.returncode == 0
    except (subprocess.SubprocessError, OSError):
        pass

    try:
        os.unlink(source_path)
    except OSError:
        pass

    return success


def write_terminfo(
    term: str,
    str_caps: Dict[str, str],
    num_caps: Dict[str, int],
    bool_caps: Set[str],
    dest_dir: Path,
) -> bool:
    """Write a compiled terminfo entry to *dest_dir* using pure Python.

    Returns True on success.
    """
    safe_term = sanitize_term_name(term)
    data = _build_terminfo_binary(safe_term, str_caps, num_caps, bool_caps)

    file_path = terminfo_path(safe_term, dest_dir)
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_bytes(data)
    return True


def _build_terminfo_binary(  # pylint: disable=too-many-locals,too-many-branches,too-many-statements
    term: str,
    str_caps: Dict[str, str],
    num_caps: Dict[str, int],
    bool_caps: Set[str],
) -> Optional[bytes]:
    """Build a compiled terminfo entry as bytes.

    Returns None if the data cannot be constructed.
    """
    # Build the terminal names section
    names = f"{term}|XTGETTCAP-discovered terminal"
    names_bytes = names.encode("ascii", errors="replace") + b"\x00"
    name_size = len(names_bytes)

    # Boolean section: determine highest index any present bool cap
    bool_indices: List[int] = []
    for cap in bool_caps:
        idx = _BOOL_INDEX.get(cap)
        if idx is not None:
            bool_indices.append(idx)

    if not bool_indices:
        bool_max = 0
    else:
        bool_max = max(bool_indices) + 1

    bool_data = bytearray(bool_max)
    for idx in bool_indices:
        bool_data[idx] = 1

    # Numeric section
    num_entries: List[tuple] = []  # (index, value)
    for cap, val in num_caps.items():
        idx = _NUM_INDEX.get(cap)
        if idx is not None:
            num_entries.append((idx, val))

    if not num_entries:
        num_max = 0
    else:
        num_max = max(idx for idx, _ in num_entries) + 1

    use_32bit = any(
        val > 32767 or val < -32768 for _, val in num_entries
    )
    num_entry_size = 4 if use_32bit else 2
    magic = _TERMINFO_MAGIC2 if use_32bit else _TERMINFO_MAGIC

    num_data = bytearray(num_max * num_entry_size)
    for idx, val in num_entries:
        if use_32bit:
            struct.pack_into("<i", num_data, idx * 4, val)
        else:
            _pack_short_le(num_data, idx * 2, val)

    # Fill absent numerics with -1 sentinel
    num_used = set(idx for idx, _ in num_entries)
    for i in range(num_max):
        if i not in num_used:
            if use_32bit:
                struct.pack_into("<i", num_data, i * 4, _SENTINEL_ABSENT)
            else:
                _pack_short_le(num_data, i * 2, _SENTINEL_ABSENT)

    # String section: build offset table and string table
    str_entries: List[tuple] = []  # (index, raw_value)
    for cap, val in str_caps.items():
        idx = _STR_INDEX.get(cap)
        if idx is not None:
            str_entries.append((idx, val.encode("utf-8", errors="replace")))

    if not str_entries:
        str_max = 0
    else:
        str_max = max(idx for idx, _ in str_entries) + 1

    # Build string table and compute offsets
    str_table_parts: List[bytes] = []
    offsets: Dict[int, int] = {}
    for idx, raw in sorted(str_entries):
        offsets[idx] = len(b"".join(str_table_parts))
        str_table_parts.append(raw + b"\x00")

    str_table = b"".join(str_table_parts)

    # Build offset data
    offset_data = bytearray(str_max * 2)
    for i in range(str_max):
        if i in offsets:
            _pack_short_le(offset_data, i * 2, offsets[i])
        else:
            _pack_short_le(offset_data, i * 2, _SENTINEL_ABSENT)

    # Assemble the file
    header = bytearray(12)
    _pack_short_le(header, 0, magic)
    _pack_short_le(header, 2, name_size)
    _pack_short_le(header, 4, bool_max)
    _pack_short_le(header, 6, num_max)
    _pack_short_le(header, 8, str_max)
    _pack_short_le(header, 10, len(str_table))

    parts: List[bytes] = [bytes(header), names_bytes, bytes(bool_data)]

    # Alignment: NUL byte if (name_size + bool_max) is odd
    if (name_size + bool_max) % 2 != 0:
        parts.append(b"\x00")

    parts.append(bytes(num_data))
    parts.append(bytes(offset_data))
    parts.append(str_table)

    return b"".join(parts)


def _pack_short_le(buf: bytearray, offset: int, value: int) -> None:
    """Pack a signed short into *buf* at *offset* as little-endian.

    Python ``struct`` packs shorts, but we need to handle -1 as 0xFFFF.
    """
    packed = struct.pack("<h", value)
    buf[offset:offset + 2] = packed


def validate_terminfo(term: str, base_dir: Path) -> Optional[str]:
    """Validate a compiled terminfo entry using ``infocmp``.

    Returns None on success, or an error message string on failure.
    """
    infocmp = shutil.which("infocmp")
    if not infocmp:
        return None  # cannot validate, but not a failure

    file_path = terminfo_path(term, base_dir)
    if not file_path.exists():
        return f"terminfo file not found at {file_path}"

    env = {**os.environ, "TERMINFO": str(base_dir)}
    try:
        result = subprocess.run(
            [infocmp, "-1", term],
            capture_output=True,
            text=True,
            timeout=10,
            env=env,
            check=False,
        )
        if result.returncode != 0:
            return result.stderr.strip() or f"infocmp failed with code {result.returncode}"
        if not result.stdout.strip():
            return "infocmp produced empty output"
    except (subprocess.SubprocessError, OSError) as exc:
        return str(exc)

    return None  # success


def verify_terminfo_via_curses(term: str, base_dir: Path) -> Optional[str]:
    """Verify a compiled terminfo entry by spawning a subprocess that
    calls ``curses.setupterm()`` with ``TERMINFO`` set to *base_dir*.

    Returns None on success, or an error message string on failure.
    """
    check_script = (
        f"import curses, os, sys\n"
        f"os.environ['TERMINFO'] = {str(base_dir)!r}\n"
        f"try:\n"
        f"    curses.setupterm({term!r})\n"
        f"    sys.exit(0)\n"
        f"except Exception as e:\n"
        f"    print(str(e), file=sys.stderr)\n"
        f"    sys.exit(1)\n"
    )
    try:
        result = subprocess.run(
            [sys.executable, "-c", check_script],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if result.returncode != 0:
            return result.stderr.strip() or "setupterm failed"
    except (subprocess.SubprocessError, OSError) as exc:
        return str(exc)

    return None


def terminfo_path(term: str, base_dir: Path) -> Path:
    """Return the expected path of a compiled terminfo entry."""
    return base_dir / term[0] / term


def terminfo_installed(term: str, base_dir: Path) -> bool:
    """Return whether a compiled terminfo entry exists at *base_dir*."""
    return terminfo_path(term, base_dir).exists()


def _escape_terminfo_value(value: str) -> str:
    """Escape a raw capability value for terminfo source format."""
    return _escape_value(value, terminfo=True)


def _escape_value(value: str, terminfo: bool = False) -> str:
    """Escape a raw capability value for terminfo or termcap source format."""
    simple = {
        "\x1b": "\\E", "\n": "\\n", "\t": "\\t", "\r": "\\r",
        "\b": "\\b", "\f": "\\f", "\\": "\\\\", "^": "\\^",
    }
    if terminfo:
        simple[" "] = "\\s"
        simple[":"] = "\\:"

    result = []
    for ch in value:
        if ch in simple:
            result.append(simple[ch])
            continue
        code = ord(ch)
        if code < 32:
            result.append(f"^{chr(code + 64)}")
        elif code == 127:
            result.append("^?")
        else:
            result.append(ch)
    return "".join(result)


def _ttyscan_terminfo_dir() -> Path:
    """Return the ttyscan-specific terminfo directory under XDG config."""
    xdg_config = os.environ.get(
        "XDG_CONFIG_HOME",
        os.path.join(os.path.expanduser("~"), ".config"),
    )
    return Path(xdg_config) / "ttyscan" / "terminfo"


def ensure_terminfo(
    term: str,
    str_caps: Dict[str, str],
    num_caps: Dict[str, int],
    bool_caps: Set[str],
    force: bool = False,
) -> Optional[Path]:
    """Ensure a terminfo entry exists for *term*.

    Writes into the ttyscan-specific directory under XDG config, never
    into the system database or an existing ``$TERMINFO``.

    When *force* is True, (re-)installs the terminfo entry unconditionally.

    Returns the ``TERMINFO`` directory path if a terminfo was installed,
    or None if the system database already has this entry (and *force* is
    False).
    """
    if not force and has_terminfo(term):
        return None

    dest_dir = _ttyscan_terminfo_dir()
    safe_term = sanitize_term_name(term)

    # Try pure-Python writer first
    installed = write_terminfo(term, str_caps, num_caps, bool_caps, dest_dir)
    if not installed:
        # Fall back to tic
        dest_dir.mkdir(parents=True, exist_ok=True)
        source = build_terminfo_source(term, str_caps, num_caps, bool_caps)
        installed = compile_terminfo(source, dest_dir)

    if not installed:
        return None

    # Validate via infocmp (informational only, failure is non-fatal)
    _ = validate_terminfo(safe_term, dest_dir)

    # Verify via curses in a subprocess
    err = verify_terminfo_via_curses(safe_term, dest_dir)
    if err:
        file_path = terminfo_path(safe_term, dest_dir)
        print(
            f"ttyscan: warning: terminfo installed at {file_path}, "
            f"but curses.setupterm('{safe_term}') failed: {err}",
            file=sys.stderr,
        )

    return dest_dir
