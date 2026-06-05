"""Tests for ttyscan module."""

import io
import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from ttyscan import (
    build_termcap_entry,
    build_terminfo_binary,
    check_colorterm,
    check_lines_columns,
    check_term,
    check_term_program,
    classify_caps,
    decqss_query,
    escape_value,
    has_meaningful_caps,
    hex_decode,
    hex_encode,
    normalize_terminal_name,
    pack_short_le,
    probe_truecolor,
    sanitize_term_name,
    shell_escape,
    terminfo_file_path,
    terminfo_installed_at,
    ttyscan_terminfo_dir,
    unescape_terminfo,
    verbose,
    warn,
    _parse_xtversion_text,
    xtversion_query,
)
from ttyscan import write_terminfo as _write_terminfo


def _pty_run(args, env, response, timeout=5.0):
    """Run a command in a PTY child with canned terminal response.

    Returns ``(output_text, wait_status)``.
    """
    import fcntl
    import select
    import struct
    import termios

    pid, master_fd = os.forkpty()
    if pid == 0:
        os.execve(sys.executable, args, env)
        os._exit(1)

    winsize = struct.pack("HHHH", 31, 128, 0, 0)
    fcntl.ioctl(master_fd, termios.TIOCSWINSZ, winsize)
    attrs = termios.tcgetattr(master_fd)
    attrs[3] = attrs[3] & ~termios.ECHO
    termios.tcsetattr(master_fd, termios.TCSANOW, attrs)

    os.write(master_fd, response)

    output = b""
    deadline = __import__("time").monotonic() + timeout
    while __import__("time").monotonic() < deadline:
        ready, _, _ = select.select([master_fd], [], [], 0.3)
        if ready:
            try:
                chunk = os.read(master_fd, 4096)
            except OSError:
                break
            if not chunk:
                break
            output += chunk

    _, status = os.waitpid(pid, 0)
    return output.decode("utf-8", errors="replace"), status


def _pty_run_staggered(args, env, responses, timeout=5.0):
    """Run a command in a PTY child, writing response chunks with delays.

    ``responses`` is a list of ``(delay_sec, data)`` tuples.  Each chunk
    is written after its corresponding delay, allowing multiple
    ``read_until`` rounds to consume separate response segments.
    Returns ``(output_text, wait_status)``.
    """
    import fcntl
    import select
    import struct
    import termios

    pid, master_fd = os.forkpty()
    if pid == 0:
        os.execve(sys.executable, args, env)
        os._exit(1)

    winsize = struct.pack("HHHH", 31, 128, 0, 0)
    fcntl.ioctl(master_fd, termios.TIOCSWINSZ, winsize)
    attrs = termios.tcgetattr(master_fd)
    attrs[3] = attrs[3] & ~termios.ECHO
    termios.tcsetattr(master_fd, termios.TCSANOW, attrs)

    output = b""
    deadline = __import__("time").monotonic() + timeout
    for delay, chunk in responses:
        __import__("time").sleep(delay)
        os.write(master_fd, chunk)
        if __import__("time").monotonic() >= deadline:
            break
        ready, _, _ = select.select([master_fd], [], [], 0.3)
        if ready:
            try:
                chunk = os.read(master_fd, 4096)
            except OSError:
                break
            output += chunk

    # drain remaining output
    while __import__("time").monotonic() < deadline:
        ready, _, _ = select.select([master_fd], [], [], 0.3)
        if ready:
            try:
                chunk = os.read(master_fd, 4096)
            except OSError:
                break
            if not chunk:
                break
            output += chunk

    _, status = os.waitpid(pid, 0)
    return output.decode("utf-8", errors="replace"), status


@pytest.mark.parametrize("name,hexstr", [("TN", "544e"), ("RGB", "524742")])
def test_hex_encode(name, hexstr):
    """Encode ASCII string to hex."""
    assert hex_encode(name) == hexstr


@pytest.mark.parametrize("hexstr,expected", [("544e", "TN"), ("", ""), ("xyz", "")])
def test_hex_decode(hexstr, expected):
    """Decode hex string to ASCII, empty string on invalid."""
    assert hex_decode(hexstr) == expected


@pytest.mark.parametrize("raw,expected", [
    ("hello", "hello"),
    (r"\E", "\x1b"),
    (r"\n", "\n"),
    (r"\t", "\t"),
    (r"\r", "\r"),
    (r"\b", "\b"),
    (r"\f", "\f"),
    (r"\\", "\\"),
    (r"\^", "^"),
    (r"\:", ":"),
    (r"\007", "\x07"),
    ("^G", "\x07"),
    ("^?", "\x7f"),
    (r"\E[1m", "\x1b[1m"),
    ("^z", "^z"),
])
def test_unescape_terminfo(raw, expected):
    """Unescape terminfo-format escape sequences."""
    assert unescape_terminfo(raw) == expected


@pytest.mark.parametrize("caps,expected_bool,expected_num,expected_str", [
    ({"am": "", "bce": "", "km": "", "notabool": ""},
     {"am", "bce", "km"}, {}, {}),
    ({"colors": "256", "cols": "80", "notanum": "nope"},
     set(), {"colors": 256, "cols": 80}, {}),
    ({"clear": "\x1b[H", "bel": "\x07", "TN": "xterm-kitty"},
     set(), {}, {"clear": "\x1b[H", "bel": "\x07"}),
    ({"RGB": "8/8/8", "bel": "\x07"}, set(), {}, {"bel": "\x07"}),
    ({"unknown": ""}, set(), {}, {}),
    ({"cols": "abc"}, set(), {}, {}),
])
def test_classify_caps(caps, expected_bool, expected_num, expected_str):
    """Classify XTGETTCAP response into bool/num/str capability dicts."""
    result = classify_caps(caps)
    assert result["bool_caps"] == expected_bool
    assert result["num_caps"] == expected_num
    assert result["str_caps"] == expected_str


@pytest.mark.parametrize("str_caps,num_caps,bool_caps,expected", [
    ({"clear": "..."}, {}, set(), True),
    ({"kf1": "..."}, {}, set(), False),
    ({"kf1": "...", "clear": "..."}, {}, set(), True),
    ({"kf1": "..."}, {"cols": 80}, set(), True),
    ({}, {}, {"am"}, True),
    ({}, {"cols": 80}, set(), True),
    ({}, {"colors": 256}, set(), False),
    ({}, {}, set(), False),
])
def test_has_meaningful_caps(str_caps, num_caps, bool_caps, expected):
    """Check whether capabilities contain meaningful screen-oriented caps."""
    assert has_meaningful_caps(str_caps, num_caps, bool_caps) == expected


@pytest.mark.parametrize("rgb,force,env_colorterm,expected", [
    ("8/8/8", False, None, "export COLORTERM=truecolor"),
    ("8/8/8", False, "truecolor", None),
    ("8/8/8", True, "truecolor", "export COLORTERM=truecolor"),
    ("6/6/6", False, None, None),
    ("", False, None, None),
    ("bad", False, None, None),
    (None, False, None, None),
])
def test_check_colorterm(rgb, force, env_colorterm, expected):
    """Check COLORTERM export based on RGB capability."""
    env = {}
    if env_colorterm is not None:
        env["COLORTERM"] = env_colorterm
    caps = {"RGB": rgb} if rgb is not None else {}
    with patch.dict(os.environ, env, clear=True):
        assert check_colorterm(caps, force) == expected


@pytest.mark.parametrize("tn,force,env_term,expected", [
    ("kitty", False, "xterm", "export TERM=kitty"),
    ("xterm", False, "xterm", None),
    ("xterm", True, "xterm", "export TERM=xterm"),
    ("", False, "xterm", None),
    (None, False, "xterm", None),
])
def test_check_term(tn, force, env_term, expected):
    """Check TERM export based on TN capability vs environment."""
    caps = {"TN": tn} if tn is not None else {}
    with patch.dict(os.environ, {"TERM": env_term}, clear=True):
        assert check_term(caps, force) == expected


@pytest.mark.parametrize("rows,cols,winsize,force,env,expected", [
    (30, 100, (80, 24), False, {},
     ["export LINES=30", "export COLUMNS=100"]),
    (30, 100, (100, 30), False, {}, None),
    (30, 100, (80, 24), False, {"LINES": "30", "COLUMNS": "100"}, None),
    (30, 100, (100, 30), False, {"LINES": "24", "COLUMNS": "80"},
     ["export LINES=30", "export COLUMNS=100"]),
    (30, 100, (100, 30), True, {"LINES": "30", "COLUMNS": "100"},
     ["export LINES=30", "export COLUMNS=100"]),
    (30, 100, (100, 30), False, {"LINES": "30", "COLUMNS": "99"},
     ["export COLUMNS=100"]),
])
def test_check_lines_columns(rows, cols, winsize, force, env, expected):
    """LINES/COLUMNS export when detected size differs from terminal/environment."""
    with patch.dict(os.environ, env, clear=True):
        assert check_lines_columns(rows, cols, winsize, force) == expected


@pytest.mark.parametrize("value,expected", [
    (42, (42, 0)),
    (-1, (0xFF, 0xFF)),
    (256, (0, 1)),
])
def test_pack_short_le(value, expected):
    """Pack short integer into bytearray at offset."""
    buf = bytearray(2)
    pack_short_le(buf, 0, value)
    assert buf[0] == expected[0]
    assert buf[1] == expected[1]


@pytest.mark.parametrize("term,str_caps,num_caps,bool_caps,checks", [
    ("test", {"clear": "\x1b[H\x1b[2J"}, {"colors": 256}, {"am"},
     [(0, 0x1A), (1, 0x01)]),
    ("test32", {"clear": "\x1b[H"}, {"colors": 256, "pairs": 65536}, set(),
     [(0, 0x1E), (1, 0x02)]),
    ("empty", {}, {}, set(), []),
])
def test_build_terminfo_binary(term, str_caps, num_caps, bool_caps, checks):
    """Build terminfo binary from capabilities."""
    data = build_terminfo_binary(term, str_caps, num_caps, bool_caps)
    assert len(data) >= 12
    for idx, val in checks:
        assert data[idx] == val


@pytest.mark.parametrize("name,expected", [
    ("xterm", "xterm"),
    ("xterm-256color", "xterm-256color"),
    ("../../etc/passwd", "etcpasswd"),
    ("", "unknown"),
    ("../../../", "unknown"),
])
def test_sanitize_term_name(name, expected):
    """Sanitize terminal name stripping path-traversal characters."""
    assert sanitize_term_name(name) == expected


@pytest.mark.parametrize("value,terminfo,expected", [
    ("hello", False, "hello"),
    ("\x1b", False, "\\E"),
    ("\n", False, "\\n"),
    ("\x01", False, "^A"),
    ("\x7f", False, "^?"),
    (" ", True, "\\s"),
    (":", True, "\\:"),
])
def test_escape_value(value, terminfo, expected):
    """Escape special characters to terminfo/termcap format."""
    assert escape_value(value, terminfo=terminfo) == expected


@pytest.mark.parametrize("value,expected", [
    ("hello", "'hello'"),
    ("", "''"),
    ("it's", "'it'\\''s'"),
    ("a$b", "'a$b'"),
])
def test_shell_escape(value, expected):
    """Shell-escape a value for export statements."""
    assert shell_escape(value) == expected


@pytest.mark.parametrize("term,str_caps,num_caps,bool_caps,substrs", [
    ("myterm",
     {"clear": "\x1b[H\x1b[2J", "home": "\x1b[H"},
     {"colors": 256, "cols": 80},
     {"am", "km"},
     [":am:", ":km:", ":Co#256:", ":co#80:", ":cl=\\E[H\\E[2J:"]),
    ("t",
     {"unknown_cap": "value", "clear": "\x1b[H"},
     {"unknown_num": 42, "colors": 8},
     {"unknown_bool", "am"},
     [":am:", ":Co#8:"]),
])
def test_build_termcap_entry(term, str_caps, num_caps, bool_caps, substrs):
    """Build termcap entry from capabilities."""
    entry = build_termcap_entry(term, str_caps, num_caps, bool_caps)
    assert f"{term}|XTGETTCAP-discovered terminal:" in entry
    for s in substrs:
        assert s in entry


def test_build_termcap_entry_empty():
    """Build termcap entry with no capabilities."""
    assert build_termcap_entry("e", {}, {}, set()) == \
        "e|XTGETTCAP-discovered terminal:"


@pytest.mark.parametrize("name,expected", [
    ("WezTerm", "wezterm"),
    ("xterm-kitty", "xterm-kitty"),
])
def test_normalize_terminal_name(name, expected):
    """Normalize TN capability value to lowercase."""
    assert normalize_terminal_name(name) == expected


@pytest.mark.parametrize("text,expected", [
    ("kitty(0.24.2)", ("kitty", "0.24.2")),
    ("XTerm(367)", ("XTerm", "367")),
    ("tmux 3.2a", ("tmux", "3.2a")),
    ("X.Org 7.7.0(370)", ("X.Org", "7.7.0(370)")),
    ("foot", ("foot", "")),
    ("", ("", "")),
])
def test_parse_xtversion_text(text, expected):
    """Parse XTVERSION response text into name and version."""
    assert _parse_xtversion_text(text) == expected


@pytest.mark.parametrize("name,version,force,env,expected", [
    ("kitty", "0.24.2", False, {},
     ["export TERM_PROGRAM='kitty'", "export TERM_PROGRAM_VERSION='0.24.2'"]),
    ("kitty", "0.24.2", False,
     {"TERM_PROGRAM": "kitty", "TERM_PROGRAM_VERSION": "0.24.2"}, None),
    ("kitty", "0.24.2", True,
     {"TERM_PROGRAM": "kitty", "TERM_PROGRAM_VERSION": "0.24.2"},
     ["export TERM_PROGRAM='kitty'", "export TERM_PROGRAM_VERSION='0.24.2'"]),
    ("xterm", "", False, {},
     ["export TERM_PROGRAM='xterm'"]),
    ("X.Org", "7.7.0(370)", False, {},
     ["export TERM_PROGRAM='X.Org'", "export TERM_PROGRAM_VERSION='7.7.0(370)'"]),
])
def test_check_term_program(name, version, force, env, expected):
    """Check TERM_PROGRAM/TERM_PROGRAM_VERSION export logic."""
    with patch.dict(os.environ, env, clear=True):
        assert check_term_program(name, version, force) == expected


@pytest.mark.parametrize("read_until_result,expected", [
    ((None, ""), None),
    ((None, "\x1bP>|kitty(0.24.2)\x1b\\"), None),
    ((None, "\x1b[31;128R"), None),
])
def test_xtversion_query_no_cpr(read_until_result, expected):
    """xtversion_query returns None when CPR boundary not found."""
    with patch('ttyscan.read_until', return_value=read_until_result):
        assert xtversion_query(3, 4, 0.25) is expected


@pytest.mark.parametrize("data,expected_name,expected_version", [
    ("\x1bP>|kitty(0.24.2)\x1b\\", "kitty", "0.24.2"),
    ("\x1bP>|tmux 3.2a\x1b\\", "tmux", "3.2a"),
    ("\x1bP>|foot\x1b\\", "foot", ""),
])
def test_xtversion_query_parsed(data, expected_name, expected_version):
    """xtversion_query extracts name/version from DCS response."""
    import re as _re_mod
    from ttyscan import _RE_CPR_BOUNDARY

    full_buf = data + "\x1b[31;128R"
    cpr_match = _re_mod.search(_RE_CPR_BOUNDARY, full_buf)
    read_until_return = (cpr_match, full_buf)
    with patch('ttyscan.read_until', return_value=read_until_return):
        result = xtversion_query(3, 4, 0.25)
    assert result == (expected_name, expected_version)


def test_xtversion_query_no_dcs():
    """xtversion_query returns None when no DCS response found before CPR."""
    import re as _re_mod
    from ttyscan import _RE_CPR_BOUNDARY

    full_buf = "\x1b[31;128R"
    cpr_match = _re_mod.search(_RE_CPR_BOUNDARY, full_buf)
    read_until_return = (cpr_match, full_buf)
    with patch('ttyscan.read_until', return_value=read_until_return):
        result = xtversion_query(3, 4, 0.25)
    assert result is None


@pytest.mark.parametrize("func,args,enabled,expected_in", [
    (warn, ("test message",), None, "ttyscan: test message"),
    (verbose, ("test message", True), True, "ttyscan: test message"),
    (verbose, ("test message", False), False, None),
])
def test_output_functions(func, args, enabled, expected_in):
    """warn() and verbose() write prefixed messages to stderr."""
    buf = io.StringIO()
    with patch.object(sys, "stderr", buf):
        func(*args)
    if expected_in is not None:
        assert expected_in in buf.getvalue()
    else:
        assert buf.getvalue() == ""


def test_terminfo_file_path():
    """terminfo_file_path() builds path from term name and base dir."""
    assert terminfo_file_path("xterm", Path("/tmp/t")) == Path("/tmp/t/x/xterm")


def test_terminfo_installed_at(tmp_path):
    """terminfo_installed_at() checks if terminfo file exists."""
    fpath = terminfo_file_path("xterm", tmp_path)
    fpath.parent.mkdir(parents=True, exist_ok=True)
    fpath.write_bytes(b"fake")
    assert terminfo_installed_at("xterm", tmp_path) is True
    assert terminfo_installed_at("nonexist", tmp_path) is False


@pytest.mark.parametrize("env,expected_prefix", [
    ({}, None),
    ({"XDG_CONFIG_HOME": "/custom/config"}, "/custom/config"),
])
def test_ttyscan_terminfo_dir(env, expected_prefix):
    """ttyscan_terminfo_dir() returns XDG-based path."""
    with patch.dict(os.environ, env, clear=True):
        result = ttyscan_terminfo_dir()
    assert "ttyscan" in str(result)
    assert "terminfo" in str(result)
    if expected_prefix is not None:
        assert str(result).startswith(expected_prefix)


@pytest.mark.parametrize("term,str_caps,num_caps,bool_caps", [
    ("xterm", {"clear": "\x1b[H"}, {"colors": 256}, {"am"}),
    ("../../bad", {"clear": "\x1b[H"}, {}, set()),
])
def test_write_terminfo(tmp_path, term, str_caps, num_caps, bool_caps):
    """write_terminfo() creates and sanitizes terminfo file on disk."""
    assert _write_terminfo(term, str_caps, num_caps, bool_caps, tmp_path) is True
    safe = sanitize_term_name(term)
    fpath = terminfo_file_path(safe, tmp_path)
    assert fpath.exists()
    assert fpath.stat().st_size > 0


@pytest.mark.parametrize("setting_id,read_until_result,expected", [
    ("m",
     (None, ""),
     None),
    ("m",
     (None, "\x1bP1$r0m\x1b\\"),
     None),
    ("m",
     (None, "\x1b[31;128R"),
     None),
])
def test_decqss_query_no_cpr(setting_id, read_until_result, expected):
    """decqss_query returns None when CPR boundary not found."""
    with patch('ttyscan.read_until', return_value=read_until_result):
        assert decqss_query(3, 4, setting_id, 0.25) is expected


@pytest.mark.parametrize("setting_id,buf,expected", [
    ("m",
     "\x1bP1$r0m\x1b\\\x1b[31;128R",
     "0"),
    ("m",
     "\x1bP1$r48:2:1:2:3m\x1b\\\x1b[31;128R",
     "48:2:1:2:3"),
    (" q",
     "\x1bP1$r2 q\x1b\\\x1b[31;128R",
     "2"),
])
def test_decqss_query_valid(setting_id, buf, expected):
    """decqss_query parses valid DECRQSS responses."""
    import re as _re_mod
    from ttyscan import _RE_CPR_BOUNDARY

    cpr_match = _re_mod.search(_RE_CPR_BOUNDARY, buf)
    with patch('ttyscan.read_until', return_value=(cpr_match, buf)):
        assert decqss_query(3, 4, setting_id, 0.25) == expected


@pytest.mark.parametrize("buf", [
    "\x1bP0$rm\x1b\\\x1b[31;128R",
    "\x1b[31;128R",
])
def test_decqss_query_invalid(buf):
    """decqss_query returns None for Ps=0 or missing response."""
    import re as _re_mod
    from ttyscan import _RE_CPR_BOUNDARY

    cpr_match = _re_mod.search(_RE_CPR_BOUNDARY, buf)
    with patch('ttyscan.read_until', return_value=(cpr_match, buf)):
        assert decqss_query(3, 4, 'm', 0.25) is None


@pytest.mark.parametrize("original,probed,expected,verbose_msg", [
    ("0", "48:2:1:2:3", True, None),
    ("0", "0", False, None),
    ("0", "40", False, None),
    (None, None, False, "DECRQSS not supported by this terminal"),
])
def test_probe_truecolor(original, probed, expected, verbose_msg):
    """probe_truecolor detects truecolor via DECRQSS SGR set/query."""
    decrqss_responses = [original, probed]
    with patch('ttyscan.decqss_query', side_effect=decrqss_responses), \
            patch('ttyscan.write_all'), \
            patch('ttyscan.verbose') as mock_verbose:
        assert probe_truecolor(3, 4, 0.25, True) == expected
        if verbose_msg:
            mock_verbose.assert_called_with(verbose_msg, True)


def test_probe_truecolor_fails_on_second_query():
    """probe_truecolor returns False when probe query fails."""
    with patch('ttyscan.decqss_query', side_effect=["0", None]), \
            patch('ttyscan.write_all'), \
            patch('ttyscan.verbose'):
        assert probe_truecolor(3, 4, 0.25, False) is False


def test_main_help():
    """ttyscan --help prints usage and exits 0."""
    result = subprocess.run(
        [sys.executable, "-m", "ttyscan", "--help"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=5,
    )
    assert result.returncode == 0
    assert "Export terminal capabilities" in result.stdout


@pytest.mark.parametrize("args", [
    [],
    ["-v"],
    ["-f"],
    ["-t"],
])
def test_main_flags(args):
    from ttyscan import main, generate_exports  # noqa: F401
    buf = io.StringIO()
    with patch.object(sys, "stdout", buf), \
            patch("ttyscan.generate_exports", return_value=[]):
        main(args)
    assert isinstance(buf.getvalue(), str)


@pytest.mark.skipif(sys.platform == "win32", reason="pty requires unix")
def test_main_subprocess():
    env = {
        **dict(os.environ),
        "TTYSCAN_QUERY_TIMEOUT": "0.25",
    }
    env.pop("COLORTERM", None)
    env["TERM"] = "dumb"

    response = _XT_RESP["tn_xterm"] + _XT_RESP["colors_256"] \
        + _XT_RESP["clear"] + _XT_RESP["am"] + _CPR_31_128

    text, status = _pty_run(
        [sys.executable, "-m", "ttyscan", "-f"],
        env, response)

    assert os.WIFEXITED(status)
    assert os.WEXITSTATUS(status) == 0
    assert "export TERM=xterm" in text


def test_ttyscan_query_timeout_bad_value():
    """TTYSCAN_QUERY_TIMEOUT with non-float value warns and uses default."""
    result = subprocess.run(
        [sys.executable, "-c",
         "import os; os.environ['TTYSCAN_QUERY_TIMEOUT'] = 'bad'; "
         "import ttyscan; print(ttyscan._TTYSCAN_QUERY_TIMEOUT)"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=5,
    )
    assert result.stdout.strip() == "1.0"
    assert "is not a valid float" in result.stderr


@pytest.mark.parametrize("term,expected", [
    ("nonexistent_term_xyz", "False"),
    ("xterm", "True"),
])
def test_has_terminfo(term, expected):
    """has_terminfo() returns True/False based on terminfo availability."""
    result = subprocess.run(
        [sys.executable, "-c",
         f"from ttyscan import has_terminfo; "
         f"print(has_terminfo({term!r}))"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=5,
    )
    assert result.stdout.strip() == expected


@pytest.mark.skipif(sys.platform == "win32", reason="start_new_session requires unix")
@pytest.mark.parametrize("verbose_arg", ["", "True"])
def test_generate_exports_no_tty(verbose_arg):
    """generate_exports() returns [] when /dev/tty unavailable."""
    verbose = f"verbose_enabled={verbose_arg}" if verbose_arg else ""
    code = f"import ttyscan; print(ttyscan.generate_exports({verbose}))"
    result = subprocess.run(
        [sys.executable, "-c", code],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=5,
        stdin=subprocess.DEVNULL,
        start_new_session=True,
    )
    assert result.stdout.strip() == "[]"


def test_get_winsize_non_tty():
    """get_winsize() returns defaults for non-TTY fd."""
    from ttyscan import get_winsize
    with open("/dev/null") as f:
        assert get_winsize(f.fileno()) == (80, 24)


def test_set_cbreak_none():
    """set_cbreak() returns None when fd is None."""
    from ttyscan import set_cbreak
    assert set_cbreak(None) is None


def test_restore_termios_none():
    """restore_termios() is a no-op when fd or saved is None."""
    from ttyscan import restore_termios
    restore_termios(None, None)
    restore_termios(3, None)


def test_write_all_none_fd():
    """write_all() is a no-op when fd is None."""
    from ttyscan import write_all
    write_all(None, b"data")


@pytest.mark.parametrize("decrpm,read_available_raw,read_until_responses,expected", [
    (2, b"\x1b[48;31;128;0;0t", None, (31, 128, 'inband')),
    (2, b"",
     [("31;128R", "31;128R"), ("31;128R", "31;128R")],
     (31, 128, 'cpr')),
    (2, b"",
     [("31;128R", "31;128R"), ("999;999R", "999;999R")],
     None),
    (None, None,
     [("31;128R", "31;128R"), ("31;128R", "31;128R")],
     (31, 128, 'cpr')),
    (None, None,
     [("31;128R", "31;128R"), ("999;999R", "999;999R")],
     None),
    (None, None,
     [("31;128R", "31;128R"), (None, None), ("5;10R", "5;10R")],
     (5, 10, 'fallback_cpr')),
    (None, None,
     [(None, None), (None, None), (None, None)],
     None),
    (None, None,
     [("31;128R", "31;128R"), (None, None), ("999;999R", "999;999R")],
     None),
])
def test_detect_size(decrpm, read_available_raw, read_until_responses, expected):
    from ttyscan import detect_size, _RE_CPR
    import re as _re

    def _make_response(pair):
        if pair[0] is None:
            return (None, b"")
        m = _re.search(_RE_CPR, f"\x1b[{pair[0]}")
        return (m, b"some data")

    side_effect = [_make_response(p) for p in read_until_responses] \
        if read_until_responses is not None else None

    with patch('ttyscan.decrqm_query', return_value=decrpm), \
            patch('ttyscan.read_available', return_value=read_available_raw), \
            patch('ttyscan.read_until', side_effect=side_effect) as mock_read_until, \
            patch('ttyscan.write_all'), \
            patch('ttyscan.verbose'):
        result = detect_size(3, 4, False)

    assert result == expected
    if expected == (31, 128, 'inband'):
        mock_read_until.assert_not_called()


# Canned XTGETTCAP responses for PTY tests.
_XT_RESP = {
    "tn_xterm": b"\x1bP1+r544e=787465726d\x1b\\",
    "tn_nonexist": b"\x1bP1+r544e=6e6f6e6578697374\x1b\\",
    "colors_256": b"\x1bP1+r636f6c6f7273=323536\x1b\\",
    "clear": b"\x1bP1+r636c656172=1b5b481b5b324a\x1b\\",
    "am": b"\x1bP1+r616d\x1b\\",
    "cols_80": b"\x1bP1+r636f6c73=3830\x1b\\",
    "lines_24": b"\x1bP1+r6c696e6573=3234\x1b\\",
    "rgb_8_8_8": b"\x1bP1+r524742=382f382f38\x1b\\",
    "xtversion_kitty": b"\x1bP>|kitty(0.24.2)\x1b\\",
}
_CPR_31_128 = b"\x1b[31;128R"
_CPR_5_10 = b"\x1b[5;10R"
_CPR_6_7 = b"\x1b[6;7R"
_CPR_999_999 = b"\x1b[999;999R"
_DECRPM_none = b"\x1b[?2048;1$y"
_DECRPM_set = b"\x1b[?2048;2$y"
_RESIZE_31_128 = b"\x1b[48;31;128;0;0t"
_DECRQSS_SGR_ORIGINAL = b"\x1bP1$r0m\x1b\\"
_DECRQSS_SGR_TRUECOLOR = b"\x1bP1$r48:2:1:2:3m\x1b\\"
_DECRQSS_SGR_PALETTE = b"\x1bP1$r40m\x1b\\"
_DECRQSS_SGR_INVALID = b"\x1bP0$r\x1b\\"
_XTVERSION_XTERM = b"\x1bP>|XTerm(367)\x1b\\"


@pytest.mark.skipif(sys.platform == "win32", reason="pty requires unix")
@pytest.mark.parametrize("flags,response,expected,not_expected", [
    # force+termcap, full query, terminfo+termcap exported
    ("-vft",
     _XT_RESP["tn_xterm"] + _CPR_31_128
     + _XT_RESP["colors_256"] + _XT_RESP["clear"] + _XT_RESP["am"]
     + _XT_RESP["cols_80"] + _XT_RESP["lines_24"] + _CPR_31_128,
     ["export TERM=xterm", "export TERMINFO=", "export TERMCAP="],
     []),
    # bogus CPR (999) rejection: no LINES/COLUMNS, still exports TERMINFO/TERMCAP
    ("-vft",
     _XT_RESP["tn_xterm"] + _CPR_31_128
     + _DECRPM_none + _CPR_6_7 + _CPR_5_10 + _CPR_999_999
     + _XT_RESP["colors_256"] + _XT_RESP["clear"] + _XT_RESP["am"]
     + _XT_RESP["cols_80"] + _XT_RESP["lines_24"] + _CPR_31_128,
     ["export TERM=xterm", "export TERMINFO=", "export TERMCAP="],
     ["export LINES=", "export COLUMNS="]),
    # no force/termcap, has_terminfo skips full query (TERM exported, none else)
    ("-v",
     _XT_RESP["tn_xterm"] + _CPR_31_128,
     ["export TERM=xterm"],
     ["export TERMINFO=", "export TERMCAP=", "export LINES=", "export COLUMNS="]),
    # XTGETTCAP not supported: empty response, no exports
    ("-vft",
     b"",
     ["XTGETTCAP not supported by this terminal"],
     ["export TERM=", "export TERMINFO=", "export TERMCAP=",
      "export LINES=", "export COLUMNS="]),
    # no TN capability in response
    ("-vft",
     _XT_RESP["colors_256"] + _CPR_31_128,
     ["no TN (terminal name) capability"],
     ["export TERM=", "export TERMINFO=", "export TERMCAP=",
      "export LINES=", "export COLUMNS="]),
    # RGB=8/8/8 triggers COLORTERM=truecolor export
    ("-vft",
     _XT_RESP["tn_xterm"] + _CPR_31_128
     + _XT_RESP["rgb_8_8_8"] + _XT_RESP["colors_256"]
     + _XT_RESP["clear"] + _XT_RESP["am"]
     + _XT_RESP["cols_80"] + _XT_RESP["lines_24"] + _CPR_31_128,
     ["export COLORTERM=truecolor", "export TERM=xterm",
      "export TERMINFO=", "export TERMCAP="],
     []),
    # bare-minimum caps (only TN+colors): skips TERMINFO/TERMCAP
    ("-vft",
     _XT_RESP["tn_xterm"] + _CPR_31_128
     + _XT_RESP["colors_256"] + _CPR_31_128,
     ["export TERM=xterm"],
     ["export TERMINFO=", "export TERMCAP=", "export COLORTERM="]),
    # nonexistent TN (has_terminfo=False): full query path, exports TERMINFO
    ("-v",
     _XT_RESP["tn_nonexist"] + _CPR_31_128
     + _XT_RESP["colors_256"] + _XT_RESP["clear"] + _XT_RESP["am"]
     + _XT_RESP["cols_80"] + _XT_RESP["lines_24"] + _CPR_31_128,
     ["export TERM=nonexist", "export TERMINFO="],
     ["export TERMCAP="]),
])
def test_generate_exports_pty(flags, response, expected, not_expected, tmp_path):
    """PTY integration: run ttyscan with canned XTGETTCAP, verify exports."""
    terminfo_dir = tmp_path / "ttyscan" / "terminfo"
    project_coverage = os.path.join(os.path.dirname(__file__), ".coverage")

    env = {
        **dict(os.environ),
        "XDG_CONFIG_HOME": str(tmp_path),
        "TTYSCAN_QUERY_TIMEOUT": "0.5",
        "COVERAGE_FILE": project_coverage,
    }
    env.pop("COLORTERM", None)
    env["TERM"] = "dumb"

    text, _ = _pty_run(
        [sys.executable, "-m", "coverage", "run", "--append",
         "-m", "ttyscan"] + flags.split(),
        env, response)

    for s in expected:
        assert s in text
    for s in not_expected:
        assert s not in text

    if "export TERMINFO=" in text:
        import re
        term_match = re.search(r"export TERM=(\S+)", text)
        term_name = term_match.group(1) if term_match else "xterm"
        from ttyscan import sanitize_term_name, terminfo_file_path
        safe = sanitize_term_name(term_name)
        terminfo_file = terminfo_file_path(safe, terminfo_dir)
        assert terminfo_file.exists()
        assert terminfo_file.stat().st_size > 0


@pytest.mark.skipif(sys.platform == "win32", reason="pty requires unix")
@pytest.mark.parametrize("flags,responses,env_extra,expected,not_expected", [
    # DECRQSS detects truecolor when neither COLORTERM nor XTGETTCAP RGB indicate it
    ("-v",
     [(0.0, _XT_RESP["tn_xterm"] + _CPR_31_128),
      (0.1, _DECRQSS_SGR_ORIGINAL + _CPR_5_10),
      (0.1, _DECRQSS_SGR_TRUECOLOR + _CPR_6_7),
      (0.1, _DECRPM_none + _CPR_5_10),
      (0.1, _CPR_999_999),
      (0.1, _CPR_999_999)],
     {"TERM_PROGRAM": "xterm"},
     ["export COLORTERM=truecolor", "export TERM=xterm"],
     ["export LINES=", "export COLUMNS=", "export TERMINFO=", "export TERMCAP="]),
    # DECRQSS probe skipped when COLORTERM already truecolor
    ("-v",
     [(0.0, _XT_RESP["tn_xterm"] + _CPR_31_128),
      (0.1, _DECRPM_none + _CPR_5_10),
      (0.1, _CPR_999_999),
      (0.1, _CPR_999_999)],
     {"TERM_PROGRAM": "xterm", "COLORTERM": "truecolor"},
     ["export TERM=xterm"],
     ["export COLORTERM=truecolor"]),
    # DECRQSS probe skipped when XTGETTCAP RGB=8/8/8
    ("-v",
     [(0.0, _XT_RESP["tn_xterm"] + _XT_RESP["rgb_8_8_8"] + _CPR_31_128),
      (0.1, _DECRPM_none + _CPR_31_128),
      (0.1, _CPR_999_999),
      (0.1, _CPR_999_999)],
     {"TERM_PROGRAM": "xterm"},
     ["export COLORTERM=truecolor", "export TERM=xterm"],
     ["export TERMINFO=", "export TERMCAP="]),
    # -f forces DECRQSS probe even when COLORTERM already truecolor
    ("-vf",
     [(0.0, _XT_RESP["tn_xterm"] + _CPR_31_128),
      (0.1, _XTVERSION_XTERM + _CPR_5_10),
      (0.1, _DECRQSS_SGR_ORIGINAL + _CPR_6_7),
      (0.1, _DECRQSS_SGR_TRUECOLOR + _CPR_5_10),
      (0.1, _DECRPM_none + _CPR_6_7),
      (0.1, _CPR_999_999),
      (0.1, _CPR_999_999),
      (0.1, _CPR_31_128)],
     {"TERM_PROGRAM": "xterm", "COLORTERM": "truecolor"},
     ["export COLORTERM=truecolor", "export TERM=xterm"],
     []),
    # DECRQSS unsupported: no probe response, no COLORTERM export
    ("-v",
     [(0.0, _XT_RESP["tn_xterm"] + _CPR_31_128),
      (0.1, _DECRPM_none + _CPR_5_10),
      (0.1, _CPR_999_999),
      (0.1, _CPR_999_999)],
     {"TERM_PROGRAM": "xterm"},
     ["export TERM=xterm"],
     ["export COLORTERM=truecolor"]),
    # DECRQSS returns palette index (non-truecolor): no COLORTERM export
    ("-v",
     [(0.0, _XT_RESP["tn_xterm"] + _CPR_31_128),
      (0.1, _DECRQSS_SGR_ORIGINAL + _CPR_5_10),
      (0.1, _DECRQSS_SGR_PALETTE + _CPR_6_7),
      (0.1, _DECRPM_none + _CPR_5_10),
      (0.1, _CPR_999_999),
      (0.1, _CPR_999_999)],
     {"TERM_PROGRAM": "xterm"},
     ["export TERM=xterm"],
     ["export COLORTERM=truecolor"]),
    # DECRQSS probe with XTGETTCAP not supported (empty init): COLORTERM only
    ("-v",
     [(0.0, _CPR_31_128),
      (0.1, _DECRQSS_SGR_ORIGINAL + _CPR_5_10),
      (0.1, _DECRQSS_SGR_TRUECOLOR + _CPR_6_7)],
     {"TERM_PROGRAM": "xterm"},
     ["export COLORTERM=truecolor"],
     ["export TERM=", "export TERMINFO=", "export LINES=", "export COLUMNS="]),
])
def test_decrqss_probe_pty(flags, responses, env_extra, expected,
                            not_expected, tmp_path):
    """PTY integration: DECRQSS truecolor probe scenarios."""
    env = {
        **dict(os.environ),
        "XDG_CONFIG_HOME": str(tmp_path),
        "TTYSCAN_QUERY_TIMEOUT": "0.5",
    }
    env.pop("COLORTERM", None)
    env["TERM"] = "dumb"
    env.update(env_extra)

    project_coverage = os.path.join(os.path.dirname(__file__), ".coverage")
    env["COVERAGE_FILE"] = project_coverage

    text, status = _pty_run_staggered(
        [sys.executable, "-m", "coverage", "run", "--append",
         "-m", "ttyscan"] + flags.split(),
        env, responses)

    assert os.WIFEXITED(status)
    assert os.WEXITSTATUS(status) == 0

    for s in expected:
        assert s in text, f"expected {s!r} not found in output:\n{text}"
    for s in not_expected:
        assert s not in text, f"unexpected {s!r} found in output:\n{text}"
