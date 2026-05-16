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
    classify_caps,
    escape_value,
    has_meaningful_caps,
    hex_decode,
    hex_encode,
    normalize_terminal_name,
    pack_short_le,
    sanitize_term_name,
    shell_escape,
    terminfo_file_path,
    terminfo_installed_at,
    ttyscan_terminfo_dir,
    unescape_terminfo,
    verbose,
    warn,
)
from ttyscan import write_terminfo as _write_terminfo


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


def test_main_help():
    """ttyscan --help prints usage and exits 0."""
    result = subprocess.run(
        [sys.executable, "-m", "ttyscan", "--help"],
        capture_output=True, text=True, timeout=5,
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
    """main() parses flags and runs generate_exports."""
    from ttyscan import main
    buf = io.StringIO()
    with patch.object(sys, "stdout", buf):
        main(args)
    assert isinstance(buf.getvalue(), str)


def test_main_subprocess():
    """ttyscan --force runs and exits 0 from pipe."""
    result = subprocess.run(
        [sys.executable, "-m", "ttyscan", "-f"],
        capture_output=True, text=True, timeout=5,
        stdin=subprocess.DEVNULL,
    )
    assert result.returncode == 0


def test_main_version():
    """ttyscan module has __version__ attribute."""
    result = subprocess.run(
        [sys.executable, "-c", "import ttyscan; print(ttyscan.__version__)"],
        capture_output=True, text=True, timeout=5,
    )
    assert result.stdout.strip() == "0.0.2"


def test_ttyscan_query_timeout_bad_value():
    """TTYSCAN_QUERY_TIMEOUT with non-float value warns and uses default."""
    result = subprocess.run(
        [sys.executable, "-c",
         "import os; os.environ['TTYSCAN_QUERY_TIMEOUT'] = 'bad'; "
         "import ttyscan; print(ttyscan._TTYSCAN_QUERY_TIMEOUT)"],
        capture_output=True, text=True, timeout=5,
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
        capture_output=True, text=True, timeout=5,
    )
    assert result.stdout.strip() == expected


@pytest.mark.skipif(sys.platform == "win32", reason="pty requires unix")
@pytest.mark.parametrize("verbose_arg", ["", "True"])
def test_generate_exports_no_tty(verbose_arg):
    """generate_exports() returns [] when /dev/tty unavailable."""
    verbose = f"verbose_enabled={verbose_arg}" if verbose_arg else ""
    code = f"import ttyscan; print(ttyscan.generate_exports({verbose}))"
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True, text=True, timeout=5,
        stdin=subprocess.DEVNULL,
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


@pytest.mark.skipif(sys.platform == "win32", reason="pty requires unix")
def test_generate_exports_happy_path(tmp_path):
    """Full integration: run ttyscan -vft in PTY with canned XTGETTCAP, verify terminfo output."""
    import fcntl
    import select as _select
    import struct
    import termios

    terminfo_dir = tmp_path / "ttyscan" / "terminfo"
    project_coverage = os.path.join(os.path.dirname(__file__), ".coverage")

    env = {
        **dict(os.environ),
        "XDG_CONFIG_HOME": str(tmp_path),
        "TTYSCAN_QUERY_TIMEOUT": "0.5",
        "COVERAGE_FILE": project_coverage,
    }
    env.pop("COLORTERM", None)

    pid, master_fd = os.forkpty()
    if pid == 0:
        os.execve(sys.executable,
                  [sys.executable, "-m", "coverage", "run",
                   "--data-file=" + project_coverage,
                   "--append",
                   "-m", "ttyscan", "-vft"],
                  env)
        os._exit(1)

    winsize = struct.pack("HHHH", 31, 128, 0, 0)
    fcntl.ioctl(master_fd, termios.TIOCSWINSZ, winsize)
    attrs = termios.tcgetattr(master_fd)
    attrs[3] = attrs[3] & ~termios.ECHO
    termios.tcsetattr(master_fd, termios.TCSANOW, attrs)

    _select.select([master_fd], [], [], 3.0)
    os.write(master_fd,
             b"\x1bP1+r544e=787465726d\x1b\\\x1b[31;128R"
             b"\x1b[?2048;1$y\x1b[6;7R"
             b"\x1b[5;10R"
             b"\x1b[31;128R"
             b"\x1bP1+r636f6c6f7273=323536\x1b\\"
             b"\x1bP1+r636c656172=1b5b481b5b324a\x1b\\"
             b"\x1bP1+r616d\x1b\\"
             b"\x1bP1+r636f6c73=3830\x1b\\"
             b"\x1bP1+r6c696e6573=3234\x1b\\"
             b"\x1b[31;128R")

    output = b""
    deadline = __import__("time").monotonic() + 5.0
    while __import__("time").monotonic() < deadline:
        ready, _, _ = _select.select([master_fd], [], [], 0.3)
        if ready:
            try:
                chunk = os.read(master_fd, 4096)
            except OSError:
                break
            if not chunk:
                break
            output += chunk

    os.waitpid(pid, 0)
    text = output.decode("utf-8", errors="replace")

    assert "export TERM=xterm" in text, f"output: {text!r}"
    assert f"export TERMINFO={terminfo_dir}" in text, f"output: {text!r}"
    assert "export TERMCAP=" in text, f"output: {text!r}"

    terminfo_file = terminfo_dir / "x" / "xterm"
    assert terminfo_file.exists(), f"expected {terminfo_file} to exist"
    assert terminfo_file.stat().st_size > 0, "terminfo file is empty"
