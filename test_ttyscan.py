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
    classify_caps,
    decqss_query,
    env_exports,
    escape_value,
    has_meaningful_caps,
    hex_decode,
    hex_encode,
    probe_truecolor,
    read_cpr,
    read_until,
    sanitize_term_name,
    shell_escape,
    size_exports,
    terminfo_file_path,
    ttyscan_terminfo_dir,
    unescape_terminfo,
    verbose,
    warn,
    NoCPRReply,
    xtversion_query,
)


def _split_replies(response):
    """Split canned replies into one segment per cursor position fence."""
    import re
    segments = []
    start = 0
    for match in re.finditer(rb"\x1b\[[0-9]+;[0-9]+R", response):
        segments.append(response[start:match.end()])
        start = match.end()
    if start < len(response):
        segments.append(response[start:])
    return segments


def _pty_run(args, env, response, timeout=5.0):
    """Run a command in a PTY child, writing each canned segment at its fence.

    Returns ``(output_text, wait_status)``.
    """
    return _pty_run_staggered(
        args, env, [(0.0, segment) for segment in _split_replies(response)],
        timeout=timeout)


def _pty_run_staggered(args, env, responses, timeout=5.0):
    """Run a command in a PTY child, answering fence k with ``responses[k]``.

    Each entry is ``(delay_sec, data)``.  Returns ``(output_text, wait_status)``.
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
    sent = 0
    deadline = __import__("time").monotonic() + timeout
    while __import__("time").monotonic() < deadline:
        ready, _, _ = select.select([master_fd], [], [], 0.05)
        if not ready:
            continue
        try:
            chunk = os.read(master_fd, 4096)
        except OSError:
            break
        if not chunk:
            break
        output += chunk
        fences = output.count(b"\x1b[6n")
        while sent < fences and sent < len(responses):
            delay, reply = responses[sent]
            __import__("time").sleep(delay)
            os.write(master_fd, reply)
            sent += 1

    _, status = os.waitpid(pid, 0)
    return output.decode("utf-8", errors="replace"), status


def test_xtgettcap_query_counts_replies():
    """The reply count separates a short batch from a selective terminal."""
    import re as _re
    from ttyscan import xtgettcap_query, _RE_CPR_BOUNDARY

    first = ("\x1bP1+r544e=787465726d\x1b\\\x1bP0+r636f6c6f7273\x1b\\"
             + "\x1b[31;128R")
    fence = _re.search(_RE_CPR_BOUNDARY, first)

    with patch('ttyscan.read_until', return_value=(fence, first)), \
            patch('ttyscan.write_all'):
        caps, answered = xtgettcap_query(3, ['TN', 'colors'], 10.0)

    assert caps == {'TN': 'xterm'}
    assert answered == 2


@pytest.mark.parametrize("init_answered,answered,expected", [
    (10, 190, ""),
    (10, 113, "XTGETTCAP: 113 of 190 queries answered, the batch may be truncated"),
    (3, 100, ""),
])
def test_check_xtgettcap_replies(init_answered, answered, expected):
    """A short batch warns only for a terminal that answered the first batch."""
    from ttyscan import check_xtgettcap_replies

    with patch('ttyscan.warn') as mock_warn:
        check_xtgettcap_replies(init_answered, 10, answered, 190)

    if expected:
        mock_warn.assert_called_once_with(expected)
    else:
        mock_warn.assert_not_called()


@pytest.mark.parametrize("name,hexstr", [("TN", "544e"), ("RGB", "524742")])
def test_hex_encode(name, hexstr):
    assert hex_encode(name) == hexstr


@pytest.mark.parametrize("hexstr,expected", [("544e", "TN"), ("", ""), ("xyz", "")])
def test_hex_decode(hexstr, expected):
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
    """Screen capabilities decide; key-only strings and a bare colors count yield nothing."""
    assert has_meaningful_caps(str_caps, num_caps, bool_caps) == expected


@pytest.mark.parametrize("force,pairs,env,expected", [
    (False, (("TERM", "xterm"),), {}, ["export TERM='xterm'"]),
    (False, (("TERM", "xterm"),), {"TERM": "xterm"}, []),
    (True, (("TERM", "xterm"),), {"TERM": "xterm"}, ["export TERM='xterm'"]),
    (False, (("TERM_PROGRAM", "X.Org"), ("TERM_PROGRAM_VERSION", "7.7.0(370)")), {},
     ["export TERM_PROGRAM='X.Org'", "export TERM_PROGRAM_VERSION='7.7.0(370)'"]),
    (False, (("TERM_PROGRAM", "kitty"), ("TERM_PROGRAM_VERSION", "0.24.2")),
     {"TERM_PROGRAM": "kitty", "TERM_PROGRAM_VERSION": "0.24.2"}, []),
    (False, (("TERM_PROGRAM", "foot"), ("TERM_PROGRAM_VERSION", "")), {},
     ["export TERM_PROGRAM='foot'"]),
])
def test_env_exports(force, pairs, env, expected):
    """env_exports emits only values that differ from the environment."""
    with patch.dict(os.environ, env, clear=True):
        assert env_exports(force, *pairs) == expected


def test_env_exports_quote_override():
    """A ``quote`` of ``str`` leaves the value unquoted."""
    with patch.dict(os.environ, {}, clear=True):
        assert env_exports(False, ("TERM", "a b"), quote=str) == ["export TERM=a b"]


@pytest.mark.parametrize("rows,cols,winsize,force,env,expected", [
    (30, 100, (80, 24), False, {},
     ["export LINES=30", "export COLUMNS=100"]),
    (30, 100, (100, 30), False, {}, []),
    (30, 100, (80, 24), False, {"LINES": "30", "COLUMNS": "100"}, []),
    (30, 100, (100, 30), False, {"LINES": "24", "COLUMNS": "80"},
     ["export LINES=30", "export COLUMNS=100"]),
    (30, 100, (100, 30), True, {"LINES": "30", "COLUMNS": "100"},
     ["export LINES=30", "export COLUMNS=100"]),
    (30, 100, (100, 30), False, {"LINES": "30", "COLUMNS": "99"},
     ["export COLUMNS=100"]),
])
def test_size_exports(rows, cols, winsize, force, env, expected):
    """LINES/COLUMNS export when the size is new or corrects the environment."""
    with patch.dict(os.environ, env, clear=True):
        assert size_exports(rows, cols, winsize, force) == expected


@pytest.mark.parametrize("term,str_caps,num_caps,bool_caps,checks", [
    ("test", {"clear": "\x1b[H\x1b[2J"}, {"colors": 256}, {"am"},
     [(0, 0x1A), (1, 0x01)]),
    ("test32", {"clear": "\x1b[H"}, {"colors": 256, "pairs": 65536}, set(),
     [(0, 0x1E), (1, 0x02)]),
    ("empty", {}, {}, set(), []),
])
def test_build_terminfo_binary(term, str_caps, num_caps, bool_caps, checks):
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
    assert escape_value(value, terminfo=terminfo) == expected


@pytest.mark.parametrize("value,expected", [
    ("hello", "'hello'"),
    ("", "''"),
    ("it's", "'it'\\''s'"),
    ("a$b", "'a$b'"),
])
def test_shell_escape(value, expected):
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
    entry = build_termcap_entry(term, str_caps, num_caps, bool_caps)
    assert f"{term}|XTGETTCAP-discovered terminal:" in entry
    for s in substrs:
        assert s in entry


def test_build_termcap_entry_empty():
    assert build_termcap_entry("e", {}, {}, set()) == \
        "e|XTGETTCAP-discovered terminal:"


def test_xtversion_query_no_cpr():
    """xtversion_query propagates the missing cursor position report."""
    with patch('ttyscan.read_until', side_effect=NoCPRReply("no cursor position report")):
        with pytest.raises(NoCPRReply):
            xtversion_query(3, 0.25)


@pytest.mark.parametrize("data,expected_name,expected_version", [
    ("\x1bP>|kitty(0.24.2)\x1b\\", "kitty", "0.24.2"),
    ("\x1bP>|tmux 3.2a\x1b\\", "tmux", "3.2a"),
    ("\x1bP>|X.Org 7.7.0(370)\x1b\\", "X.Org", "7.7.0(370)"),
    ("\x1bP>|foot\x1b\\", "foot", ""),
])
def test_xtversion_query_parsed(data, expected_name, expected_version):
    import re as _re_mod
    from ttyscan import _RE_CPR_BOUNDARY

    full_buf = data + "\x1b[31;128R"
    cpr_match = _re_mod.search(_RE_CPR_BOUNDARY, full_buf)
    read_until_return = (cpr_match, full_buf)
    with patch('ttyscan.read_until', return_value=read_until_return):
        result = xtversion_query(3, 0.25)
    assert result == (expected_name, expected_version)


def test_xtversion_query_no_dcs():
    """A fence with no DCS reply in front of it yields ``None``."""
    import re as _re_mod
    from ttyscan import _RE_CPR_BOUNDARY

    full_buf = "\x1b[31;128R"
    cpr_match = _re_mod.search(_RE_CPR_BOUNDARY, full_buf)
    read_until_return = (cpr_match, full_buf)
    with patch('ttyscan.read_until', return_value=read_until_return):
        result = xtversion_query(3, 0.25)
    assert result is None


def test_warn():
    buf = io.StringIO()
    with patch.object(sys, "stderr", buf):
        warn("test message")
    assert "ttyscan: test message" in buf.getvalue()


@pytest.mark.parametrize("enabled,expected", [
    (True, "ttyscan: test message"),
    (False, ""),
])
def test_verbose(enabled, expected):
    buf = io.StringIO()
    with patch.object(sys, "stderr", buf), patch("ttyscan._VERBOSE", enabled):
        verbose("test message")
    if expected:
        assert expected in buf.getvalue()
    else:
        assert buf.getvalue() == ""


def test_terminfo_file_path():
    assert terminfo_file_path("xterm", Path("/tmp/t")) == Path("/tmp/t/x/xterm")


@pytest.mark.parametrize("env,expected_prefix", [
    ({}, None),
    ({"XDG_CONFIG_HOME": "/custom/config"}, "/custom/config"),
])
def test_ttyscan_terminfo_dir(env, expected_prefix):
    with patch.dict(os.environ, env, clear=True):
        result = ttyscan_terminfo_dir()
    assert "ttyscan" in str(result)
    assert "terminfo" in str(result)
    if expected_prefix is not None:
        assert str(result).startswith(expected_prefix)


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
    import re as _re_mod
    from ttyscan import _RE_CPR_BOUNDARY

    cpr_match = _re_mod.search(_RE_CPR_BOUNDARY, buf)
    with patch('ttyscan.read_until', return_value=(cpr_match, buf)):
        assert decqss_query(3, setting_id, 0.25) == expected


@pytest.mark.parametrize("buf", [
    "\x1bP0$rm\x1b\\\x1b[31;128R",
    "\x1b[31;128R",
])
def test_decqss_query_invalid(buf):
    """A refusal or a bare fence yields ``None``."""
    import re as _re_mod
    from ttyscan import _RE_CPR_BOUNDARY

    cpr_match = _re_mod.search(_RE_CPR_BOUNDARY, buf)
    with patch('ttyscan.read_until', return_value=(cpr_match, buf)):
        assert decqss_query(3, 'm', 0.25) is None


@pytest.mark.parametrize("original,probed,expected,verbose_msg", [
    ("0", "48:2:1:2:3", True, None),
    ("0", "0", False, None),
    ("0", "40", False, None),
    ("0", None, False, "DECRQSS probe query failed"),
    (None, None, False, "DECRQSS not supported by this terminal"),
])
def test_probe_truecolor(original, probed, expected, verbose_msg):
    decrqss_responses = [original, probed]
    with patch('ttyscan.decqss_query', side_effect=decrqss_responses), \
            patch('ttyscan.write_all'), \
            patch('ttyscan.verbose') as mock_verbose:
        assert probe_truecolor(3, 0.25) == expected
        if verbose_msg:
            mock_verbose.assert_called_with(verbose_msg)


def test_main_help():
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
    env.pop("TERM_PROGRAM", None)
    env["TERM"] = "dumb"

    response = _XT_RESP["tn_xterm"] + _XT_RESP["colors_256"] + _CPR_31_128 \
        + _XT_RESP["xtversion_kitty"] + _CPR_5_10 \
        + _CPR_6_7 \
        + _DECRPM_none + _CPR_5_10 \
        + _CPR_999_999 \
        + _XT_RESP["colors_256"] + _XT_RESP["clear"] + _XT_RESP["am"] \
        + _CPR_31_128

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
    assert result.stdout.strip() == "10.0"
    assert "is not a valid float" in result.stderr


@pytest.mark.parametrize("term,expected", [
    ("nonexistent_term_xyz", "False"),
    ("xterm", "True"),
])
def test_has_terminfo(term, expected):
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
    from ttyscan import get_winsize
    with open("/dev/null") as f:
        assert get_winsize(f.fileno()) == (80, 24)


def test_set_cbreak_none():
    from ttyscan import set_cbreak
    assert set_cbreak(None) is None


def test_restore_termios_none():
    from ttyscan import restore_termios
    restore_termios(None, None)
    restore_termios(3, None)


def test_write_all_none_fd():
    from ttyscan import write_all
    write_all(None, b"data")


@pytest.mark.parametrize("decrpm,resize_report,cpr,expected", [
    (2, "\x1b[48;31;128;0;0t", None, (31, 128, 'inband')),
    (2, None, (31, 128), (31, 128, 'cpr')),
    (2, None, None, None),
    (None, None, (31, 128), (31, 128, 'cpr')),
    (None, None, (999, 999), None),
    (None, None, None, None),
])
def test_detect_size(decrpm, resize_report, cpr, expected):
    from ttyscan import detect_size, _RE_CPR, _TTYSCAN_QUERY_TIMEOUT
    import re as _re

    data = (resize_report or "") + "\x1b[31;128R"
    fenced = (_re.search(_RE_CPR, data), data)

    with patch('ttyscan.decrqm_query', return_value=decrpm), \
            patch('ttyscan.read_until', return_value=fenced) as mock_read_until, \
            patch('ttyscan.read_cpr', return_value=cpr) as mock_read_cpr, \
            patch('ttyscan.write_all') as mock_write_all, \
            patch('ttyscan.verbose'):
        result = detect_size(3, (128, 31))

    assert result == expected
    if expected == (31, 128, 'inband'):
        mock_read_until.assert_called_once_with(
            3, ['\x1b[?2048h'], _RE_CPR.pattern, _TTYSCAN_QUERY_TIMEOUT)
        mock_read_cpr.assert_not_called()
        mock_write_all.assert_any_call(3, '\x1b[?2048l')
    else:
        mock_read_cpr.assert_called_once_with(
            3, _TTYSCAN_QUERY_TIMEOUT, minimum=(128, 31))
        mock_write_all.assert_any_call(3, '\x1b7\x1b[1000;1000H')
        mock_write_all.assert_any_call(3, '\x1b8')
        if decrpm != 2:
            mock_read_until.assert_not_called()


@pytest.mark.parametrize("chunks,minimum,expected", [
    ([b"\x1b[28;1R\x1b[28;101R"], (101, 28), (28, 101)),
    ([b"\x1b[28;1R", b"\x1b[28;101R"], (101, 28), (28, 101)),
    ([b"\x1b[28;1", b"01R"], (101, 28), (28, 101)),
    ([b"\x1b[28;1R"], None, (28, 1)),
])
def test_read_cpr(chunks, minimum, expected):
    with patch('ttyscan.read_available', side_effect=chunks), \
            patch('ttyscan.write_all') as mock_write_all:
        assert read_cpr(3, 0.25, minimum=minimum) == expected
    mock_write_all.assert_called_once_with(3, b'\x1b[6n')


@pytest.mark.parametrize("chunks,minimum", [
    ([b"\x1b[28;1R", b""], (101, 28)),
    ([b""], (101, 28)),
    ([b"\x1b[28;1R", b""], (101, 28)),
])
def test_read_cpr_no_acceptable_reply(chunks, minimum):
    with patch('ttyscan.read_available', side_effect=chunks):
        with pytest.raises(NoCPRReply):
            read_cpr(3, 0.25, minimum=minimum)


def test_read_until_no_reply():
    with patch('ttyscan.read_available', return_value=b""), \
            patch('ttyscan.write_all'):
        with pytest.raises(NoCPRReply):
            read_until(3, [], r'\x1b\[\d+;\d+R', 0.25)


def test_read_until_no_fence_in_flood():
    with patch('ttyscan.read_available', return_value=b"x" * 4096), \
            patch('ttyscan.write_all'):
        with pytest.raises(NoCPRReply):
            read_until(3, [], r'\x1b\[\d+;\d+R', 10.0)


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
    ("-vft",
     _XT_RESP["tn_xterm"] + _CPR_31_128
     + _CPR_5_10
     + _CPR_6_7
     + _DECRPM_none + _CPR_5_10
     + _CPR_999_999
     + _XT_RESP["colors_256"] + _XT_RESP["clear"] + _XT_RESP["am"]
     + _XT_RESP["cols_80"] + _XT_RESP["lines_24"] + _CPR_31_128,
     ["export TERM=xterm", "export TERMINFO=", "export TERMCAP="],
     []),
    ("-vft",
     _XT_RESP["tn_xterm"] + _CPR_31_128
     + _CPR_5_10
     + _CPR_6_7
     + _DECRPM_none + _CPR_5_10
     + _CPR_999_999
     + _XT_RESP["colors_256"] + _XT_RESP["clear"] + _XT_RESP["am"]
     + _XT_RESP["cols_80"] + _XT_RESP["lines_24"] + _CPR_31_128,
     ["export TERM=xterm", "export TERMINFO=", "export TERMCAP="],
     ["export LINES=", "export COLUMNS="]),
    ("-v",
     _XT_RESP["tn_xterm"] + _CPR_31_128
     + _CPR_5_10
     + _CPR_6_7
     + _DECRPM_none + _CPR_5_10
     + _CPR_999_999,
     ["export TERM=xterm"],
     ["export TERMINFO=", "export TERMCAP=", "export LINES=", "export COLUMNS="]),
    ("-vft",
     _CPR_31_128
     + _CPR_5_10
     + _CPR_6_7
     + _DECRPM_none + _CPR_5_10
     + _CPR_999_999,
     ["XTGETTCAP not supported by this terminal"],
     ["export TERM=", "export TERMINFO=", "export TERMCAP=",
      "export LINES=", "export COLUMNS="]),
    ("-vft",
     _XT_RESP["colors_256"] + _CPR_31_128
     + _CPR_5_10
     + _CPR_6_7
     + _DECRPM_none + _CPR_5_10
     + _CPR_999_999,
     ["no TN (terminal name) capability"],
     ["export TERM=", "export TERMINFO=", "export TERMCAP=",
      "export LINES=", "export COLUMNS="]),
    ("-vft",
     _XT_RESP["tn_xterm"] + _XT_RESP["rgb_8_8_8"] + _CPR_31_128
     + _CPR_5_10
     + _DECRQSS_SGR_ORIGINAL + _CPR_6_7
     + _DECRQSS_SGR_TRUECOLOR + _CPR_5_10
     + _DECRPM_none + _CPR_5_10
     + _CPR_999_999
     + _XT_RESP["colors_256"] + _XT_RESP["clear"] + _XT_RESP["am"]
     + _XT_RESP["cols_80"] + _XT_RESP["lines_24"] + _CPR_31_128,
     ["export COLORTERM=truecolor", "export TERM=xterm",
      "export TERMINFO=", "export TERMCAP="],
     []),
    ("-vft",
     _XT_RESP["tn_xterm"] + _XT_RESP["colors_256"] + _CPR_31_128
     + _CPR_5_10
     + _CPR_6_7
     + _DECRPM_none + _CPR_5_10
     + _CPR_999_999
     + _XT_RESP["colors_256"] + _CPR_31_128,
     ["export TERM=xterm"],
     ["export TERMINFO=", "export TERMCAP=", "export COLORTERM="]),
    ("-v",
     _XT_RESP["tn_nonexist"] + _CPR_31_128
     + _CPR_5_10
     + _CPR_6_7
     + _DECRPM_none + _CPR_5_10
     + _CPR_999_999
     + _XT_RESP["colors_256"] + _XT_RESP["clear"] + _XT_RESP["am"]
     + _XT_RESP["cols_80"] + _XT_RESP["lines_24"] + _CPR_31_128,
     ["export TERM=nonexist", "export TERMINFO="],
     ["export TERMCAP="]),
])
def test_generate_exports_pty(flags, response, expected, not_expected, tmp_path):
    terminfo_dir = tmp_path / "ttyscan" / "terminfo"
    project_coverage = os.path.join(os.path.dirname(__file__), ".coverage")

    env = {
        **dict(os.environ),
        "XDG_CONFIG_HOME": str(tmp_path),
        "TTYSCAN_QUERY_TIMEOUT": "0.5",
        "COVERAGE_FILE": project_coverage,
    }
    env.pop("COLORTERM", None)
    env.pop("TERM_PROGRAM", None)
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
def test_size_probe_waits_for_late_cpr(tmp_path):
    """A cursor report arriving 0.6s after its fence still yields the size."""
    env = {
        **dict(os.environ),
        "XDG_CONFIG_HOME": str(tmp_path),
        "TTYSCAN_QUERY_TIMEOUT": "2.0",
        "TERM_PROGRAM": "xterm",
        "COLORTERM": "truecolor",
        "COVERAGE_FILE": os.path.join(os.path.dirname(__file__), ".coverage"),
        "TERM": "dumb",
    }
    responses = [
        (0.0, _XT_RESP["tn_xterm"] + _CPR_31_128),
        (0.1, _XTVERSION_XTERM + _CPR_5_10),
        (0.1, _DECRQSS_SGR_ORIGINAL + _CPR_6_7),
        (0.1, _DECRQSS_SGR_TRUECOLOR + _CPR_5_10),
        (0.6, _DECRPM_none + _CPR_5_10),
        (0.6, _CPR_31_128),
        (0.1, _XT_RESP["colors_256"] + _XT_RESP["clear"] + _XT_RESP["am"]
         + _CPR_31_128),
    ]

    text, status = _pty_run_staggered(
        [sys.executable, "-m", "coverage", "run", "--append", "-m", "ttyscan", "-vf"],
        env, responses)

    assert os.WIFEXITED(status)
    assert os.WEXITSTATUS(status) == 0
    assert "export LINES=31" in text
    assert "export COLUMNS=128" in text


@pytest.mark.skipif(sys.platform == "win32", reason="pty requires unix")
def test_main_exits_without_cpr(tmp_path):
    env = {
        **dict(os.environ),
        "XDG_CONFIG_HOME": str(tmp_path),
        "TTYSCAN_QUERY_TIMEOUT": "0.2",
        "COVERAGE_FILE": os.path.join(os.path.dirname(__file__), ".coverage"),
        "TERM": "dumb",
    }

    text, status = _pty_run(
        [sys.executable, "-m", "coverage", "run", "--append", "-m", "ttyscan"],
        env, b"")

    assert os.WIFEXITED(status)
    assert os.WEXITSTATUS(status) == 1
    assert "no cursor position report" in text


@pytest.mark.skipif(sys.platform == "win32", reason="pty requires unix")
@pytest.mark.parametrize("flags,responses,env_extra,expected,not_expected", [
    pytest.param(
        "-v",
        [(0.0, _XT_RESP["tn_xterm"] + _CPR_31_128),
         (0.1, _DECRQSS_SGR_ORIGINAL + _CPR_5_10),
         (0.1, _DECRQSS_SGR_TRUECOLOR + _CPR_6_7),
         (0.1, _DECRPM_none + _CPR_5_10),
         (0.1, _CPR_999_999),
         (0.1, _CPR_999_999)],
        {"TERM_PROGRAM": "xterm"},
        ["export COLORTERM=truecolor", "export TERM=xterm"],
        ["export LINES=", "export COLUMNS=", "export TERMINFO=", "export TERMCAP="],
        id="probe-detects-truecolor"),
    pytest.param(
        "-v",
        [(0.0, _XT_RESP["tn_xterm"] + _CPR_31_128),
         (0.1, _DECRPM_none + _CPR_5_10),
         (0.1, _CPR_999_999),
         (0.1, _CPR_999_999)],
        {"TERM_PROGRAM": "xterm", "COLORTERM": "truecolor"},
        ["export TERM=xterm"],
        ["export COLORTERM=truecolor"],
        id="colorterm-already-set"),
    pytest.param(
        "-v",
        [(0.0, _XT_RESP["tn_xterm"] + _XT_RESP["rgb_8_8_8"] + _CPR_31_128),
         (0.1, _DECRPM_none + _CPR_31_128),
         (0.1, _CPR_999_999),
         (0.1, _CPR_999_999)],
        {"TERM_PROGRAM": "xterm"},
        ["export COLORTERM=truecolor", "export TERM=xterm"],
        ["export TERMINFO=", "export TERMCAP="],
        id="rgb-capability"),
    pytest.param(
        "-vf",
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
        [],
        id="force-probes-anyway"),
    pytest.param(
        "-v",
        [(0.0, _XT_RESP["tn_xterm"] + _CPR_31_128),
         (0.1, _DECRPM_none + _CPR_5_10),
         (0.1, _CPR_999_999),
         (0.1, _CPR_999_999)],
        {"TERM_PROGRAM": "xterm"},
        ["export TERM=xterm"],
        ["export COLORTERM=truecolor"],
        id="decrqss-unsupported"),
    pytest.param(
        "-v",
        [(0.0, _XT_RESP["tn_xterm"] + _CPR_31_128),
         (0.1, _DECRQSS_SGR_ORIGINAL + _CPR_5_10),
         (0.1, _DECRQSS_SGR_PALETTE + _CPR_6_7),
         (0.1, _DECRPM_none + _CPR_5_10),
         (0.1, _CPR_999_999),
         (0.1, _CPR_999_999)],
        {"TERM_PROGRAM": "xterm"},
        ["export TERM=xterm"],
        ["export COLORTERM=truecolor"],
        id="palette-index"),
    pytest.param(
        "-v",
        [(0.0, _CPR_31_128),
         (0.1, _DECRQSS_SGR_ORIGINAL + _CPR_5_10),
         (0.1, _DECRQSS_SGR_TRUECOLOR + _CPR_6_7),
         (0.1, _DECRPM_none + _CPR_5_10),
         (0.1, _CPR_999_999)],
        {"TERM_PROGRAM": "xterm"},
        ["export COLORTERM=truecolor"],
        ["export TERM=", "export TERMINFO=", "export LINES=", "export COLUMNS="],
        id="no-xtgettcap"),
])
def test_decrqss_probe_pty(flags, responses, env_extra, expected,
                           not_expected, tmp_path):
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
