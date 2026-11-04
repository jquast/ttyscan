"""Tests for ttyscan module."""

import io
import os
import re
import subprocess
import sys
from pathlib import Path
from unittest.mock import call, patch

import pytest

from ttyscan import (
    build_termcap_entry,
    build_terminfo_binary,
    classify_caps,
    da1_query,
    decqss_query,
    detect_terminal,
    enq_query,
    env_exports,
    escape_value,
    has_meaningful_caps,
    hex_decode,
    hex_encode,
    probe_truecolor,
    probe_width,
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
    _TERM_PROBES,
    _TERM_QUIZ,
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
    bare = (_re.search(_RE_CPR, "\x1b[31;128R"), "\x1b[31;128R")
    returns = [fenced, bare] if decrpm == 2 else []

    with patch('ttyscan.decrqm_query', return_value=decrpm), \
            patch('ttyscan.read_until', side_effect=returns) as mock_read_until, \
            patch('ttyscan.read_cpr', return_value=cpr) as mock_read_cpr, \
            patch('ttyscan.write_all') as mock_write_all, \
            patch('ttyscan.verbose'):
        result = detect_size(3, (128, 31))

    assert result == expected
    if expected == (31, 128, 'inband'):
        assert mock_read_until.call_args_list == [
            call(3, ['\x1b[?2048h'], _RE_CPR.pattern, _TTYSCAN_QUERY_TIMEOUT),
            call(3, [], _RE_CPR.pattern, _TTYSCAN_QUERY_TIMEOUT),
        ]
        mock_read_cpr.assert_not_called()
        mock_write_all.assert_called_once_with(3, '\x1b[?2048l')
    else:
        mock_read_cpr.assert_called_once_with(
            3, _TTYSCAN_QUERY_TIMEOUT, minimum=(128, 31))
        mock_write_all.assert_any_call(3, '\x1b7\x1b[1000;1000H')
        mock_write_all.assert_any_call(3, '\x1b8')
        if decrpm != 2:
            mock_read_until.assert_not_called()


@pytest.mark.parametrize("late,expected", [
    ("", (31, 128)),
    ("\x1b[48;32;130;0;0t", (32, 130)),
    ("\x1b[48;32;130;0;0t\x1b[48;33;131;0;0t", (33, 131)),
])
def test_detect_size_uses_the_last_inband_report(late, expected):
    """Resize reports emitted before the mode reset arrive ahead of the fence."""
    from ttyscan import detect_size, _RE_CPR
    import re as _re

    early = "\x1b[48;31;128;0;0t\x1b[31;128R"
    tail = late + "\x1b[31;128R"

    with patch('ttyscan.decrqm_query', return_value=2), \
            patch('ttyscan.read_until', side_effect=[
                (_re.search(_RE_CPR, early), early),
                (_re.search(_RE_CPR, tail), tail),
            ]), \
            patch('ttyscan.write_all'), \
            patch('ttyscan.verbose'):
        assert detect_size(3, (128, 31)) == (*expected, 'inband')


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
     + _CPR_31_128
     + _CPR_31_128
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
     + _CPR_31_128
     + _CPR_31_128
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
     + _CPR_31_128
     + _CPR_31_128
     + _CPR_6_7
     + _DECRPM_none + _CPR_5_10
     + _CPR_999_999,
     ["export TERM=xterm"],
     ["export TERMINFO=", "export TERMCAP=", "export LINES=", "export COLUMNS="]),
    ("-vft",
     _CPR_31_128
     + _CPR_5_10
     + _CPR_31_128
     + _CPR_31_128
     + _CPR_6_7
     + _DECRPM_none + _CPR_5_10
     + _CPR_999_999,
     ["XTGETTCAP not supported by this terminal"],
     ["export TERM=", "export TERMINFO=", "export TERMCAP=",
      "export LINES=", "export COLUMNS="]),
    ("-vft",
     _XT_RESP["colors_256"] + _CPR_31_128
     + _CPR_5_10
     + _CPR_31_128
     + _CPR_31_128
     + _CPR_6_7
     + _DECRPM_none + _CPR_5_10
     + _CPR_999_999,
     ["no TN (terminal name) capability"],
     ["export TERM=", "export TERMINFO=", "export TERMCAP=",
      "export LINES=", "export COLUMNS="]),
    ("-vft",
     _XT_RESP["tn_xterm"] + _XT_RESP["rgb_8_8_8"] + _CPR_31_128
     + _CPR_5_10
     + _CPR_31_128
     + _CPR_31_128
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
     + _CPR_31_128
     + _CPR_31_128
     + _CPR_6_7
     + _DECRPM_none + _CPR_5_10
     + _CPR_999_999
     + _XT_RESP["colors_256"] + _CPR_31_128,
     ["export TERM=xterm"],
     ["export TERMINFO=", "export TERMCAP=", "export COLORTERM="]),
    ("-v",
     _XT_RESP["tn_nonexist"] + _CPR_31_128
     + _CPR_5_10
     + _CPR_31_128
     + _CPR_31_128
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
def test_generate_exports_pty_inband_resize(tmp_path):
    """A report emitted before the mode reset is consumed, and the last one wins."""
    env = {
        **dict(os.environ),
        "XDG_CONFIG_HOME": str(tmp_path),
        "TTYSCAN_QUERY_TIMEOUT": "0.5",
        "COVERAGE_FILE": os.path.join(os.path.dirname(__file__), ".coverage"),
    }
    env.pop("COLORTERM", None)
    env.pop("TERM_PROGRAM", None)
    env["TERM"] = "dumb"

    response = (_CPR_31_128
                + _CPR_5_10
                + _CPR_31_128
                + _CPR_31_128
                + _CPR_6_7
                + _DECRPM_set + _CPR_31_128
                + _RESIZE_31_128 + _CPR_31_128
                + b"\x1b[48;25;98;0;0t" + _CPR_31_128
                + _CPR_31_128)

    text, status = _pty_run(
        [sys.executable, "-m", "coverage", "run", "--append",
         "-m", "ttyscan"],
        env, response)

    assert status == 0
    assert "export LINES=25" in text
    assert "export COLUMNS=98" in text


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


@pytest.mark.parametrize("reply,expected", [
    ("\x1b[?1;2c", ('?', 1, (2,))),
    ("\x1b[6c", ('', 6, ())),
    ("\x1b[?64;1;9;15;21;22c", ('?', 64, (1, 9, 15, 21, 22))),
    ("", None),
])
def test_da1_query(reply, expected):
    """A primary device attributes reply is a service class and extensions."""
    buf = reply + "\x1b[31;128R"
    fence = re.search(r"\x1b\[[0-9]+;[0-9]+R", buf)
    with patch('ttyscan.read_until', return_value=(fence, buf)), \
            patch('ttyscan.write_all'):
        assert da1_query(3) == expected


@pytest.mark.parametrize("answer,expected", [
    ("urxvt 9.31", ('urxvt', '9.31')),
    ("\x1b[?1;2c", ('urxvt', '')),
    ("PuTTY", ('PuTTY', '')),
    ("\x1bP>|Extraterm 0.78\x1b\\", ('Extraterm', '0.78')),
    ("\x1b]0;title\x07urxvt", ('urxvt', '')),
    ("   ", None),
    ("", None),
])
def test_enq_query(answer, expected):
    """An answerback names the terminal, with a trailing version when present."""
    buf = answer + "\x1b[31;128R"
    fence = re.search(r"\x1b\[[0-9]+;[0-9]+R", buf)
    with patch('ttyscan.read_until', return_value=(fence, buf)), \
            patch('ttyscan._drain_fd', return_value=''), \
            patch('ttyscan.write_all'):
        assert enq_query(3) == expected


def test_enq_query_accepts_an_answer_after_the_cpr():
    """An answerback that trails the fence is not discarded."""
    buf = "\x1b[31;128R" + "urxvt 9.31"
    fence = re.search(r"\x1b\[[0-9]+;[0-9]+R", buf)
    with patch('ttyscan.read_until', return_value=(fence, buf)), \
            patch('ttyscan._drain_fd', return_value=''), \
            patch('ttyscan.write_all'):
        assert enq_query(3) == ('urxvt', '9.31')


def test_enq_query_uses_the_idle_drain():
    """An answerback that arrives after the fence is read from the drain."""
    buf = "\x1b[31;128R"
    fence = re.search(r"\x1b\[[0-9]+;[0-9]+R", buf)
    with patch('ttyscan.read_until', return_value=(fence, buf)), \
            patch('ttyscan._drain_fd', return_value='Extraterm 0.81.4'), \
            patch('ttyscan.write_all'):
        assert enq_query(3) == ('Extraterm', '0.81.4')


@pytest.mark.parametrize("answer", [
    "\x1b[?6c",
    "\x1b[31;128R",
    ">|",
    "   ",
])
def test_enq_query_ignores_stray_replies(answer):
    """A cursor or device attribute reply is not an answerback."""
    buf = "\x1b[31;128R" + answer
    fence = re.search(r"\x1b\[[0-9]+;[0-9]+R", buf)
    with patch('ttyscan.read_until', return_value=(fence, buf)), \
            patch('ttyscan._drain_fd', return_value=''), \
            patch('ttyscan.write_all'):
        assert enq_query(3) is None


def test_probe_width():
    """The cursor column after the grapheme, minus one, is its width."""
    probe = _TERM_PROBES[0]
    buf = "\x1b[1;11R"
    fence = re.search(r"\x1b\[([0-9]+);([0-9]+)R", buf)
    with patch('ttyscan.read_until', return_value=(fence, buf)) as mock_read, \
            patch('ttyscan.write_all'):
        assert probe_width(3, probe) == 10
    assert mock_read.call_args[0][1] == [b'\r' + probe.encode('utf-8')]


def test_probe_width_erases_a_grapheme_left_by_a_missing_cpr():
    """A grapheme is erased even when its cursor position report never arrives."""
    with patch('ttyscan.read_until', side_effect=NoCPRReply("no fence")), \
            patch('ttyscan.write_all') as mock_write:
        with pytest.raises(NoCPRReply):
            probe_width(3, _TERM_PROBES[0])
    mock_write.assert_called_with(3, '\r\x1b[K')


def _ask_sequence(da1, widths):
    candidates = [row for row in _TERM_QUIZ if row[0] == da1]
    asked = []
    while len(candidates) > 1:
        for index in range(len(_TERM_PROBES)):
            if not all(index in row[2] for row in candidates):
                continue
            if len({row[2][index] for row in candidates}) == 1:
                continue
            value = widths[index]
            asked.append(value)
            candidates = [row for row in candidates if row[2][index] == value]
            break
        else:
            break
    return asked


def _resolve_set(da1, widths):
    candidates = [row for row in _TERM_QUIZ if row[0] == da1]
    while len(candidates) > 1:
        for index in range(len(_TERM_PROBES)):
            if not all(index in row[2] for row in candidates):
                continue
            if len({row[2][index] for row in candidates}) == 1:
                continue
            value = widths[index]
            candidates = [row for row in candidates if row[2][index] == value]
            break
        else:
            break
    return [row[1] for row in candidates]


def _da1_reply(da1):
    marker, service, extensions = da1
    params = ";".join(str(value) for value in (service,) + extensions)
    return ("\x1b[" + marker + params + "c").encode()


def _cpr_for_width(width):
    return ("\x1b[1;%dR" % (width + 1)).encode()


@pytest.mark.parametrize("da1,name,widths", _TERM_QUIZ,
                         ids=[row[1] for row in _TERM_QUIZ])
def test_detect_terminal_every_row(da1, name, widths):
    """Every row either resolves uniquely or reports an honest class."""
    def fake_width(fd, probe, timeout):
        return widths[_TERM_PROBES.index(probe)]
    expected = _resolve_set(da1, widths)
    with patch.dict(os.environ, {'TERM': ''}), \
            patch('ttyscan.da1_query', return_value=da1), \
            patch('ttyscan.probe_width', side_effect=fake_width):
        result = detect_terminal(3)
    if len(expected) == 1:
        assert result == name
    else:
        assert name in expected
        assert result is None


@pytest.mark.parametrize("da1,widths", [
    (None, []),
    (('?', 99, ()), []),
    (('?', 6, ()), [99]),
    (('?', 1, (2,)), [3, 99]),
])
def test_detect_terminal_no_match(da1, widths):
    """An unexpected reply leaves the terminal unnamed."""
    with patch('ttyscan.da1_query', return_value=da1), \
            patch('ttyscan.probe_width', side_effect=widths):
        assert detect_terminal(3) is None


def test_detect_terminal_da1_without_a_cpr():
    """A DA1 query without a cursor position report leaves the terminal unnamed."""
    with patch('ttyscan.da1_query', side_effect=NoCPRReply("no fence")):
        assert detect_terminal(3) is None


def _failing_first_probe(widths):
    def fake_width(fd, probe, timeout):
        if probe == _TERM_PROBES[0]:
            raise NoCPRReply("no fence")
        return widths[_TERM_PROBES.index(probe)]
    return fake_width


@pytest.mark.parametrize("terminal", ["GNU Screen", "QTerminal", "alacritty", "st"])
def test_detect_terminal_probe_without_a_cpr_falls_through(terminal):
    """A probe without a cursor position report leaves the next probe to decide."""
    da1, name, widths = next(row for row in _TERM_QUIZ if row[1] == terminal)
    with patch('ttyscan.da1_query', return_value=da1), \
            patch('ttyscan.probe_width', side_effect=_failing_first_probe(widths)):
        assert detect_terminal(3) == name


def test_detect_terminal_probe_without_a_cpr_reports_the_class():
    """A terminal separable only by the failed probe is reported as a class."""
    da1, _name, widths = next(row for row in _TERM_QUIZ if row[1] == "Hyper")
    with patch('ttyscan.da1_query', return_value=da1), \
            patch('ttyscan.probe_width', side_effect=_failing_first_probe(widths)):
        assert detect_terminal(3) is None


@pytest.mark.skipif(sys.platform == "win32", reason="pty requires unix")
@pytest.mark.parametrize("terminal", ["alacritty", "st", "QTerminal", "Hyper",
                                      "zutty"])
def test_generate_exports_ladder_pty(terminal, tmp_path):
    """A silent ENQ falls through to the measured table."""
    da1, name, widths = next(row for row in _TERM_QUIZ if row[1] == terminal)
    quiz_replies = [_CPR_31_128, _da1_reply(da1) + _CPR_31_128]
    quiz_replies += [_cpr_for_width(width) for width in _ask_sequence(da1, widths)]

    env = {
        **dict(os.environ),
        "XDG_CONFIG_HOME": str(tmp_path),
        "TTYSCAN_QUERY_TIMEOUT": "0.5",
        "COVERAGE_FILE": os.path.join(os.path.dirname(__file__), ".coverage"),
    }
    env.pop("COLORTERM", None)
    env.pop("TERM_PROGRAM", None)
    env["TERM"] = "dumb"

    responses = [(0.0, _CPR_31_128),
                 (0.0, _CPR_31_128)]
    responses += [(0.1, reply) for reply in quiz_replies]
    responses += [(0.1, _CPR_31_128),
                  (0.1, _DECRPM_none + _CPR_5_10),
                  (0.1, _CPR_999_999)]

    text, status = _pty_run_staggered(
        [sys.executable, "-m", "coverage", "run", "--append",
         "-m", "ttyscan", "-v"],
        env, responses)

    assert os.WIFEXITED(status)
    assert os.WEXITSTATUS(status) == 0
    assert "export TERM_PROGRAM='%s'" % name in text
    assert "TERM_PROGRAM_VERSION" not in text


@pytest.mark.skipif(sys.platform == "win32", reason="pty requires unix")
@pytest.mark.parametrize("answer,version", [
    (b"urxvt 9.31", "9.31"),
    (b"\x1b[?1;2c", ""),
])
def test_generate_exports_enq_pty(answer, version, tmp_path):
    """An ENQ answerback names the terminal before any measurement."""
    env = {
        **dict(os.environ),
        "XDG_CONFIG_HOME": str(tmp_path),
        "TTYSCAN_QUERY_TIMEOUT": "0.5",
        "COVERAGE_FILE": os.path.join(os.path.dirname(__file__), ".coverage"),
    }
    env.pop("COLORTERM", None)
    env.pop("TERM_PROGRAM", None)
    env["TERM"] = "dumb"

    responses = [(0.0, _CPR_31_128),
                 (0.0, _CPR_31_128),
                 (0.1, answer + _CPR_31_128),
                 (0.1, _CPR_31_128),
                 (0.1, _DECRPM_none + _CPR_5_10),
                 (0.1, _CPR_999_999)]

    text, status = _pty_run_staggered(
        [sys.executable, "-m", "coverage", "run", "--append",
         "-m", "ttyscan", "-v"],
        env, responses)

    assert os.WIFEXITED(status)
    assert os.WEXITSTATUS(status) == 0
    assert "export TERM_PROGRAM='urxvt'" in text
    if version:
        assert "export TERM_PROGRAM_VERSION='%s'" % version in text
    else:
        assert "TERM_PROGRAM_VERSION" not in text


GENERATOR = Path(__file__).parent / "update-detect-table.py"


def _load_generator():
    import importlib.util
    spec = importlib.util.spec_from_file_location("update_detect_table", GENERATOR)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _fake_data_dir(tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    package = tmp_path / "ucs_detect"
    package.mkdir()
    (package / "table_narrow.py").write_text(
        'NARROW_CHARACTERS = (("18.0.0", (0x17D8,)),)\n')
    (package / "table_zwj.py").write_text(
        'EMOJI_ZWJ_SEQUENCES = (("18.0.0", ("PROBE-A", "PROBE-B")),)\n')
    return data_dir


def _fake_run(name, da1, values, method=None, tn=None, n_total=10, narrow=None):
    failed = [{"wchar": probe, "measured_by_terminal": width,
               "measured_by_wcwidth": 2}
              for probe, width in values.items()]
    results = {"emoji_zwj_results": {"17.0": {
        "n_total": n_total, "failed_codepoints": failed}}}
    if narrow is not None:
        results["narrow_results"] = {"18.0.0": {"n_total": n_total,
                                                "failed_codepoints": narrow}}
    return {
        "software_name": name,
        "wcwidth_version": "0.8.4",
        "unicode_version": "18.0.0",
        "terminal_results": {
            "software_method": method,
            "device_attributes": {"raw": da1},
            "xtgettcap": {"capabilities": {"TN": tn} if tn else {}},
        },
        "test_results": results,
    }


@pytest.mark.parametrize("value,expected", [
    (r"\u3248", "\u3248"),
    (r"\U0001f9d1\U0001f3fb\u200d\U0001faef\u200d\U0001f9d1\U0001f3fc",
     "\U0001f9d1\U0001f3fb\u200d\U0001faef\u200d\U0001f9d1\U0001f3fc"),
    ("\u3248", "\u3248"),
])
def test_generator_decode_wchar(value, expected):
    generator = _load_generator()
    assert generator.decode_wchar(value) == expected


@pytest.mark.parametrize("raw,expected", [
    ("\x1b[?1;2c", ('?', 1, (2,))),
    ("\x1b[6c", ('', 6, ())),
    ("\x1b[?62;4;9;22c", ('?', 62, (4, 9, 22))),
])
def test_generator_parse_da1(raw, expected):
    generator = _load_generator()
    assert generator.parse_da1(raw) == expected


@pytest.mark.parametrize("raw", ["", "\x1b[?c", "x"])
def test_generator_parse_da1_rejects(raw):
    generator = _load_generator()
    with pytest.raises(SystemExit):
        generator.parse_da1(raw)


def test_generator_majority_version():
    generator = _load_generator()
    runs = [{"wcwidth_version": "0.8.4"}] * 3 + [{"wcwidth_version": "0.9.2"}]
    assert generator.majority_version(runs) == "0.8.4"


def test_generator_unique_tn():
    generator = _load_generator()
    assert generator.unique_tn(_fake_run("A", "\x1b[?1;2c", {}, tn="kitty"))
    assert not generator.unique_tn(_fake_run("A", "\x1b[?1;2c", {}, tn="xterm"))
    assert not generator.unique_tn(_fake_run("A", "\x1b[?1;2c", {}))


def test_generator_load_width_table_rejects_missing_file(tmp_path):
    generator = _load_generator()
    with pytest.raises(SystemExit):
        generator.load_width_table(tmp_path, "table_narrow", "NARROW_CHARACTERS")


def test_generator_build_rows_skips_other_versions_and_named_terminals(tmp_path):
    generator = _load_generator()
    data_dir = _fake_data_dir(tmp_path)
    runs = [
        _fake_run("Anonymous", "\x1b[?1;2c", {"PROBE-A": 8, "PROBE-B": 2}),
        _fake_run("Named", "\x1b[?1;2c", {"PROBE-A": 2}, method="XTVERSION"),
        _fake_run("Answerback", "\x1b[?1;2c", {"PROBE-A": 2}, method="ENQ"),
        _fake_run("Kitty", "\x1b[?1;2c", {"PROBE-A": 2}, tn="kitty"),
        _fake_run("Older", "\x1b[?1;2c", {"PROBE-A": 2}),
    ]
    runs[-1]["wcwidth_version"] = "0.7.0"
    rows, skipped, expected = generator.build_rows(runs, data_dir)
    assert [row["name"] for row in rows] == ["Anonymous"]
    assert skipped == [("Older", "0.7.0")]
    assert expected["PROBE-A"] == 2
    assert rows[0]["values"] == {"PROBE-A": 8, "PROBE-B": 2}


def test_generator_build_rows_keeps_only_tested_probes(tmp_path):
    generator = _load_generator()
    data_dir = _fake_data_dir(tmp_path)
    runs = [
        _fake_run("Short", "\x1b[?1;2c", {"PROBE-A": 8}, n_total=1),
        _fake_run("Full", "\x1b[?1;2c", {"PROBE-A": 8, "PROBE-B": 5}),
    ]
    rows, _skipped, _expected = generator.build_rows(runs, data_dir)
    assert rows[0]["values"] == {"PROBE-A": 8}
    assert rows[1]["values"] == {"PROBE-A": 8, "PROBE-B": 5}


def test_generator_usable_probe():
    generator = _load_generator()
    assert generator.usable_probe("\U0001f575\U0001f3ff\u200d\u2642\ufe0f")
    assert generator.usable_probe("\U0001faf1\U0001f3ff\u200d\U0001faf2\U0001f3fe")
    assert generator.usable_probe("\u17d8")
    assert not generator.usable_probe("\u0605")
    assert not generator.usable_probe("\u3248")
    assert not generator.usable_probe("\ufe0f")
    assert not generator.usable_probe(
        "\U0001f9d1\U0001f3ff\u200d\U0001faef\u200d\U0001f9d1\U0001f3fe")


def test_generator_build_rows_reads_a_tested_narrow_probe(tmp_path):
    generator = _load_generator()
    data_dir = _fake_data_dir(tmp_path)
    record = [{"wchar": "\u17d8", "measured_by_terminal": 2,
               "measured_by_wcwidth": 1},
              {"wchar": "\u0605", "measured_by_terminal": 0,
               "measured_by_wcwidth": 1}]
    runs = [
        _fake_run("Measured", "\x1b[?1;2c", {"PROBE-A": 2}, narrow=record),
        _fake_run("Tested", "\x1b[?1;2c", {"PROBE-A": 2}, narrow=[]),
    ]
    rows, _skipped, _expected = generator.build_rows(runs, data_dir)
    assert rows[0]["values"]["\u17d8"] == 2
    assert rows[1]["values"]["\u17d8"] == 1
    assert "\u0605" not in rows[0]["values"]


def test_generator_choose_probes():
    generator = _load_generator()
    rows = [
        {"name": "A", "da1": ('?', 6, ()), "values": {"P": 0, "Q": 1}},
        {"name": "B", "da1": ('?', 6, ()), "values": {"P": 1, "Q": 1}},
        {"name": "C", "da1": ('?', 6, ()), "values": {"P": 1, "Q": 2}},
        {"name": "Solo", "da1": ('?', 62, ()), "values": {"P": 1, "Q": 1}},
    ]
    order, unseparated = generator.choose_probes(rows)
    assert set(order) == {"P", "Q"}
    assert unseparated == []


def test_generator_choose_probes_reports_an_unseparated_pair():
    generator = _load_generator()
    rows = [
        {"name": "A", "da1": ('?', 6, ()), "values": {"P": 1}},
        {"name": "B", "da1": ('?', 6, ()), "values": {"P": 1}},
    ]
    order, unseparated = generator.choose_probes(rows)
    assert order == []
    assert unseparated == [("A", "B")]


def test_generator_render_block():
    generator = _load_generator()
    rows = [
        {"name": "A", "da1": ('?', 6, ()), "values": {"P": 0, "Q": 1}},
        {"name": "B", "da1": ('?', 62, ()), "values": {"P": 1}},
    ]
    block = generator.render_block(rows, ["P", "Q"], "note")
    assert "('?', 6, ())" in block
    assert "'A'" in block
    assert "{0: 0, 1: 1}" in block
    assert block.startswith(generator.START)
    assert block.endswith(generator.END)


def test_generator_main_writes_and_checks(tmp_path):
    import yaml
    generator = _load_generator()
    data_dir = _fake_data_dir(tmp_path)
    for run in (_fake_run("Anonymous", "\x1b[?1;2c", {"PROBE-A": 8, "PROBE-B": 4}),
                _fake_run("Other", "\x1b[?6c", {"PROBE-A": 2, "PROBE-B": 2}),
                _fake_run("Older", "\x1b[?6c", {"PROBE-A": 2})):
        if run["software_name"] == "Older":
            run["wcwidth_version"] = "0.7.0"
        with (data_dir / (run["software_name"] + ".yaml")).open("w") as handle:
            yaml.safe_dump(run, handle)

    target = tmp_path / "ttyscan.py"
    target.write_text("head\n%s\n%s\ntail\n" % (generator.START, generator.END))

    args = ["--data-dir", str(data_dir), "--target", str(target)]
    assert generator.main(args) == 0
    text = target.read_text()
    assert "'Anonymous'" in text
    assert generator.START in text and generator.END in text
    assert generator.main(args + ["--check"]) == 0

    target.write_text(text.replace("'Anonymous'", "'Replaced'"))
    assert generator.main(args + ["--check"]) == 1


def test_generator_main_warns_about_unseparable_terminals(tmp_path, capsys):
    import yaml
    generator = _load_generator()
    data_dir = _fake_data_dir(tmp_path)
    for name in ("A", "B"):
        run = _fake_run(name, "\x1b[?1;2c", {"PROBE-A": 2})
        with (data_dir / (name + ".yaml")).open("w") as handle:
            yaml.safe_dump(run, handle)

    target = tmp_path / "ttyscan.py"
    target.write_text("head\n%s\n%s\ntail\n" % (generator.START, generator.END))
    assert generator.main(["--data-dir", str(data_dir),
                           "--target", str(target)]) == 0
    assert "cannot separate" in capsys.readouterr().err
    text = target.read_text()
    assert "'A'" in text and "'B'" in text


def test_generator_load_runs_rejects_empty_directory(tmp_path):
    generator = _load_generator()
    with pytest.raises(SystemExit):
        generator.load_runs(tmp_path)


def test_generator_majority_version_requires_a_version():
    generator = _load_generator()
    with pytest.raises(SystemExit):
        generator.majority_version([{}, {}])


def test_generator_build_rows_rejects_mixed_unicode_versions(tmp_path):
    generator = _load_generator()
    data_dir = _fake_data_dir(tmp_path)
    runs = [_fake_run("A", "\x1b[?1;2c", {"PROBE-A": 8}),
            _fake_run("B", "\x1b[?1;2c", {"PROBE-A": 8})]
    runs[1]["unicode_version"] = "17.0.0"
    with pytest.raises(SystemExit):
        generator.build_rows(runs, data_dir)


def test_generator_build_rows_rejects_wcwidth_disagreement(tmp_path):
    generator = _load_generator()
    data_dir = _fake_data_dir(tmp_path)
    run = _fake_run("A", "\x1b[?1;2c", {"PROBE-A": 8})
    run["test_results"]["narrow_results"] = {"18.0.0": {"failed_codepoints": [
        {"wchar": "PROBE-A", "measured_by_terminal": 1,
         "measured_by_wcwidth": 3}]}}
    with pytest.raises(SystemExit):
        generator.build_rows([run], data_dir)


def test_generator_build_rows_rejects_duplicate_names(tmp_path):
    generator = _load_generator()
    data_dir = _fake_data_dir(tmp_path)
    runs = [_fake_run("A", "\x1b[?1;2c", {"PROBE-A": 8}),
            _fake_run("A", "\x1b[?6c", {"PROBE-A": 2})]
    with pytest.raises(SystemExit):
        generator.build_rows(runs, data_dir)


def test_generator_source_note_reads_git(tmp_path):
    generator = _load_generator()
    subprocess.check_call(["git", "init", "-q", str(tmp_path)])
    (tmp_path / "x.yaml").write_text("x")
    subprocess.check_call(["git", "-C", str(tmp_path), "add", "x.yaml"])
    subprocess.check_call(["git", "-C", str(tmp_path), "-c", "user.email=a@b",
                           "-c", "user.name=a", "commit", "-qm", "x"])

    note = generator.source_note(tmp_path, [{}], 3, 2)
    assert note.endswith(": 1 runs, 2 terminals, 3 probes")
    assert "working tree modified" not in note

    (tmp_path / "x.yaml").write_text("y")
    assert "working tree modified" in generator.source_note(tmp_path, [], 0, 0)
