"""Tests for ttyscan2 standalone module."""

import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from ttyscan2 import (
    build_termcap_entry,
    build_terminfo_binary,
    check_colorterm,
    check_lines_columns,
    check_term,
    classify_caps,
    escape_value,
    generate_exports,
    has_meaningful_caps,
    hex_decode,
    hex_encode,
    normalize_terminal_name,
    pack_short_le,
    sanitize_term_name,
    shell_escape,
    unescape_terminfo,
    _CANONICAL_BOOL_CAPS,
    _CANONICAL_NUM_CAPS,
    _CANONICAL_STR_CAPS,
)


class TestHexCodec:
    def test_encode(self):
        assert hex_encode("TN") == "544e"
        assert hex_encode("RGB") == "524742"

    def test_decode(self):
        assert hex_decode("544e") == "TN"
        assert hex_decode("") == ""
        assert hex_decode("xyz") == ""


class TestUnescapeTerminfo:
    def test_plain(self):
        assert unescape_terminfo("hello") == "hello"

    def test_escape_e(self):
        assert unescape_terminfo("\\E") == "\x1b"

    def test_newline(self):
        assert unescape_terminfo("\\n") == "\n"

    def test_tab(self):
        assert unescape_terminfo("\\t") == "\t"

    def test_cr(self):
        assert unescape_terminfo("\\r") == "\r"

    def test_backspace(self):
        assert unescape_terminfo("\\b") == "\b"

    def test_formfeed(self):
        assert unescape_terminfo("\\f") == "\f"

    def test_backslash(self):
        assert unescape_terminfo("\\\\") == "\\"

    def test_caret(self):
        assert unescape_terminfo("\\^") == "^"

    def test_colon(self):
        assert unescape_terminfo("\\:") == ":"

    def test_octal(self):
        assert unescape_terminfo("\\007") == "\x07"

    def test_caret_control(self):
        assert unescape_terminfo("^G") == "\x07"
        assert unescape_terminfo("^?") == "\x7f"

    def test_mixed(self):
        assert unescape_terminfo("\\E[1m") == "\x1b[1m"


class TestClassifyCaps:
    def test_bool_caps(self):
        caps = {"am": "", "bce": "", "km": "", "notabool": ""}
        result = classify_caps(caps)
        assert result["bool_caps"] == {"am", "bce", "km"}
        assert result["num_caps"] == {}
        assert result["str_caps"] == {}

    def test_num_caps(self):
        caps = {"colors": "256", "cols": "80", "it": "8", "notanum": "skip"}
        result = classify_caps(caps)
        assert result["num_caps"] == {"colors": 256, "cols": 80, "it": 8}

    def test_str_caps(self):
        caps = {"clear": "\x1b[H", "bel": "\x07", "TN": "xterm-kitty"}
        result = classify_caps(caps)
        assert result["str_caps"] == {"clear": "\x1b[H", "bel": "\x07"}
        assert "TN" not in result["str_caps"]

    def test_rgb_skipped(self):
        caps = {"RGB": "8/8/8", "bel": "\x07"}
        result = classify_caps(caps)
        assert result["str_caps"] == {"bel": "\x07"}


class TestHasMeaningfulCaps:
    def test_screen_str_caps(self):
        assert has_meaningful_caps({"clear": "..."}, {}, set()) is True

    def test_keyboard_only(self):
        assert has_meaningful_caps({"kf1": "..."}, {}, set()) is False

    def test_keyboard_with_screen(self):
        assert has_meaningful_caps({"kf1": "...", "clear": "..."}, {}, set()) is True

    def test_keyboard_with_nums(self):
        assert has_meaningful_caps({"kf1": "..."}, {"cols": 80}, set()) is True

    def test_bool_caps(self):
        assert has_meaningful_caps({}, {}, {"am"}) is True

    def test_meaningful_nums(self):
        assert has_meaningful_caps({}, {"cols": 80}, set()) is True

    def test_only_colors(self):
        assert has_meaningful_caps({}, {"colors": 256}, set()) is False

    def test_empty(self):
        assert has_meaningful_caps({}, {}, set()) is False


class TestCheckColorterm:
    def test_rgb_8bit(self, monkeypatch):
        monkeypatch.delenv("COLORTERM", raising=False)
        assert check_colorterm({"RGB": "8/8/8"}, False) == "export COLORTERM=truecolor"

    def test_already_set(self, monkeypatch):
        monkeypatch.setenv("COLORTERM", "truecolor")
        assert check_colorterm({"RGB": "8/8/8"}, False) is None

    def test_force(self, monkeypatch):
        monkeypatch.setenv("COLORTERM", "truecolor")
        assert check_colorterm({"RGB": "8/8/8"}, True) == "export COLORTERM=truecolor"

    def test_not_8bit(self):
        assert check_colorterm({"RGB": "6/6/6"}, False) is None

    def test_empty(self):
        assert check_colorterm({"RGB": ""}, False) is None

    def test_missing(self):
        assert check_colorterm({}, False) is None

    def test_invalid(self):
        assert check_colorterm({"RGB": "bad"}, False) is None


class TestCheckTerm:
    def test_differs(self, monkeypatch):
        monkeypatch.setenv("TERM", "xterm")
        assert check_term({"TN": "kitty"}, False) == "export TERM=kitty"

    def test_same(self, monkeypatch):
        monkeypatch.setenv("TERM", "xterm")
        assert check_term({"TN": "xterm"}, False) is None

    def test_force(self, monkeypatch):
        monkeypatch.setenv("TERM", "xterm")
        assert check_term({"TN": "xterm"}, True) == "export TERM=xterm"

    def test_missing(self):
        assert check_term({}, False) is None

    def test_empty_string(self, monkeypatch):
        monkeypatch.setenv("TERM", "xterm")
        assert check_term({"TN": ""}, False) is None


class TestCheckLinesColumns:
    @staticmethod
    def _make_winsize(cols, rows):
        return cols, rows

    def test_exports_different(self):
        ws = self._make_winsize(80, 24)
        with patch.dict(os.environ, {}, clear=True):
            result = check_lines_columns(30, 100, ws, False)
        assert result == ["export LINES=30", "export COLUMNS=100"]

    def test_skips_when_matches_term_and_unset(self):
        ws = self._make_winsize(100, 30)
        with patch.dict(os.environ, {}, clear=True):
            result = check_lines_columns(30, 100, ws, False)
        assert result is None

    def test_skips_when_matches_env(self):
        ws = self._make_winsize(80, 24)
        with patch.dict(os.environ, {"LINES": "30", "COLUMNS": "100"}):
            result = check_lines_columns(30, 100, ws, False)
        assert result is None

    def test_exports_when_env_wrong(self):
        ws = self._make_winsize(100, 30)
        with patch.dict(os.environ, {"LINES": "24", "COLUMNS": "80"}):
            result = check_lines_columns(30, 100, ws, False)
        assert result == ["export LINES=30", "export COLUMNS=100"]

    def test_force(self):
        ws = self._make_winsize(100, 30)
        with patch.dict(os.environ, {"LINES": "30", "COLUMNS": "100"}):
            result = check_lines_columns(30, 100, ws, True)
        assert result == ["export LINES=30", "export COLUMNS=100"]

    def test_partial(self):
        ws = self._make_winsize(100, 30)
        with patch.dict(os.environ, {"LINES": "30", "COLUMNS": "99"}):
            result = check_lines_columns(30, 100, ws, False)
        assert result == ["export COLUMNS=100"]

    def test_empty_env_term_differs(self):
        ws = self._make_winsize(80, 24)
        with patch.dict(os.environ, {}, clear=True):
            result = check_lines_columns(30, 100, ws, False)
        assert result == ["export LINES=30", "export COLUMNS=100"]


class TestPackShortLe:
    def test_positive(self):
        buf = bytearray(2)
        pack_short_le(buf, 0, 42)
        assert buf[0] == 42
        assert buf[1] == 0

    def test_negative(self):
        buf = bytearray(2)
        pack_short_le(buf, 0, -1)
        assert buf[0] == 0xFF
        assert buf[1] == 0xFF

    def test_large(self):
        buf = bytearray(2)
        pack_short_le(buf, 0, 256)
        assert buf[0] == 0
        assert buf[1] == 1


class TestBuildTerminfoBinary:
    def test_simple(self):
        data = build_terminfo_binary(
            "test", {"clear": "\x1b[H\x1b[2J"}, {"colors": 256}, {"am"},
        )
        assert data is not None
        assert len(data) > 12

    def test_32bit_numeric(self):
        data = build_terminfo_binary(
            "test32", {"clear": "\x1b[H"},
            {"colors": 256, "pairs": 65536}, set(),
        )
        assert data is not None
        assert data[0] == 0x1E
        assert data[1] == 0x02

    def test_empty(self):
        data = build_terminfo_binary("test", {}, {}, set())
        assert data is not None
        assert len(data) >= 12

    def test_unknown_skipped(self):
        data = build_terminfo_binary(
            "test", {}, {}, set(),
        )
        assert data is not None

    def test_header_magic(self):
        data = build_terminfo_binary("test", {}, {}, set())
        assert data[0] == 0x1A
        assert data[1] == 0x01


class TestSanitizeTermName:
    def test_plain(self):
        assert sanitize_term_name("xterm") == "xterm"

    def test_hyphen(self):
        assert sanitize_term_name("xterm-256color") == "xterm-256color"

    def test_path_traversal(self):
        assert sanitize_term_name("../../etc/passwd") == "etcpasswd"

    def test_empty(self):
        assert sanitize_term_name("") == "unknown"

    def test_all_special(self):
        assert sanitize_term_name("../../../") == "unknown"


class TestEscapeValue:
    def test_plain(self):
        assert escape_value("hello") == "hello"

    def test_escape(self):
        assert escape_value("\x1b") == "\\E"

    def test_newline(self):
        assert escape_value("\n") == "\\n"

    def test_control_char(self):
        assert escape_value("\x01") == "^A"

    def test_delete(self):
        assert escape_value("\x7f") == "^?"

    def test_terminfo_space(self):
        assert escape_value(" ", terminfo=True) == "\\s"

    def test_terminfo_colon(self):
        assert escape_value(":", terminfo=True) == "\\:"


class TestShellEscape:
    def test_plain(self):
        assert shell_escape("hello") == "'hello'"

    def test_empty(self):
        assert shell_escape("") == "''"

    def test_with_single_quote(self):
        assert shell_escape("it's") == "'it'\\''s'"

    def test_special_chars(self):
        assert shell_escape("a$b") == "'a$b'"


class TestBuildTermcapEntry:
    def test_all_types(self):
        entry = build_termcap_entry(
            "myterm",
            {"clear": "\x1b[H\x1b[2J", "home": "\x1b[H"},
            {"colors": 256, "cols": 80},
            {"am", "km"},
        )
        assert "myterm|XTGETTCAP-discovered terminal:" in entry
        assert ":am:" in entry
        assert ":km:" in entry
        assert ":Co#256:" in entry
        assert ":co#80:" in entry
        assert ":cl=\\E[H\\E[2J:" in entry
        assert ":ho=\\E[H:" in entry

    def test_only_known_mappings(self):
        entry = build_termcap_entry(
            "t",
            {"unknown_cap": "value", "clear": "\x1b[H"},
            {"unknown_num": 42, "colors": 8},
            {"unknown_bool", "am"},
        )
        assert ":am:" in entry
        assert ":Co#8:" in entry
        assert ":cl=\\E[H:" in entry
        assert "unknown" not in entry

    def test_empty(self):
        entry = build_termcap_entry("e", {}, {}, set())
        assert entry == "e|XTGETTCAP-discovered terminal:"


class TestNormalizeTerminalName:
    def test_wezterm(self):
        assert normalize_terminal_name("WezTerm") == "wezterm"

    def test_other(self):
        assert normalize_terminal_name("xterm-kitty") == "xterm-kitty"


class TestGenerateExports:
    def test_no_terminal(self):
        with patch("ttyscan2.open_tty", return_value=(None, None)):
            assert generate_exports() == []

    def test_no_xtgettcap(self):
        with patch("ttyscan2.open_tty", return_value=(3, 4)):
            with patch("ttyscan2.set_cbreak", return_value=None):
                with patch("ttyscan2.get_winsize", return_value=(80, 24)):
                    with patch("ttyscan2.xtgettcap_query", return_value={}):
                        with patch("ttyscan2.restore_termios"):
                            result = generate_exports()
        assert result == []

    def test_no_tn(self):
        with patch("ttyscan2.open_tty", return_value=(3, 4)):
            with patch("ttyscan2.set_cbreak", return_value=None):
                with patch("ttyscan2.get_winsize", return_value=(80, 24)):
                    with patch("ttyscan2.xtgettcap_query", return_value={"RGB": "8/8/8"}):
                        with patch("ttyscan2.restore_termios"):
                            result = generate_exports()
        assert result == []

    def test_terminfo_available_skip_full(self):
        with patch("ttyscan2.open_tty", return_value=(3, 4)):
            with patch("ttyscan2.set_cbreak", return_value=None):
                with patch("ttyscan2.get_winsize", return_value=(80, 24)):
                    init = {"TN": "myterm", "RGB": "8/8/8"}
                    with patch("ttyscan2.xtgettcap_query", return_value=init):
                        with patch("ttyscan2.detect_size", return_value=None):
                            with patch("ttyscan2.has_terminfo", return_value=True):
                                with patch("ttyscan2.restore_termios"):
                                    with patch.dict(os.environ, {}, clear=True):
                                        result = generate_exports()
        assert "export COLORTERM=truecolor" in result
        assert "export TERM=myterm" in result
        assert not any("TERMINFO" in r for r in result)

    def test_minimal_caps_skip(self):
        init = {"TN": "minterm", "RGB": "8/8/8"}
        full = {"colors": "256"}
        classified = {"bool_caps": set(), "num_caps": {"colors": 256},
                       "str_caps": {}}
        with patch("ttyscan2.open_tty", return_value=(3, 4)):
            with patch("ttyscan2.set_cbreak", return_value=None):
                with patch("ttyscan2.get_winsize", return_value=(80, 24)):
                    with patch("ttyscan2.xtgettcap_query",
                               side_effect=[init, full]):
                        with patch("ttyscan2.detect_size", return_value=None):
                            with patch("ttyscan2.has_terminfo",
                                       return_value=False):
                                with patch("ttyscan2.classify_caps",
                                           return_value=classified):
                                    with patch("ttyscan2.restore_termios"):
                                        with patch.dict(
                                            os.environ, {"TERM": "xterm"},
                                            clear=True,
                                        ):
                                            result = generate_exports()
        assert "export TERM=minterm" in result
        assert "export COLORTERM=truecolor" in result
        assert not any("TERMINFO" in r for r in result)

    def test_full_exports(self, tmp_path):
        terminfo_dir = tmp_path / ".terminfo"
        init = {"TN": "myterm", "RGB": "8/8/8"}
        full = {"clear": "\x1b[H\x1b[2J", "colors": "256", "am": ""}
        classified = {
            "bool_caps": {"am"}, "num_caps": {"colors": 256},
            "str_caps": {"clear": "\x1b[H\x1b[2J"},
        }
        with patch("ttyscan2.open_tty", return_value=(3, 4)):
            with patch("ttyscan2.set_cbreak", return_value=None):
                with patch("ttyscan2.get_winsize", return_value=(80, 24)):
                    with patch("ttyscan2.xtgettcap_query",
                               side_effect=[init, full]):
                        with patch("ttyscan2.detect_size", return_value=None):
                            with patch("ttyscan2.has_terminfo",
                                       return_value=False):
                                with patch("ttyscan2.classify_caps",
                                           return_value=classified):
                                    with patch(
                                        "ttyscan2.ttyscan_terminfo_dir",
                                        return_value=terminfo_dir,
                                    ):
                                        with patch(
                                            "ttyscan2.restore_termios",
                                        ):
                                            with patch.dict(
                                                os.environ,
                                                {"TERM": "xterm",
                                                 "HOME": str(tmp_path)},
                                                clear=True,
                                            ):
                                                result = generate_exports(
                                                    termcap=True,
                                                )
        assert "export COLORTERM=truecolor" in result
        assert "export TERM=myterm" in result
        assert f"export TERMINFO={terminfo_dir}" in result
        assert any("TERMCAP" in r for r in result)


class TestBinaryIdenticalToOriginal:
    """Verify ttyscan2 binary output matches original ttyscan._terminfo."""

    def test_identical_kitty_data(self):
        from ttyscan._terminfo import _build_terminfo_binary as orig_build
        caps = {
            "am": "", "bce": "", "ccc": "", "km": "", "mc5i": "",
            "mir": "", "msgr": "", "npc": "", "xenl": "", "hs": "", "bw": "",
            "colors": "256", "cols": "80", "lines": "24",
            "pairs": "32767", "it": "8",
            "clear": "\x1b[H\x1b[2J", "bel": "\x07",
            "blink": "\x1b[5m", "bold": "\x1b[1m",
            "cup": "\x1b[%i%p1%d;%p2%dH",
        }
        classified = classify_caps(caps)
        new_data = build_terminfo_binary("xterm-kitty", **classified)

        from ttyscan._caps_data import (
            _CANONICAL_BOOL_CAPS as o_bool,
            _CANONICAL_NUM_CAPS as o_num,
            _CANONICAL_STR_CAPS as o_str,
        )
        bool_set = frozenset(o_bool)
        num_set = frozenset(o_num)
        str_set = frozenset(o_str)
        orig_classified = {
            "bool_caps": set(), "num_caps": {}, "str_caps": {},
        }
        for name, value in caps.items():
            if name == "RGB":
                continue
            if not value:
                if name in bool_set:
                    orig_classified["bool_caps"].add(name)
            elif name in num_set:
                if value.isdigit():
                    orig_classified["num_caps"][name] = int(value)
            elif name in str_set:
                orig_classified["str_caps"][name] = value

        old_data = orig_build("xterm-kitty", **orig_classified)
        assert new_data == old_data
