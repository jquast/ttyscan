"""Tests for ttyscan._termcap."""

import os
from pathlib import Path
from unittest.mock import patch

import pytest

from ttyscan._termcap import (
    _shell_escape,
    _terminfo_to_termcap_bool,
    _terminfo_to_termcap_num,
    _terminfo_to_termcap_str,
    build_termcap_entry,
    ensure_termcap,
)
from ttyscan._terminfo import _escape_value


class TestEscapeValue:
    def test_plain_text(self):
        assert _escape_value("hello") == "hello"

    def test_escape(self):
        assert _escape_value("\x1b") == "\\E"

    def test_newline(self):
        assert _escape_value("\n") == "\\n"

    def test_tab(self):
        assert _escape_value("\t") == "\\t"

    def test_carriage_return(self):
        assert _escape_value("\r") == "\\r"

    def test_backspace(self):
        assert _escape_value("\b") == "\\b"

    def test_form_feed(self):
        assert _escape_value("\f") == "\\f"

    def test_backslash(self):
        assert _escape_value("\\") == "\\\\"

    def test_caret(self):
        assert _escape_value("^") == "\\^"

    def test_control_char(self):
        assert _escape_value("\x01") == "^A"

    def test_delete(self):
        assert _escape_value("\x7f") == "^?"

    def test_mixed(self):
        result = _escape_value("\x1b[1mhello")
        assert result == "\\E[1mhello"

    def test_terminfo_space(self):
        assert _escape_value(" ", terminfo=True) == "\\s"

    def test_terminfo_colon(self):
        assert _escape_value(":", terminfo=True) == "\\:"

    def test_termcap_no_escape_space(self):
        assert _escape_value(" ") == " "

    def test_termcap_no_escape_colon(self):
        assert _escape_value(":") == ":"


class TestEscapeTerminfoValue:
    """Tests for terminfo-specific escaping via _escape_terminfo_value."""
    pass


class TestShellEscape:
    def test_plain(self):
        assert _shell_escape("hello") == "'hello'"

    def test_empty(self):
        assert _shell_escape("") == "''"

    def test_with_single_quote(self):
        assert _shell_escape("it's") == "'it'\\''s'"

    def test_with_special_chars(self):
        assert _shell_escape("a$b") == "'a$b'"


class TestTerminfoToTermcapMappings:
    def test_bool_known(self):
        assert _terminfo_to_termcap_bool("am") == "am"
        assert _terminfo_to_termcap_bool("bce") == "ut"
        assert _terminfo_to_termcap_bool("km") == "km"
        assert _terminfo_to_termcap_bool("xenl") == "xn"

    def test_bool_unknown(self):
        assert _terminfo_to_termcap_bool("nonexistent") is None

    def test_num_known(self):
        assert _terminfo_to_termcap_num("colors") == "Co"
        assert _terminfo_to_termcap_num("cols") == "co"
        assert _terminfo_to_termcap_num("lines") == "li"

    def test_num_unknown(self):
        assert _terminfo_to_termcap_num("nonexistent") is None

    def test_str_known(self):
        assert _terminfo_to_termcap_str("clear") == "cl"
        assert _terminfo_to_termcap_str("cup") == "cm"
        assert _terminfo_to_termcap_str("home") == "ho"
        assert _terminfo_to_termcap_str("smcup") == "ti"
        assert _terminfo_to_termcap_str("rmcup") == "te"

    def test_str_unknown(self):
        assert _terminfo_to_termcap_str("nonexistent") is None


class TestBuildTermcapEntry:
    def test_all_cap_types(self):
        entry = build_termcap_entry(
            "myterm",
            str_caps={"clear": "\x1b[H\x1b[2J", "home": "\x1b[H"},
            num_caps={"colors": 256, "cols": 80},
            bool_caps={"am", "km"},
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
            str_caps={"unknown_cap": "value", "clear": "\x1b[H"},
            num_caps={"unknown_num": 42, "colors": 8},
            bool_caps={"unknown_bool", "am"},
        )
        assert ":am:" in entry
        assert ":Co#8:" in entry
        assert ":cl=\\E[H:" in entry
        assert "unknown_cap" not in entry
        assert "unknown_num" not in entry
        assert "unknown_bool" not in entry

    def test_empty(self):
        entry = build_termcap_entry("e", {}, {}, set())
        assert entry == "e|XTGETTCAP-discovered terminal:"


class TestEnsureTermcap:
    def test_builder_success_same_as_env(self, monkeypatch):
        entry = "myterm|XTGETTCAP-discovered terminal::am:"
        monkeypatch.setenv("TERMCAP", entry)
        with patch("ttyscan._termcap.build_termcap_entry", return_value=entry):
            result = ensure_termcap(
                "myterm", Path("/tmp/ti"), {}, {}, set(),
            )
            assert result is None

    def test_builder_success_force(self, monkeypatch):
        entry = "myterm|XTGETTCAP-discovered terminal::am:"
        monkeypatch.setenv("TERMCAP", entry)
        with patch("ttyscan._termcap.build_termcap_entry", return_value=entry):
            result = ensure_termcap(
                "myterm", Path("/tmp/ti"), {}, {}, set(), force=True,
            )
            assert result == f"export TERMCAP='{entry}'"

    def test_builder_success_different_from_env(self, monkeypatch):
        entry = "myterm|XTGETTCAP-discovered terminal::am:"
        monkeypatch.setenv("TERMCAP", "old-value")
        with patch("ttyscan._termcap.build_termcap_entry", return_value=entry):
            result = ensure_termcap(
                "myterm", Path("/tmp/ti"), {}, {}, set(),
            )
            assert result == f"export TERMCAP='{entry}'"

    def test_no_env_termcap(self, monkeypatch):
        monkeypatch.delenv("TERMCAP", raising=False)
        entry = "myterm|XTGETTCAP-discovered terminal::am:"
        with patch("ttyscan._termcap.build_termcap_entry", return_value=entry):
            result = ensure_termcap(
                "myterm", Path("/tmp/ti"), {}, {}, set(),
            )
            assert result == f"export TERMCAP='{entry}'"
