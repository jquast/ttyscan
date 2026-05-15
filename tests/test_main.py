"""Tests for ttyscan.__main__."""

import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from ttyscan.__main__ import (
    _check_colorterm,
    _check_lines_columns,
    _check_term,
    _detect_terminal_size,
    _has_meaningful_caps,
    _normalize_terminal_name,
    _verbose,
    generate_exports,
    main,
)


class TestHasMeaningfulCaps:
    def test_str_caps(self):
        assert _has_meaningful_caps({"clear": "..."}, {}, set()) is True

    def test_keyboard_only_str_caps(self):
        assert _has_meaningful_caps({"kf1": "..."}, {}, set()) is False

    def test_keyboard_str_caps_with_screen_str_caps(self):
        assert _has_meaningful_caps(
            {"kf1": "...", "clear": "..."}, {}, set(),
        ) is True

    def test_keyboard_str_caps_with_meaningful_nums(self):
        assert _has_meaningful_caps(
            {"kf1": "..."}, {"cols": 80}, set(),
        ) is True

    def test_keyboard_str_caps_with_bool_caps(self):
        assert _has_meaningful_caps(
            {"kf1": "..."}, {}, {"am"},
        ) is True

    def test_bool_caps(self):
        assert _has_meaningful_caps({}, {}, {"am"}) is True

    def test_meaningful_nums(self):
        assert _has_meaningful_caps({}, {"cols": 80}, set()) is True

    def test_only_colors(self):
        assert _has_meaningful_caps({}, {"colors": 256}, set()) is False

    def test_empty(self):
        assert _has_meaningful_caps({}, {}, set()) is False

    def test_colors_and_co(self):
        assert _has_meaningful_caps({}, {"colors": 256, "Co": 256}, set()) is False


class TestCheckColorterm:
    def test_rgb_8bit_truecolor(self, monkeypatch):
        monkeypatch.delenv("COLORTERM", raising=False)
        tc = MagicMock()
        tc.capabilities = {"RGB": "8/8/8"}
        result = _check_colorterm(tc)
        assert result == "export COLORTERM=truecolor"

    def test_rgb_8bit_already_set(self, monkeypatch):
        monkeypatch.setenv("COLORTERM", "truecolor")
        tc = MagicMock()
        tc.capabilities = {"RGB": "8/8/8"}
        result = _check_colorterm(tc)
        assert result is None

    def test_rgb_8bit_force(self, monkeypatch):
        monkeypatch.setenv("COLORTERM", "truecolor")
        tc = MagicMock()
        tc.capabilities = {"RGB": "8/8/8"}
        result = _check_colorterm(tc, force=True)
        assert result == "export COLORTERM=truecolor"

    def test_rgb_not_8bit(self):
        tc = MagicMock()
        tc.capabilities = {"RGB": "6/6/6"}
        result = _check_colorterm(tc)
        assert result is None

    def test_rgb_empty(self):
        tc = MagicMock()
        tc.capabilities = {"RGB": ""}
        result = _check_colorterm(tc)
        assert result is None

    def test_rgb_missing(self):
        tc = MagicMock()
        tc.capabilities = {}
        result = _check_colorterm(tc)
        assert result is None

    def test_rgb_invalid(self):
        tc = MagicMock()
        tc.capabilities = {"RGB": "not-a-number"}
        result = _check_colorterm(tc)
        assert result is None

    def test_rgb_different_colorterm(self, monkeypatch):
        monkeypatch.setenv("COLORTERM", "24bit")
        tc = MagicMock()
        tc.capabilities = {"RGB": "8/8/8"}
        result = _check_colorterm(tc)
        assert result == "export COLORTERM=truecolor"


class TestCheckTerm:
    def test_tn_differs(self, monkeypatch):
        monkeypatch.setenv("TERM", "xterm")
        tc = MagicMock()
        tc.capabilities = {"TN": "kitty"}
        result = _check_term(tc)
        assert result == "export TERM=kitty"

    def test_tn_same(self, monkeypatch):
        monkeypatch.setenv("TERM", "xterm")
        tc = MagicMock()
        tc.capabilities = {"TN": "xterm"}
        result = _check_term(tc)
        assert result is None

    def test_tn_force(self, monkeypatch):
        monkeypatch.setenv("TERM", "xterm")
        tc = MagicMock()
        tc.capabilities = {"TN": "xterm"}
        result = _check_term(tc, force=True)
        assert result == "export TERM=xterm"

    def test_tn_missing(self):
        tc = MagicMock()
        tc.capabilities = {}
        result = _check_term(tc)
        assert result is None

    def test_tn_empty_string(self, monkeypatch):
        monkeypatch.setenv("TERM", "xterm")
        tc = MagicMock()
        tc.capabilities = {"TN": ""}
        result = _check_term(tc)
        assert result is None


class TestGenerateExports:
    def setup_method(self):
        self._size_patcher = patch(
            "ttyscan.__main__._detect_terminal_size", return_value=None,
        )
        self._size_patcher.start()
        self._has_ti_patcher = patch(
            "ttyscan.__main__.has_terminfo", return_value=False,
        )
        self._has_ti_patcher.start()

    def teardown_method(self):
        self._size_patcher.stop()
        self._has_ti_patcher.stop()

    def test_no_xtgettcap(self):
        with patch("ttyscan.__main__.Terminal") as MockTerminal:
            mock_term = MockTerminal.return_value
            mock_term.get_xtgettcap.return_value = None
            result = generate_exports()
            assert result == []

    def test_unsupported_xtgettcap(self):
        with patch("ttyscan.__main__.Terminal") as MockTerminal:
            mock_term = MockTerminal.return_value
            tc = MagicMock()
            tc.supported = False
            mock_term.get_xtgettcap.return_value = tc
            result = generate_exports()
            assert result == []

    def test_no_tn(self):
        with patch("ttyscan.__main__.Terminal") as MockTerminal:
            mock_term = MockTerminal.return_value
            tc = MagicMock()
            tc.supported = True
            tc.capabilities = {"RGB": "8/8/8"}
            tc.make_jinxed_capabilities.return_value = {
                "str_caps": {}, "num_caps": {}, "bool_caps": set(),
            }
            mock_term.get_xtgettcap.return_value = tc

            with patch.dict(os.environ, {}, clear=True):
                result = generate_exports()
            assert result == []

    def test_fast_ok_full_none(self):
        """Fast probe succeeds but full get_xtgettcap() returns None."""
        with patch("ttyscan.__main__.Terminal") as MockTerminal:
            mock_term = MockTerminal.return_value
            fast = MagicMock()
            fast.supported = True
            fast.capabilities = {"TN": "myterm", "RGB": "8/8/8"}
            mock_term.get_xtgettcap.side_effect = [fast, None]

            with patch.dict(os.environ, {}, clear=True):
                result = generate_exports()
            assert result == []

    def test_terminfo_already_available_skip_full_query(self):
        """Skip full query when terminfo exists and no force/termcap."""
        with patch("ttyscan.__main__.Terminal") as MockTerminal:
            mock_term = MockTerminal.return_value
            fast = MagicMock()
            fast.supported = True
            fast.capabilities = {"TN": "myterm", "RGB": "8/8/8"}
            mock_term.get_xtgettcap.return_value = fast

            with patch("ttyscan.__main__.has_terminfo", return_value=True):
                with patch.dict(os.environ, {}, clear=True):
                    result = generate_exports()
            assert result == ["export COLORTERM=truecolor", "export TERM=myterm"]

    def test_minimal_caps_skip_terminfo(self):
        """Only TN/colors/RGB, skip TERMINFO/TERMCAP."""
        with patch("ttyscan.__main__.Terminal") as MockTerminal:
            mock_term = MockTerminal.return_value
            tc = MagicMock()
            tc.supported = True
            tc.capabilities = {"RGB": "8/8/8", "TN": "minterm"}
            tc.make_jinxed_capabilities.return_value = {
                "str_caps": {}, "num_caps": {"colors": 256}, "bool_caps": set(),
            }
            mock_term.get_xtgettcap.return_value = tc

            with patch.dict(os.environ, {"TERM": "xterm"}, clear=True):
                with patch("ttyscan.__main__.ensure_terminfo") as mock_ensure:
                    result = generate_exports()

            mock_ensure.assert_not_called()
            assert "export COLORTERM=truecolor" in result
            assert "export TERM=minterm" in result
            assert not any("TERMINFO" in r for r in result)
            assert not any("TERMCAP" in r for r in result)

    def test_keyboard_only_caps_skip_terminfo(self):
        """Keyboard-only string caps (kf1, kbs, etc.) skip terminfo."""
        with patch("ttyscan.__main__.Terminal") as MockTerminal:
            mock_term = MockTerminal.return_value
            tc = MagicMock()
            tc.supported = True
            tc.capabilities = {"RGB": "8/8/8", "TN": "xterm"}
            tc.make_jinxed_capabilities.return_value = {
                "str_caps": {"kf1": "\x1bOP", "kbs": "\x7f"},
                "num_caps": {"colors": 256},
                "bool_caps": set(),
            }
            mock_term.get_xtgettcap.return_value = tc

            with patch.dict(os.environ, {}, clear=True):
                # no TERM in env → _check_term will export
                result = generate_exports()

            assert "export COLORTERM=truecolor" in result
            assert "export TERM=xterm" in result
            assert not any("TERMINFO" in r for r in result)

    def test_full_exports(self, monkeypatch, tmp_path):
        """All exports including TERMCAP via -t."""
        terminfo_dir = tmp_path / ".terminfo"

        with patch("ttyscan.__main__.Terminal") as MockTerminal:
            mock_term = MockTerminal.return_value
            tc = MagicMock()
            tc.supported = True
            tc.capabilities = {"RGB": "8/8/8", "TN": "myterm"}
            tc.make_jinxed_capabilities.return_value = {
                "str_caps": {"clear": "\x1b[H\x1b[2J"},
                "num_caps": {"colors": 256},
                "bool_caps": {"am"},
            }
            mock_term.get_xtgettcap.return_value = tc

            with patch("ttyscan.__main__.ensure_terminfo") as mock_ensure_ti:
                mock_ensure_ti.return_value = terminfo_dir
                with patch("ttyscan.__main__.ensure_termcap") as mock_ensure_tc:
                    mock_ensure_tc.return_value = "export TERMCAP='myterm:...'"
                    env = {"TERM": "xterm", "HOME": str(tmp_path)}
                    with patch.dict(os.environ, env, clear=True):
                        result = generate_exports(termcap=True)

            assert "export COLORTERM=truecolor" in result
            assert "export TERM=myterm" in result
            assert f"export TERMINFO={terminfo_dir}" in result
            assert "export TERMCAP='myterm:...'" in result

    def test_full_exports_no_termcap_by_default(self):
        """TERMCAP not exported unless -t is given."""
        with patch("ttyscan.__main__.Terminal") as MockTerminal:
            mock_term = MockTerminal.return_value
            tc = MagicMock()
            tc.supported = True
            tc.capabilities = {"TN": "myterm"}
            tc.make_jinxed_capabilities.return_value = {
                "str_caps": {"clear": "\x1b[H"},
                "num_caps": {},
                "bool_caps": set(),
            }
            mock_term.get_xtgettcap.return_value = tc

            with patch("ttyscan.__main__.ensure_terminfo") as mock_ensure_ti:
                from pathlib import Path
                mock_ensure_ti.return_value = Path("/some/terminfo")
                env = {"TERM": "xterm"}
                with patch.dict(os.environ, env, clear=True):
                    result = generate_exports(termcap=False)

            assert f"export TERMINFO=/some/terminfo" in result
            assert not any("TERMCAP" in r for r in result)

    def test_terminfo_system_available(self):
        """System terminfo available, skip TERMINFO/TERMCAP."""
        with patch("ttyscan.__main__.Terminal") as MockTerminal:
            mock_term = MockTerminal.return_value
            tc = MagicMock()
            tc.supported = True
            tc.capabilities = {"RGB": "8/8/8", "TN": "myterm"}
            tc.make_jinxed_capabilities.return_value = {
                "str_caps": {"clear": "\x1b[H"},
                "num_caps": {},
                "bool_caps": set(),
            }
            mock_term.get_xtgettcap.return_value = tc

            with patch("ttyscan.__main__.ensure_terminfo") as mock_ensure:
                mock_ensure.return_value = None
                env = {"TERM": "xterm", "COLORTERM": "truecolor"}
                with patch.dict(os.environ, env):
                    result = generate_exports()

            assert "export TERM=myterm" in result
            assert not any("TERMINFO" in r for r in result)
            assert not any("TERMCAP" in r for r in result)

    def test_terminfo_already_in_env_same_path(self):
        """TERMINFO already set to ttyscan path, skip re-export."""
        terminfo_dir = "/home/user/.config/ttyscan/terminfo"
        with patch("ttyscan.__main__.Terminal") as MockTerminal:
            mock_term = MockTerminal.return_value
            tc = MagicMock()
            tc.supported = True
            tc.capabilities = {"TN": "myterm"}
            tc.make_jinxed_capabilities.return_value = {
                "str_caps": {"clear": "\x1b[H"},
                "num_caps": {},
                "bool_caps": set(),
            }
            mock_term.get_xtgettcap.return_value = tc

            with patch("ttyscan.__main__.ensure_terminfo") as mock_ensure_ti:
                mock_ensure_ti.return_value = Path(terminfo_dir)
                env = {"TERM": "myterm", "TERMINFO": terminfo_dir}
                with patch.dict(os.environ, env):
                    result = generate_exports()

            assert not any("TERMINFO" in r for r in result)
            assert not any("TERMCAP" in r for r in result)

    def test_terminfo_differs_from_env(self):
        """TERMINFO set to different value, export ttyscan path."""
        ttyscan_path = "/home/user/.config/ttyscan/terminfo"
        with patch("ttyscan.__main__.Terminal") as MockTerminal:
            mock_term = MockTerminal.return_value
            tc = MagicMock()
            tc.supported = True
            tc.capabilities = {"TN": "myterm"}
            tc.make_jinxed_capabilities.return_value = {
                "str_caps": {"clear": "\x1b[H"},
                "num_caps": {},
                "bool_caps": set(),
            }
            mock_term.get_xtgettcap.return_value = tc

            with patch("ttyscan.__main__.ensure_terminfo") as mock_ensure_ti:
                mock_ensure_ti.return_value = Path(ttyscan_path)
                env = {"TERM": "myterm", "TERMINFO": "/old/path"}
                with patch.dict(os.environ, env):
                    result = generate_exports()

            assert f"export TERMINFO={ttyscan_path}" in result

    def test_force_exports(self):
        """Force flag exports even when values unchanged."""
        with patch("ttyscan.__main__.Terminal") as MockTerminal:
            mock_term = MockTerminal.return_value
            tc = MagicMock()
            tc.supported = True
            tc.capabilities = {"RGB": "8/8/8", "TN": "xterm"}
            tc.make_jinxed_capabilities.return_value = {
                "str_caps": {"clear": "\x1b[H"},
                "num_caps": {},
                "bool_caps": set(),
            }
            mock_term.get_xtgettcap.return_value = tc

            with patch("ttyscan.__main__.ensure_terminfo") as mock_ensure_ti:
                mock_ensure_ti.return_value = Path("/some/terminfo")
                env = {"COLORTERM": "truecolor", "TERM": "xterm",
                       "TERMINFO": "/some/terminfo"}
                with patch.dict(os.environ, env):
                    result = generate_exports(force=True)

            assert "export COLORTERM=truecolor" in result
            assert "export TERM=xterm" in result
            assert "export TERMINFO=/some/terminfo" in result

    def test_verbose_stderr(self, capsys):
        """Verbose flag writes to stderr."""
        with patch("ttyscan.__main__.Terminal") as MockTerminal:
            mock_term = MockTerminal.return_value
            mock_term.get_xtgettcap.return_value = None
            generate_exports(verbose=True)

        captured = capsys.readouterr()
        assert "XTGETTCAP not supported" in captured.err

    def test_verbose_full_flow(self, capsys, tmp_path):
        """Verbose covers all diagnostic branches."""
        terminfo_dir = tmp_path / ".terminfo"

        with patch("ttyscan.__main__.Terminal") as MockTerminal:
            mock_term = MockTerminal.return_value
            tc = MagicMock()
            tc.supported = True
            tc.capabilities = {"RGB": "8/8/8", "TN": "myterm"}
            tc.make_jinxed_capabilities.return_value = {
                "str_caps": {"clear": "\x1b[H\x1b[2J"},
                "num_caps": {"colors": 256},
                "bool_caps": {"am"},
            }
            mock_term.get_xtgettcap.return_value = tc

            with patch("ttyscan.__main__.ensure_terminfo") as mock_ensure_ti:
                mock_ensure_ti.return_value = terminfo_dir
                env = {"TERM": "xterm", "HOME": str(tmp_path)}
                with patch.dict(os.environ, env, clear=True):
                    result = generate_exports(verbose=True)

        captured = capsys.readouterr()
        assert "XTGETTCAP supported" in captured.err
        assert "received" in captured.err
        assert "in" in captured.err  # "in Nms"
        assert "writing" in captured.err

    def test_verbose_terminfo_changed(self, capsys, tmp_path):
        """Verbose output shows writing path."""
        terminfo_dir = tmp_path / ".terminfo"

        with patch("ttyscan.__main__.Terminal") as MockTerminal:
            mock_term = MockTerminal.return_value
            tc = MagicMock()
            tc.supported = True
            tc.capabilities = {"TN": "myterm"}
            tc.make_jinxed_capabilities.return_value = {
                "str_caps": {"clear": "\x1b[H"},
                "num_caps": {},
                "bool_caps": set(),
            }
            mock_term.get_xtgettcap.return_value = tc

            with patch("ttyscan.__main__.ensure_terminfo") as mock_ensure_ti:
                new_path = tmp_path / "ttyscan_terminfo"
                mock_ensure_ti.return_value = new_path
                env = {"TERM": "xterm", "TERMINFO": "/old/path",
                       "HOME": str(tmp_path)}
                with patch.dict(os.environ, env):
                    generate_exports(verbose=True)

        captured = capsys.readouterr()
        assert "writing" in captured.err

    def test_verbose_terminfo_force_reexport(self, capsys, tmp_path):
        """Verbose+force output shows writing path."""
        ttyscan_path = "/home/user/.config/ttyscan/terminfo"
        with patch("ttyscan.__main__.Terminal") as MockTerminal:
            mock_term = MockTerminal.return_value
            tc = MagicMock()
            tc.supported = True
            tc.capabilities = {"TN": "myterm"}
            tc.make_jinxed_capabilities.return_value = {
                "str_caps": {"clear": "\x1b[H"},
                "num_caps": {},
                "bool_caps": set(),
            }
            mock_term.get_xtgettcap.return_value = tc

            with patch("ttyscan.__main__.ensure_terminfo") as mock_ensure_ti:
                mock_ensure_ti.return_value = Path(ttyscan_path)
                env = {"TERM": "xterm", "TERMINFO": ttyscan_path,
                       "HOME": str(tmp_path)}
                with patch.dict(os.environ, env):
                    generate_exports(verbose=True, force=True)

        captured = capsys.readouterr()
        assert "writing" in captured.err


class TestDetectTerminalSize:
    """Tests for _detect_terminal_size."""

    @staticmethod
    def _make_cpr_keystroke(y, x):
        """Create a mock Keystroke with CPR_RESPONSE name and cpr_yx."""
        ks = MagicMock()
        ks.name = 'CPR_RESPONSE'
        ks.cpr_yx = (y, x)
        return ks

    @staticmethod
    def _make_preferred_size_cache(rows, cols):
        """Create a mock WINSZ for _preferred_size_cache."""
        cache = MagicMock()
        cache.ws_row = rows
        cache.ws_col = cols
        return cache

    def test_inband_preferred_over_cpr(self):
        """In-band resize result is preferred when available."""
        term = MagicMock()
        term._preferred_size_cache = self._make_preferred_size_cache(30, 100)
        term.move_yx.return_value = "\x1b[999;999H"
        term.u7 = None
        cpr1 = self._make_cpr_keystroke(5, 10)
        cpr2 = self._make_cpr_keystroke(23, 79)
        term.inkey.side_effect = [cpr1, cpr2, None]

        result = _detect_terminal_size(term)
        assert result == (30, 100, 'inband')

    def test_dual_cpr_succeeds(self):
        """Second CPR response gives window dimensions."""
        term = MagicMock()
        term._preferred_size_cache = None
        term.move_yx.return_value = "\x1b[999;999H"
        term.u7 = None
        cpr1 = self._make_cpr_keystroke(5, 10)
        cpr2 = self._make_cpr_keystroke(23, 79)
        term.inkey.side_effect = [cpr1, cpr2, None]

        result = _detect_terminal_size(term)
        assert result == (24, 80, 'cpr')

    def test_cursor_restored_from_first_cpr(self):
        """First CPR response used to restore cursor position."""
        term = MagicMock()
        term._preferred_size_cache = self._make_preferred_size_cache(30, 100)
        term.move_yx.return_value = "\x1b[move"
        term.u7 = None
        cpr1 = self._make_cpr_keystroke(5, 10)
        cpr2 = self._make_cpr_keystroke(23, 79)
        term.inkey.side_effect = [cpr1, cpr2, None]

        _detect_terminal_size(term)
        term.move_yx.assert_any_call(5, 10)

    def test_inkey_returns_none_breaks_loop(self):
        """Loop breaks when inkey returns empty keystroke."""
        term = MagicMock()
        term._preferred_size_cache = None
        term.move_yx.return_value = "\x1b[999;999H"
        term.u7 = None
        term.inkey.return_value = None  # never returns CPR

        result = _detect_terminal_size(term)
        # Falls through to fallback get_location()
        assert result is None  # get_location not mocked, returns (-1,-1) which means None

    def test_inkey_raises_during_read(self):
        """Exception during inkey breaks loop gracefully."""
        term = MagicMock()
        term._preferred_size_cache = self._make_preferred_size_cache(30, 100)
        term.move_yx.return_value = "\x1b[999;999H"
        term.u7 = None
        term.inkey.side_effect = RuntimeError("inkey failed")

        result = _detect_terminal_size(term)
        assert result == (30, 100, 'inband')

    def test_only_one_cpr_received(self):
        """Only one CPR arrives, use fallback get_location()."""
        term = MagicMock()
        term._preferred_size_cache = None
        term.move_yx.return_value = "\x1b[999;999H"
        term.u7 = None
        cpr1 = self._make_cpr_keystroke(5, 10)
        term.inkey.side_effect = [cpr1, None]  # only one CPR
        term.get_location.return_value = (24, 79)

        result = _detect_terminal_size(term)
        assert result == (25, 80, 'fallback_cpr')

    def test_dual_cpr_exception_falls_back(self):
        """Exception in dual CPR falls back to get_location()."""
        term = MagicMock()
        term.notify_on_resize.side_effect = RuntimeError("oops")
        term.move_yx.return_value = "\x1b[999;999H"
        term.get_location.return_value = (24, 79)

        result = _detect_terminal_size(term)
        assert result == (25, 80, 'fallback_cpr')

    def test_cpr_fallback_succeeds(self):
        """Fallback single CPR via get_location() works."""
        term = MagicMock()
        term.notify_on_resize.side_effect = RuntimeError("oops")
        term.move_yx.return_value = "\x1b[999;999H"
        term.get_location.return_value = (24, 79)

        result = _detect_terminal_size(term)
        assert result == (25, 80, 'fallback_cpr')

    def test_cpr_fallback_invalid_location(self):
        """Fallback CPR returns (-1, -1), size detection fails."""
        term = MagicMock()
        term.notify_on_resize.side_effect = RuntimeError("oops")
        term.move_yx.return_value = "\x1b[999;999H"
        term.get_location.return_value = (-1, -1)

        result = _detect_terminal_size(term)
        assert result is None

    def test_cpr_fallback_exception_returns_none(self):
        """Fallback CPR raises, size detection fails."""
        term = MagicMock()
        term.notify_on_resize.side_effect = RuntimeError("oops")
        term.move_yx.side_effect = RuntimeError("oops")

        result = _detect_terminal_size(term)
        assert result is None

    def test_fallback_get_location_exception_returns_none(self):
        """Fallback get_location raises, size detection fails."""
        term = MagicMock()
        term.notify_on_resize.side_effect = RuntimeError("oops")
        term.move_yx.return_value = "\x1b[999;999H"
        term.get_location.side_effect = RuntimeError("get_location failed")

        result = _detect_terminal_size(term)
        assert result is None

    def test_verbose_dual_cpr(self, capsys):
        """Verbose output for dual CPR path."""
        term = MagicMock()
        term._preferred_size_cache = None
        term.move_yx.return_value = "\x1b[999;999H"
        term.u7 = None
        cpr1 = self._make_cpr_keystroke(5, 10)
        cpr2 = self._make_cpr_keystroke(23, 79)
        term.inkey.side_effect = [cpr1, cpr2, None]

        result = _detect_terminal_size(term, verbose=True)
        captured = capsys.readouterr()
        assert result == (24, 80, 'cpr')
        assert "size via dual CPR" in captured.err

    def test_verbose_fallback(self, capsys):
        """Verbose output for fallback path."""
        term = MagicMock()
        term.notify_on_resize.side_effect = RuntimeError("oops")
        term.move_yx.return_value = "\x1b[999;999H"
        term.get_location.return_value = (-1, -1)

        _detect_terminal_size(term, verbose=True)
        captured = capsys.readouterr()
        assert "CPR size detection" in captured.err
        assert "size detection failed" in captured.err


class TestNormalizeTerminalName:
    """Tests for _normalize_terminal_name."""

    def test_wezterm_downcased(self):
        assert _normalize_terminal_name("WezTerm") == "wezterm"

    def test_other_unchanged(self):
        assert _normalize_terminal_name("xterm-kitty") == "xterm-kitty"

    def test_foot_unchanged(self):
        assert _normalize_terminal_name("foot") == "foot"


class TestCheckLinesColumns:
    """Tests for _check_lines_columns."""

    @staticmethod
    def _make_term(rows, cols):
        """Create a mock Terminal with given height/width."""
        term = MagicMock()
        term.height = rows
        term.width = cols
        return term

    def test_exports_when_different_from_term(self):
        """Export when detected size differs from terminal dimensions."""
        term = self._make_term(24, 80)
        with patch.dict(os.environ, {}, clear=True):
            result = _check_lines_columns(30, 100, term)
        assert result == ["export LINES=30", "export COLUMNS=100"]

    def test_skips_when_matches_term_and_env_unset(self):
        """Skip when detected size matches terminal and env is unset."""
        term = self._make_term(30, 100)
        with patch.dict(os.environ, {}, clear=True):
            result = _check_lines_columns(30, 100, term)
        assert result is None

    def test_skips_when_matches_env(self):
        """Skip when detected size matches env (even if different from term)."""
        term = self._make_term(24, 80)
        with patch.dict(os.environ, {"LINES": "30", "COLUMNS": "100"}):
            result = _check_lines_columns(30, 100, term)
        assert result is None

    def test_skips_when_matches_term_and_env(self):
        """Skip when detected size matches both terminal and env."""
        term = self._make_term(30, 100)
        with patch.dict(os.environ, {"LINES": "30", "COLUMNS": "100"}):
            result = _check_lines_columns(30, 100, term)
        assert result is None

    def test_exports_when_env_wrong_and_term_matches(self):
        """Export when env is wrong even if term matches (env needs fixing)."""
        term = self._make_term(30, 100)
        with patch.dict(os.environ, {"LINES": "24", "COLUMNS": "80"}):
            result = _check_lines_columns(30, 100, term)
        assert result == ["export LINES=30", "export COLUMNS=100"]

    def test_force_exports_always(self):
        """Force exports even when everything matches."""
        term = self._make_term(30, 100)
        with patch.dict(os.environ, {"LINES": "30", "COLUMNS": "100"}):
            result = _check_lines_columns(30, 100, term, force=True)
        assert result == ["export LINES=30", "export COLUMNS=100"]

    def test_partial_difference(self):
        """Export only the mismatched value."""
        term = self._make_term(30, 100)
        with patch.dict(os.environ, {"LINES": "30", "COLUMNS": "99"}):
            result = _check_lines_columns(30, 100, term)
        assert result == ["export COLUMNS=100"]

    def test_empty_env_term_differs(self):
        """Export when env is empty and detected differs from term."""
        term = self._make_term(24, 80)
        with patch.dict(os.environ, {}, clear=True):
            result = _check_lines_columns(30, 100, term)
        assert result == ["export LINES=30", "export COLUMNS=100"]


class TestSizeIntegration:
    """Integration: size detection produces LINES/COLUMNS in export output."""

    def test_size_in_exports(self):
        with patch("ttyscan.__main__.Terminal") as MockTerminal:
            mock_term = MockTerminal.return_value
            fast = MagicMock()
            fast.supported = True
            fast.capabilities = {"TN": "myterm", "RGB": "8/8/8"}
            mock_term.get_xtgettcap.return_value = fast

            with patch("ttyscan.__main__.has_terminfo", return_value=True):
                with patch("ttyscan.__main__._detect_terminal_size",
                           return_value=(30, 100, 'inband')):
                    with patch.dict(os.environ, {}, clear=True):
                        result = generate_exports()

            assert "export LINES=30" in result
            assert "export COLUMNS=100" in result


class TestMain:
    def test_main_prints_exports(self, capsys):
        with patch("ttyscan.__main__.generate_exports") as mock_gen:
            mock_gen.return_value = [
                "export COLORTERM=truecolor",
                "export TERM=foot",
            ]
            main(argv=[])
            captured = capsys.readouterr()
            assert captured.out == "export COLORTERM=truecolor\nexport TERM=foot\n"

    def test_main_no_exports(self, capsys):
        with patch("ttyscan.__main__.generate_exports") as mock_gen:
            mock_gen.return_value = []
            main(argv=[])
            captured = capsys.readouterr()
            assert captured.out == ""

    def test_main_verbose_flag(self, capsys):
        with patch("ttyscan.__main__.generate_exports") as mock_gen:
            mock_gen.return_value = ["export TERM=test"]
            main(argv=["-v"])
            mock_gen.assert_called_once_with(
                verbose=True, force=False, termcap=False,
            )

    def test_main_force_flag(self, capsys):
        with patch("ttyscan.__main__.generate_exports") as mock_gen:
            mock_gen.return_value = []
            main(argv=["-f"])
            mock_gen.assert_called_once_with(
                verbose=False, force=True, termcap=False,
            )

    def test_main_termcap_flag(self, capsys):
        with patch("ttyscan.__main__.generate_exports") as mock_gen:
            mock_gen.return_value = []
            main(argv=["-t"])
            mock_gen.assert_called_once_with(
                verbose=False, force=False, termcap=True,
            )
