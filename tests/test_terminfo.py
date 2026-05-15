"""Tests for ttyscan._terminfo."""

import os
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from ttyscan._terminfo import (
    _escape_terminfo_value,
    _escape_value,
    _build_terminfo_binary,
    _pack_short_le,
    _ttyscan_terminfo_dir,
    build_terminfo_source,
    compile_terminfo,
    ensure_terminfo,
    has_terminfo,
    sanitize_term_name,
    terminfo_installed,
    terminfo_path,
    validate_terminfo,
    verify_terminfo_via_curses,
    write_terminfo,
)


class TestSanitizeTermName:
    def test_plain(self):
        assert sanitize_term_name("xterm") == "xterm"

    def test_hyphen(self):
        assert sanitize_term_name("xterm-256color") == "xterm-256color"

    def test_dot(self):
        assert sanitize_term_name("iTerm2.app") == "iTerm2.app"

    def test_leading_dot(self):
        assert sanitize_term_name(".hidden") == "hidden"

    def test_special_chars(self):
        assert sanitize_term_name("bad/name") == "badname"

    def test_path_traversal(self):
        assert sanitize_term_name("../../etc/passwd") == "etcpasswd"

    def test_empty(self):
        assert sanitize_term_name("") == "unknown"

    def test_all_special(self):
        assert sanitize_term_name("../../../") == "unknown"

    def test_unicode(self):
        assert sanitize_term_name("t\u00e9rm") == "trm"


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

    def test_terminfo_space(self):
        assert _escape_value(" ", terminfo=True) == "\\s"

    def test_terminfo_colon(self):
        assert _escape_value(":", terminfo=True) == "\\:"

    def test_termcap_no_escape_space(self):
        assert _escape_value(" ") == " "

    def test_termcap_no_escape_colon(self):
        assert _escape_value(":") == ":"


class TestEscapeTerminfoValue:
    def test_plain_text(self):
        assert _escape_terminfo_value("hello") == "hello"

    def test_escape(self):
        assert _escape_terminfo_value("\x1b") == "\\E"

    def test_newline(self):
        assert _escape_terminfo_value("\n") == "\\n"

    def test_tab(self):
        assert _escape_terminfo_value("\t") == "\\t"

    def test_carriage_return(self):
        assert _escape_terminfo_value("\r") == "\\r"

    def test_backspace(self):
        assert _escape_terminfo_value("\b") == "\\b"

    def test_form_feed(self):
        assert _escape_terminfo_value("\f") == "\\f"

    def test_space(self):
        assert _escape_terminfo_value(" ") == "\\s"

    def test_backslash(self):
        assert _escape_terminfo_value("\\") == "\\\\"

    def test_caret(self):
        assert _escape_terminfo_value("^") == "\\^"

    def test_colon(self):
        assert _escape_terminfo_value(":") == "\\:"

    def test_control_char(self):
        assert _escape_terminfo_value("\x01") == "^A"

    def test_delete(self):
        assert _escape_terminfo_value("\x7f") == "^?"

    def test_mixed(self):
        result = _escape_terminfo_value("\x1b[1mhello\x1b[0m")
        assert result == "\\E[1mhello\\E[0m"

    def test_high_unicode(self):
        assert _escape_terminfo_value("\u00e9") == "\u00e9"


class TestHasTerminfo:
    def test_success(self, monkeypatch):
        mock_curses = MagicMock()
        monkeypatch.setitem(
            __import__("sys").modules, "curses", mock_curses,
        )
        result = has_terminfo("xterm")
        assert result is True
        mock_curses.setupterm.assert_called_once_with("xterm")

    def test_failure(self, monkeypatch):
        mock_curses = MagicMock()
        mock_curses.setupterm.side_effect = Exception("no such terminal")
        monkeypatch.setitem(
            __import__("sys").modules, "curses", mock_curses,
        )
        result = has_terminfo("nonexistent")
        assert result is False

    def test_import_error(self):
        with patch("builtins.__import__") as mock_import:
            def side_effect(name, *args, **kwargs):
                if name == "curses":
                    raise ImportError
                return __import__(name, *args, **kwargs)

            mock_import.side_effect = side_effect
            with patch.dict("sys.modules", {"curses": None}):
                result = has_terminfo("xterm")
                assert result is False


class TestBuildTerminfoSource:
    def test_all_cap_types(self):
        source = build_terminfo_source(
            "myterm",
            str_caps={"clear": "\x1b[H\x1b[2J", "cup": "\x1b[%i%p1%d;%p2%dH"},
            num_caps={"colors": 256, "cols": 80},
            bool_caps={"am", "km"},
        )
        assert "myterm|XTGETTCAP-discovered terminal," in source
        assert "\tam," in source
        assert "\tkm," in source
        assert "\tcolors#256," in source
        assert "\tcols#80," in source
        assert "\tclear=\\E[H\\E[2J," in source

    def test_only_bool_caps(self):
        source = build_terminfo_source("simple", {}, {}, {"am"})
        assert "\tam," in source

    def test_only_num_caps(self):
        source = build_terminfo_source("simple", {}, {"colors": 8}, set())
        assert "\tcolors#8," in source

    def test_only_str_caps(self):
        source = build_terminfo_source("simple", {"bel": "\x07"}, {}, set())
        assert "\tbel=^G," in source

    def test_empty(self):
        source = build_terminfo_source("empty", {}, {}, set())
        assert source == "empty|XTGETTCAP-discovered terminal,"


class TestCompileTerminfo:
    def test_tic_not_found(self):
        with patch("ttyscan._terminfo.shutil.which", return_value=None):
            result = compile_terminfo("source", Path("/tmp"))
            assert result is False

    def test_tic_success(self, tmp_path):
        dest = tmp_path / "terminfo"
        dest.mkdir()
        with patch("ttyscan._terminfo.shutil.which", return_value="/usr/bin/tic"):
            with patch("ttyscan._terminfo.subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0)
                result = compile_terminfo("xterm|xterm,", dest)
                assert result is True

    def test_tic_failure(self, tmp_path):
        dest = tmp_path / "terminfo"
        dest.mkdir()
        with patch("ttyscan._terminfo.shutil.which", return_value="/usr/bin/tic"):
            with patch("ttyscan._terminfo.subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=1)
                result = compile_terminfo("bad source", dest)
                assert result is False

    def test_tic_subprocess_error(self, tmp_path):
        dest = tmp_path / "terminfo"
        dest.mkdir()
        with patch("ttyscan._terminfo.shutil.which", return_value="/usr/bin/tic"):
            with patch("ttyscan._terminfo.subprocess.run") as mock_run:
                mock_run.side_effect = subprocess.SubprocessError()
                result = compile_terminfo("xterm|xterm,", dest)
                assert result is False

    def test_tic_os_error(self, tmp_path):
        dest = tmp_path / "terminfo"
        dest.mkdir()
        with patch("ttyscan._terminfo.shutil.which", return_value="/usr/bin/tic"):
            with patch("ttyscan._terminfo.subprocess.run") as mock_run:
                mock_run.side_effect = OSError()
                result = compile_terminfo("xterm|xterm,", dest)
                assert result is False

    def test_source_file_cleanup_on_error(self, tmp_path):
        dest = tmp_path / "terminfo"
        dest.mkdir()
        with patch("ttyscan._terminfo.shutil.which", return_value="/usr/bin/tic"):
            with patch("ttyscan._terminfo.subprocess.run",
                       side_effect=subprocess.SubprocessError()):
                result = compile_terminfo("xterm|xterm,", dest)
                assert result is False

    def test_unlink_os_error(self, tmp_path):
        dest = tmp_path / "terminfo"
        dest.mkdir()
        with patch("ttyscan._terminfo.shutil.which", return_value="/usr/bin/tic"):
            with patch("ttyscan._terminfo.subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0)
                with patch("ttyscan._terminfo.os.unlink",
                           side_effect=OSError()):
                    result = compile_terminfo("xterm|xterm,", dest)
                    assert result is True


class TestPackShortLe:
    def test_positive(self):
        buf = bytearray(2)
        _pack_short_le(buf, 0, 42)
        assert buf[0] == 42
        assert buf[1] == 0

    def test_negative(self):
        buf = bytearray(2)
        _pack_short_le(buf, 0, -1)
        assert buf[0] == 0xFF
        assert buf[1] == 0xFF

    def test_large(self):
        buf = bytearray(2)
        _pack_short_le(buf, 0, 256)
        assert buf[0] == 0
        assert buf[1] == 1


class TestBuildTerminfoBinary:
    def test_simple(self):
        data = _build_terminfo_binary(
            "test",
            str_caps={"clear": "\x1b[H\x1b[2J"},
            num_caps={"colors": 256},
            bool_caps={"am"},
        )
        assert data is not None
        assert len(data) > 12

    def test_32bit_numeric(self):
        """Foot reports pairs=65536, requires 32-bit format."""
        data = _build_terminfo_binary(
            "test32",
            str_caps={"clear": "\x1b[H"},
            num_caps={"colors": 256, "pairs": 65536},
            bool_caps=set(),
        )
        assert data is not None
        # Magic for 32-bit is 0o1036 = 0x21E -> LE: 0x1E, 0x02
        assert data[0] == 0x1E
        assert data[1] == 0x02

    def test_empty_caps(self):
        data = _build_terminfo_binary("test", {}, {}, set())
        assert data is not None
        assert len(data) >= 12

    def test_unknown_cap_skipped(self):
        data = _build_terminfo_binary(
            "test",
            str_caps={"nonexistent_cap": "value"},
            num_caps={"fake_num": 42},
            bool_caps={"fake_bool"},
        )
        assert data is not None

    def test_header_magic(self):
        data = _build_terminfo_binary("test", {}, {}, set())
        assert data is not None
        assert data[0] == 0x1A
        assert data[1] == 0x01

    def test_multiple_caps(self):
        data = _build_terminfo_binary(
            "myt",
            str_caps={
                "clear": "\x1b[H", "bel": "\x07",
                "cup": "\x1b[%i%p1%d;%p2%dH",
            },
            num_caps={"colors": 256, "cols": 80, "lines": 24},
            bool_caps={"am", "km", "xenl"},
        )
        assert data is not None
        assert len(data) > 12


class TestWriteTerminfo:
    def test_writes_file(self, tmp_path):
        dest = tmp_path / "terminfo"
        result = write_terminfo(
            "myt", {"clear": "\x1b[H"}, {"colors": 8}, {"am"}, dest,
        )
        assert result is True
        assert terminfo_installed("myt", dest)
        assert terminfo_path("myt", dest).exists()

    def test_sanitizes_name(self, tmp_path):
        dest = tmp_path / "terminfo"
        result = write_terminfo(
            "bad/name", {"clear": "\x1b[H"}, {}, set(), dest,
        )
        assert result is True
        assert terminfo_installed("badname", dest)

    def test_no_str_caps(self, tmp_path):
        dest = tmp_path / "terminfo"
        result = write_terminfo("t", {}, {}, set(), dest)
        assert result is True
        assert terminfo_installed("t", dest)


class TestValidateTerminfo:
    def test_infocmp_not_found(self, tmp_path):
        dest = tmp_path / "ti"
        dest.mkdir()
        with patch("ttyscan._terminfo.shutil.which", return_value=None):
            err = validate_terminfo("xterm", dest)
            assert err is None

    def test_file_not_found(self, tmp_path):
        dest = tmp_path / "ti"
        dest.mkdir()
        with patch("ttyscan._terminfo.shutil.which", return_value="/usr/bin/infocmp"):
            err = validate_terminfo("xterm", dest)
            assert err is not None
            assert "not found" in err

    def test_infocmp_success(self, tmp_path):
        dest = tmp_path / "ti"
        dest.mkdir()
        file_path = dest / "x" / "xterm"
        file_path.parent.mkdir(parents=True)
        file_path.write_bytes(b"dummy")
        with patch("ttyscan._terminfo.shutil.which", return_value="/usr/bin/infocmp"):
            with patch("ttyscan._terminfo.subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0, stdout="xterm|...")
                err = validate_terminfo("xterm", dest)
                assert err is None

    def test_infocmp_failure(self, tmp_path):
        dest = tmp_path / "ti"
        dest.mkdir()
        file_path = dest / "x" / "xterm"
        file_path.parent.mkdir(parents=True)
        file_path.write_bytes(b"dummy")
        with patch("ttyscan._terminfo.shutil.which", return_value="/usr/bin/infocmp"):
            with patch("ttyscan._terminfo.subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(
                    returncode=1, stdout="", stderr="bad terminfo",
                )
                err = validate_terminfo("xterm", dest)
                assert err == "bad terminfo"

    def test_infocmp_empty_output(self, tmp_path):
        dest = tmp_path / "ti"
        dest.mkdir()
        file_path = dest / "x" / "xterm"
        file_path.parent.mkdir(parents=True)
        file_path.write_bytes(b"dummy")
        with patch("ttyscan._terminfo.shutil.which", return_value="/usr/bin/infocmp"):
            with patch("ttyscan._terminfo.subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0, stdout="")
                err = validate_terminfo("xterm", dest)
                assert err == "infocmp produced empty output"

    def test_infocmp_subprocess_error(self, tmp_path):
        dest = tmp_path / "ti"
        dest.mkdir()
        file_path = dest / "x" / "xterm"
        file_path.parent.mkdir(parents=True)
        file_path.write_bytes(b"dummy")
        with patch("ttyscan._terminfo.shutil.which", return_value="/usr/bin/infocmp"):
            with patch("ttyscan._terminfo.subprocess.run",
                       side_effect=subprocess.SubprocessError("fail")):
                err = validate_terminfo("xterm", dest)
                assert err == "fail"


class TestVerifyTerminfoViaCurses:
    def test_success(self):
        with patch("ttyscan._terminfo.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            err = verify_terminfo_via_curses("xterm", Path("/tmp/ti"))
            assert err is None

    def test_failure(self):
        with patch("ttyscan._terminfo.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1, stderr="no such terminal",
            )
            err = verify_terminfo_via_curses("xterm", Path("/tmp/ti"))
            assert err == "no such terminal"

    def test_subprocess_error(self):
        with patch("ttyscan._terminfo.subprocess.run",
                   side_effect=subprocess.SubprocessError("fail")):
            err = verify_terminfo_via_curses("xterm", Path("/tmp/ti"))
            assert err == "fail"


class TestTerminfoPath:
    def test_path(self):
        p = terminfo_path("myterm", Path("/home/user/.terminfo"))
        assert p == Path("/home/user/.terminfo/m/myterm")

    def test_single_char_term(self):
        p = terminfo_path("x", Path("/tmp/ti"))
        assert p == Path("/tmp/ti/x/x")


class TestTerminfoInstalled:
    def test_exists(self, tmp_path):
        base = tmp_path / "ti"
        file_path = base / "m" / "myterm"
        file_path.parent.mkdir(parents=True)
        file_path.write_text("")
        assert terminfo_installed("myterm", base) is True

    def test_not_exists(self, tmp_path):
        base = tmp_path / "ti"
        assert terminfo_installed("myterm", base) is False


class TestEnsureTerminfo:
    def test_ttyscan_terminfo_dir_default(self, monkeypatch):
        monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
        monkeypatch.setattr(os.path, "expanduser", lambda p: "/home/testuser")
        result = _ttyscan_terminfo_dir()
        assert result == Path("/home/testuser/.config/ttyscan/terminfo")

    def test_ttyscan_terminfo_dir_xdg_set(self, monkeypatch):
        monkeypatch.setenv("XDG_CONFIG_HOME", "/custom/config")
        result = _ttyscan_terminfo_dir()
        assert result == Path("/custom/config/ttyscan/terminfo")

    def test_system_terminfo_available(self):
        with patch("ttyscan._terminfo.has_terminfo", return_value=True):
            result = ensure_terminfo("xterm", {}, {}, set())
            assert result is None

    def test_force_bypasses_system_check(self, tmp_path):
        dest = tmp_path / "ttyscan_terminfo"
        dest.mkdir()
        with patch("ttyscan._terminfo.has_terminfo", return_value=True):
            with patch("ttyscan._terminfo._ttyscan_terminfo_dir",
                       return_value=dest):
                result = ensure_terminfo(
                    "myt", {"clear": "\x1b[H"}, {"colors": 256}, {"am"},
                    force=True,
                )
        assert result == dest
        assert terminfo_installed("myt", dest)

    def test_existing_terminfo_env_and_installed(self, tmp_path, monkeypatch):
        dest = tmp_path / "ttyscan_terminfo"
        dest.mkdir()
        file_path = dest / "m" / "myterm"
        file_path.parent.mkdir(parents=True)
        file_path.write_text("")

        monkeypatch.setenv("TERMINFO", "/old/path")
        with patch("ttyscan._terminfo.has_terminfo", return_value=False):
            with patch("ttyscan._terminfo._ttyscan_terminfo_dir",
                       return_value=dest):
                result = ensure_terminfo("myterm", {}, {}, set())
            assert result == dest

    def test_pure_python_write_success(self, tmp_path):
        dest = tmp_path / "ttyscan_terminfo"

        with patch("ttyscan._terminfo.has_terminfo", return_value=False):
            with patch("ttyscan._terminfo._ttyscan_terminfo_dir",
                       return_value=dest):
                with patch.dict(os.environ, {}, clear=True):
                    result = ensure_terminfo(
                        "myt",
                        {"clear": "\x1b[H"},
                        {"colors": 256},
                        {"am"},
                    )
        assert result == dest
        path = terminfo_path("myt", dest)
        assert path.exists()

    def test_pure_python_fails_fallback_tic(self, tmp_path):
        dest = tmp_path / "ttyscan_terminfo"

        with patch("ttyscan._terminfo.has_terminfo", return_value=False):
            with patch("ttyscan._terminfo._ttyscan_terminfo_dir",
                       return_value=dest):
                with patch("ttyscan._terminfo.write_terminfo",
                           return_value=False):
                    with patch("ttyscan._terminfo.compile_terminfo",
                               return_value=True):
                        with patch.dict(os.environ, {}, clear=True):
                            result = ensure_terminfo("myt", {}, {}, set())
        assert result == dest

    def test_both_fail(self, tmp_path):
        dest = tmp_path / "ttyscan_terminfo"

        with patch("ttyscan._terminfo.has_terminfo", return_value=False):
            with patch("ttyscan._terminfo._ttyscan_terminfo_dir",
                       return_value=dest):
                with patch("ttyscan._terminfo.write_terminfo",
                           return_value=False):
                    with patch("ttyscan._terminfo.compile_terminfo",
                               return_value=False):
                        with patch.dict(os.environ, {}, clear=True):
                            result = ensure_terminfo("myt", {}, {}, set())
        assert result is None

    def test_existing_terminfo_env_not_installed(self, tmp_path, monkeypatch):
        dest = tmp_path / "ttyscan_terminfo"
        monkeypatch.setenv("TERMINFO", "/old/path")

        with patch("ttyscan._terminfo.has_terminfo", return_value=False):
            with patch("ttyscan._terminfo._ttyscan_terminfo_dir",
                       return_value=dest):
                with patch("ttyscan._terminfo.write_terminfo",
                           return_value=True):
                    result = ensure_terminfo(
                        "myt", {"clear": "\x1b[H"}, {}, set(),
                    )
        assert result == dest

    def test_verification_warning_on_failure(self, tmp_path, capsys):
        dest = tmp_path / "ttyscan_terminfo"

        with patch("ttyscan._terminfo.has_terminfo", return_value=False):
            with patch("ttyscan._terminfo._ttyscan_terminfo_dir",
                       return_value=dest):
                with patch("ttyscan._terminfo.verify_terminfo_via_curses",
                           return_value="setupterm failed"):
                    with patch.dict(os.environ, {}, clear=True):
                        result = ensure_terminfo(
                            "myt", {"clear": "\x1b[H"}, {}, set(),
                        )
        assert result is not None
        captured = capsys.readouterr()
        assert "warning" in captured.err
        assert "setupterm failed" in captured.err
