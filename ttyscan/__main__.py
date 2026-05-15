"""Entry point for ttyscan -- export terminal capabilities as shell exports."""

import argparse
import os
import sys
import time
from typing import List, Optional, Tuple

from blessed import Terminal

from ._terminfo import ensure_terminfo, has_terminfo
from ._termcap import ensure_termcap


def main(argv: Optional[List[str]] = None) -> None:
    """Run ttyscan and print export statements to stdout."""
    parser = argparse.ArgumentParser(
        prog="ttyscan",
        description="Export terminal capabilities discovered via XTGETTCAP",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Print diagnostic information to stderr",
    )
    parser.add_argument(
        "-f", "--force",
        action="store_true",
        help="Force export of all values even if unchanged",
    )
    parser.add_argument(
        "-t", "--termcap",
        action="store_true",
        help="Also export TERMCAP value",
    )
    args = parser.parse_args(argv)

    verbose = args.verbose
    force = args.force
    termcap = args.termcap

    exports = generate_exports(verbose=verbose, force=force, termcap=termcap)
    for line in exports:
        print(line)


def _verbose(msg: str, verbose: bool) -> None:
    """Print diagnostic message to stderr if verbose mode is enabled."""
    if verbose:
        print(f"ttyscan: {msg}", file=sys.stderr)


def generate_exports(
    verbose: bool = False,
    force: bool = False,
    termcap: bool = False,
) -> List[str]:
    """Generate shell export statements based on XTGETTCAP capabilities.

    Returns a list of ``export FOO=bar`` strings.
    """
    _verbose("probing terminal via XTGETTCAP ...", verbose)

    # Use stderr for the Terminal so that XTGETTCAP probing works even
    # when stdout is piped (e.g. ``ttyscan -v > debug.log``).
    term = Terminal(stream=sys.stderr)

    # Fast path: query only TN and RGB first (cached from blessed's init probe).
    # If the terminal doesn't support XTGETTCAP or has no TN, bail before the
    # full batch query.
    fast = term.get_xtgettcap(caps=["TN", "RGB"])
    if fast is None or not fast.supported:
        _verbose("XTGETTCAP not supported by this terminal", verbose)
        return []

    if not fast.capabilities.get("TN"):
        _verbose("no TN (terminal name) capability, cannot export further", verbose)
        return []

    tn = fast.capabilities["TN"]
    tn = _normalize_terminal_name(tn)
    _verbose(f"terminal name: {tn}", verbose)

    # COLORTERM and TERM can be determined from the fast-path probe alone.
    exports: List[str] = []

    if colorterm_export := _check_colorterm(fast, force):
        _verbose("exporting COLORTERM=truecolor", verbose)
        exports.append(colorterm_export)

    if term_export := _check_term(fast, force):
        _verbose(f"exporting TERM={tn}", verbose)
        exports.append(term_export)

    if size := _detect_terminal_size(term, verbose):
        rows, cols = size
        if lines_cols_export := _check_lines_columns(rows, cols, force):
            _verbose(f"exporting LINES={rows} COLUMNS={cols}", verbose)
            exports.extend(lines_cols_export)

    # If the system already has a terminfo entry for this terminal and
    # neither force nor termcap was requested, skip the full capability
    # query -- nothing more to export.
    if not force and not termcap and has_terminfo(tn):
        _verbose("terminfo already available in system database", verbose)
        return exports

    # Full batch query for terminfo / termcap generation.
    _verbose("requesting full capability set ...", verbose)
    tc = term.get_xtgettcap()
    if tc is None:
        _verbose("full XTGETTCAP query returned None", verbose)
        return []

    _verbose("XTGETTCAP supported", verbose)
    if verbose:
        n_caps = len(tc.capabilities)
        _verbose(f"received {n_caps} capabilities", verbose)

    jcaps = tc.make_jinxed_capabilities()
    str_caps = jcaps["str_caps"]
    num_caps = jcaps["num_caps"]
    bool_caps = jcaps["bool_caps"]

    if verbose:
        _verbose(
            f"classified: {len(bool_caps)} bool, {len(num_caps)} num, "
            f"{len(str_caps)} str caps",
            verbose,
        )

    if not _has_meaningful_caps(str_caps, num_caps, bool_caps):
        _verbose(
            "only bare-minimum capabilities (TN/colors/RGB), "
            "skipping TERMINFO/TERMCAP export",
            verbose,
        )
        return exports

    terminfo_dir = ensure_terminfo(
        tn, str_caps, num_caps, bool_caps, force=force,
    )
    if terminfo_dir is not None:
        terminfo_value = str(terminfo_dir)
        current_terminfo = os.environ.get("TERMINFO")
        if force or current_terminfo != terminfo_value:
            if current_terminfo and current_terminfo != terminfo_value:
                _verbose(
                    f"TERMINFO changed: was {current_terminfo}, "
                    f"now exporting {terminfo_value}",
                    verbose,
                )
            elif current_terminfo:
                _verbose(
                    f"TERMINFO re-exporting (force): {terminfo_value}",
                    verbose,
                )
            else:
                _verbose(f"exporting TERMINFO={terminfo_value}", verbose)
            exports.append(f"export TERMINFO={terminfo_value}")
    else:
        _verbose("terminfo already available in system database", verbose)

    if termcap:
        if termcap_export := ensure_termcap(
            tn, terminfo_dir, str_caps, num_caps, bool_caps,
            force=force,
        ):
            _verbose("exporting TERMCAP", verbose)
            exports.append(termcap_export)

    return exports


def _has_meaningful_caps(
    str_caps: dict,
    num_caps: dict,
    bool_caps: set,
) -> bool:
    """Return True if the classified caps contain anything beyond bare minimum.

    Bare minimum means: only TN, colors/Co, and RGB (excluded by caller).

    Keyboard-definition string caps (those starting with ``k``, e.g.
    ``kf1``, ``khome``, ``kbs``) are not screen/output capabilities.
    A terminfo entry composed solely of keyboard caps is too sparse to
    drive terminal applications and should not clobber a real system
    terminfo entry.
    """
    # Screen/output string caps (non-keyboard)
    screen_str_caps = {k for k in str_caps if not k.startswith('k')}
    if screen_str_caps:
        return True
    if bool_caps:
        return True
    meaningful_nums = {k for k in num_caps if k not in ('colors', 'Co')}
    if meaningful_nums:
        return True
    return False


def _normalize_terminal_name(raw: str) -> str:
    """Normalize a terminal name reported by XTGETTCAP TN capability.

    Some terminals report a TN value that does not match their terminfo
    entry name.  The terminfo database uses lowercase by convention.

    WezTerm: reports ``WezTerm`` but ncurses calls it ``wezterm``.
    This is an upstream bug to be submitted.
    """
    # Known mismatches
    if raw == "WezTerm":
        return "wezterm"
    return raw


def _check_colorterm(tc, force: bool = False) -> Optional[str]:
    """Return ``export COLORTERM=truecolor`` if 24-bit color detected and differs."""
    rgb = tc.capabilities.get("RGB", "")
    try:
        if rgb and int(rgb.split("/", 1)[0]) == 8:
            if force or os.environ.get("COLORTERM") != "truecolor":
                return "export COLORTERM=truecolor"
    except ValueError:
        pass
    return None


def _check_term(tc, force: bool = False) -> Optional[str]:
    """Return ``export TERM=...`` if TN differs from current TERM."""
    tn = tc.capabilities.get("TN")
    if tn:
        tn = _normalize_terminal_name(tn)
        if force or tn != os.environ.get("TERM"):
            return f"export TERM={tn}"
    return None


def _detect_terminal_size(
    term: Terminal, verbose: bool = False,
) -> Optional[Tuple[int, int]]:
    """Detect terminal dimensions using dual CPR with in-band resize preference.

    Sends two CPR queries back-to-back with a ``move_yx(999, 999)`` in
    between, then reads both ``CPR_RESPONSE`` keystrokes via :meth:`inkey`.
    The first CPR captures the original cursor position (used to restore
    the cursor afterwards), the second captures the clamped position which
    yields the window dimensions.  In-band resize (DEC mode 2048) events
    are preferred over CPR when received within the same read window.
    """
    def _dual_cpr_read(term, verbose):
        """Send dual CPR and read responses with inkey()."""
        cpr1 = cpr2 = None
        deadline = time.monotonic() + 0.25  # rapid timeout for in-flight responses

        # Send first CPR (captures original cursor position).
        term.stream.write(term.u7 or '\x1b[6n')
        # Move cursor to far corner so second CPR captures window dimensions.
        term.stream.write(term.move_yx(999, 999))
        # Send second CPR asynchronously.
        term.stream.write(term.u7 or '\x1b[6n')
        term.stream.flush()

        # Read both CPR_RESPONSE keystrokes (and any in-band resize events).
<<<<<<< HEAD
        while cpr2 is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                ks = term.inkey(timeout=remaining, capture_cpr=True)
            except Exception:
                break
            if not ks:
                break
            if ks.name == 'CPR_RESPONSE':
                yx = ks.cpr_yx
                if cpr1 is None:
                    cpr1 = yx
                else:
                    cpr2 = yx
            # In-band resize events are automatically cached into
            # term._preferred_size_cache by inkey().
=======
        # inkey() requires cbreak mode to read raw escape sequences.
        with term.cbreak():
            while cpr2 is None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                try:
                    ks = term.inkey(timeout=remaining, capture_cpr=True)
                except Exception:
                    break
                if not ks:
                    break
                if ks.name == 'CPR_RESPONSE':
                    yx = ks.cpr_yx
                    if cpr1 is None:
                        cpr1 = yx
                    else:
                        cpr2 = yx
                # In-band resize events are automatically cached into
                # term._preferred_size_cache by inkey().
>>>>>>> 7795755 (Initial commit, new project)

        # Restore cursor position from first CPR response.
        if cpr1 is not None and cpr1 != (-1, -1):
            try:
                term.stream.write(term.move_yx(*cpr1))
                term.stream.flush()
            except Exception:
                pass

        # Prefer in-band resize result (avoids cursor movement).
        if term._preferred_size_cache is not None:
            rows = term._preferred_size_cache.ws_row
            cols = term._preferred_size_cache.ws_col
            _verbose(f"size via in-band: {rows}x{cols}", verbose)
            return rows, cols

        # Use second CPR for window dimensions.
        if cpr2 is not None and cpr2 != (-1, -1):
            y, x = cpr2
            rows, cols = y + 1, x + 1
            _verbose(f"size via dual CPR: {rows}x{cols}", verbose)
            return rows, cols

        return None

    # Always enable in-band resize context (safe no-op when unsupported).
    try:
        with term.notify_on_resize():
            result = _dual_cpr_read(term, verbose)
            if result is not None:
                return result
    except Exception:
        _verbose("dual CPR failed, trying CPR only", verbose)

    # Fallback: single CPR with get_location().
    _verbose("CPR size detection", verbose)
    try:
        term.stream.write(term.move_yx(999, 999))
        term.stream.flush()
        y, x = term.get_location()
        if (y, x) != (-1, -1):
            rows, cols = y + 1, x + 1
            _verbose(f"size via CPR: {rows}x{cols}", verbose)
            return rows, cols
    except Exception:
        pass

    _verbose("size detection failed", verbose)
    return None


def _check_lines_columns(
    rows: int, cols: int, force: bool = False,
) -> Optional[List[str]]:
    """Return LINES and COLUMNS export strings if they differ from current env."""
    exports = []
    env_lines = os.environ.get("LINES")
    env_cols = os.environ.get("COLUMNS")
    if force or env_lines != str(rows):
        exports.append(f"export LINES={rows}")
    if force or env_cols != str(cols):
        exports.append(f"export COLUMNS={cols}")
    return exports or None
