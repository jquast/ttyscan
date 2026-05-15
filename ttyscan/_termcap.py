"""Build and export termcap entries."""

import os
from pathlib import Path
from typing import Dict, Optional, Set

from ._terminfo import _escape_value


def build_termcap_entry(
    term: str,
    str_caps: Dict[str, str],
    num_caps: Dict[str, int],
    bool_caps: Set[str],
) -> str:
    """Build a compressed termcap entry directly from classified capabilities.

    Produces a single-line, compact termcap entry without backslash
    continuations or extra whitespace.
    """
    parts = [f"{term}|XTGETTCAP-discovered terminal:"]

    for cap in sorted(bool_caps):
        tc_name = _terminfo_to_termcap_bool(cap)
        if tc_name:
            parts.append(f":{tc_name}:")

    for cap in sorted(num_caps):
        tc_name = _terminfo_to_termcap_num(cap)
        if tc_name:
            parts.append(f":{tc_name}#{num_caps[cap]}:")

    for cap in sorted(str_caps):
        tc_name = _terminfo_to_termcap_str(cap)
        if tc_name:
            value = _escape_value(str_caps[cap])
            parts.append(f":{tc_name}={value}:")

    return "".join(parts)


def _terminfo_to_termcap_bool(name: str) -> Optional[str]:
    """Map a terminfo boolean capability name to its termcap equivalent."""
    mapping = {
        "am": "am", "bce": "ut", "km": "km", "mc5i": "5i",
        "mir": "mi", "msgr": "ms", "npc": "NP", "xenl": "xn",
        "hs": "hs", "in": "in", "da": "da", "db": "db",
        "eo": "eo", "eslok": "es", "gn": "gn", "hc": "hc",
        "hz": "hz", "lpix": "YB", "ndscr": "ND", "nrrmc": "NR",
        "os": "os", "sam": "SA", "ul": "ul", "xb": "xb",
        "xn": "xn", "xt": "xt",
    }
    return mapping.get(name)


def _terminfo_to_termcap_num(name: str) -> Optional[str]:
    """Map a terminfo numeric capability name to its termcap equivalent."""
    mapping = {
        "colors": "Co", "cols": "co", "lines": "li", "it": "it",
        "pairs": "pa", "btns": "BT", "bufsz": "Ya", "lm": "lm",
        "lh": "lh", "lw": "lw", "ma": "ma", "mw": "mw",
        "ncv": "NC", "nlab": "Nl", "pb": "pb", "sg": "sg",
        "ug": "ug", "vt": "vt", "ws": "ws", "wnum": "dw",
        "wsl": "ws",
    }
    return mapping.get(name)


def _terminfo_to_termcap_str(name: str) -> Optional[str]:
    """Map a terminfo string capability name to its termcap equivalent."""
    mapping = {
        "acsc": "ac", "bel": "bl", "blink": "mb", "bold": "md",
        "cbt": "bt", "civis": "vi", "clear": "cl", "cnorm": "ve",
        "cr": "cr", "csr": "cs", "cub1": "le", "cud": "DO",
        "cud1": "do", "cuf1": "nd", "cup": "cm", "cuu1": "up",
        "cvvis": "vs", "dch1": "dC", "dim": "mh", "dl1": "dl",
        "dsl": "ds", "ech": "ec", "ed": "cd", "el": "ce",
        "el1": "cb", "flash": "vb", "fsl": "fs", "home": "ho",
        "hpa": "ch", "hts": "st", "ht": "ta", "ich1": "ic",
        "il1": "al", "ind": "sf", "invis": "mk", "iprog": "iP",
        "is1": "i1", "is2": "is", "is3": "i3", "kb2": "K2",
        "kbs": "kb", "kcbt": "kB", "kcub1": "kl", "kcud1": "kd",
        "kcuf1": "kr", "kcuu1": "ku", "kdch1": "kD", "kend": "@7",
        "kent": "@8", "kf1": "k1", "kf2": "k2", "kf3": "k3",
        "kf4": "k4", "kf5": "k5", "kf6": "k6", "kf7": "k7",
        "kf8": "k8", "kf9": "k9", "kf10": "k0", "kf11": "F1",
        "kf12": "F2", "kfnd": "kF", "khlp": "%1", "khome": "kh",
        "kich1": "kI", "kind": "kH", "knp": "kN", "kpp": "kP",
        "kprv": "kR", "kspd": "@9", "ktbc": "ka", "mc0": "ps",
        "mc4": "pf", "mc5": "po", "mc5p": "pO", "nel": "nw",
        "op": "op", "pad": "pc", "pln": "pn", "prot": "mp",
        "rep": "rp", "rev": "mr", "ri": "sr", "rmacs": "ae",
        "rmcup": "te", "rmdc": "ed", "rmir": "ei", "rmkx": "ke",
        "rmso": "se", "rmul": "ue", "rs1": "r1", "rs2": "r2",
        "rs3": "r3", "sgr": "sa", "sgr0": "me", "sitm": "ZH",
        "ritm": "ZR", "smacs": "as", "smcup": "ti", "smdc": "dm",
        "smir": "im", "smkx": "ks", "smso": "so", "smul": "us",
        "tbc": "ct", "tsl": "ts", "vpa": "cv", "wind": "wi",
        "wingo": "WS",
    }
    return mapping.get(name)


def ensure_termcap(
    term: str,
    terminfo_dir: Path,
    str_caps: Dict[str, str],
    num_caps: Dict[str, int],
    bool_caps: Set[str],
    force: bool = False,
) -> Optional[str]:
    """Build a termcap entry from XTGETTCAP capabilities.

    Returns an ``export TERMCAP=...`` string if needed, or None.  No
    files are written to disk -- termcap is an in-band environment
    variable, unlike terminfo which requires a compiled binary on disk.
    """
    entry = build_termcap_entry(term, str_caps, num_caps, bool_caps)

    if not entry:
        return None

    if not force and os.environ.get("TERMCAP") == entry:
        return None

    return f"export TERMCAP={_shell_escape(entry)}"


def _shell_escape(value: str) -> str:
    """Escape a value for use in a shell export statement.

    Uses single quotes, handling embedded single quotes by ending the
    single-quoted string, inserting an escaped quote, and resuming.
    """
    if not value:
        return "''"
    escaped = value.replace("'", "'\\''")
    return f"'{escaped}'"
