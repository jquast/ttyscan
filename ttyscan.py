#!/usr/bin/env python3

import argparse
import array
import os
import re
import select
import struct
import sys
import time
from pathlib import Path

try:
    import fcntl
    import termios
    import tty
except ImportError as exc:
    sys.exit(f"ttyscan: unsupported platform (missing required module: {exc})")

__version__ = "0.0.2"


def warn(msg):
    print(f"ttyscan: {msg}", file=sys.stderr)


try:
    _TTYSCAN_QUERY_TIMEOUT = float(os.environ.get('TTYSCAN_QUERY_TIMEOUT', '1.0'))
except ValueError:
    warn(f"TTYSCAN_QUERY_TIMEOUT value "
         f"{os.environ['TTYSCAN_QUERY_TIMEOUT']!r} "
         f"is not a valid float, using default 1.0")
    _TTYSCAN_QUERY_TIMEOUT = 1.0

_CANONICAL_BOOL_CAPS = [
    "bw", "am", "xsb", "xhp", "xenl", "eo", "gn", "hc", "km", "hs",
    "in", "da", "db", "mir", "msgr", "os", "eslok", "xt", "hz", "ul",
    "xon", "nxon", "mc5i", "chts", "nrrmc", "npc", "ndscr", "ccc", "bce",
    "hls", "xhpa", "crxm", "daisy", "xvpa", "sam", "cpix", "lpix",
    "OTbs", "OTns", "OTnc", "OTMT", "OTNL", "OTpt", "OTxr",
]

_CANONICAL_NUM_CAPS = [
    "cols", "it", "lines", "lm", "xmc", "pb", "vt", "wsl", "nlab",
    "lh", "lw", "ma", "wnum", "colors", "pairs", "ncv", "bufsz",
    "spinv", "spinh", "maddr", "mjump", "mcs", "mls", "npins",
    "orc", "orl", "orhi", "orvi", "cps", "widcs", "btns",
    "bitwin", "bitype", "OTug", "OTdC", "OTdN", "OTdB", "OTdT", "OTkn",
]

_CANONICAL_STR_CAPS = [
    "cbt", "bel", "cr", "csr", "tbc", "clear", "el", "ed", "hpa",
    "cmdch", "cup", "cud1", "home", "civis", "cub1", "mrcup", "cnorm",
    "cuf1", "ll", "cuu1", "cvvis", "dch1", "dl1", "dsl", "hd", "smacs",
    "blink", "bold", "smcup", "smdc", "dim", "smir", "invis", "prot",
    "rev", "smso", "smul", "ech", "rmacs", "sgr0", "rmcup", "rmdc",
    "rmir", "rmso", "rmul", "flash", "ff", "fsl", "is1", "is2", "is3",
    "if", "ich1", "il1", "ip", "kbs", "ktbc", "kclr", "kctab", "kdch1",
    "kdl1", "kcud1", "krmir", "kel", "ked", "kf0", "kf1", "kf10", "kf2",
    "kf3", "kf4", "kf5", "kf6", "kf7", "kf8", "kf9", "khome", "kich1",
    "kil1", "kcub1", "kll", "knp", "kpp", "kcuf1", "kind", "kri", "khts",
    "kcuu1", "rmkx", "smkx", "lf0", "lf1", "lf10", "lf2", "lf3", "lf4",
    "lf5", "lf6", "lf7", "lf8", "lf9", "rmm", "smm", "nel", "pad", "dch",
    "dl", "cud", "ich", "indn", "il", "cub", "cuf", "rin", "cuu", "pfkey",
    "pfloc", "pfx", "mc0", "mc4", "mc5", "rep", "rs1", "rs2", "rs3", "rf",
    "rc", "vpa", "sc", "ind", "ri", "sgr", "hts", "wind", "ht", "tsl",
    "uc", "hu", "iprog", "ka1", "ka3", "kb2", "kc1", "kc3", "mc5p", "rmp",
    "acsc", "pln", "kcbt", "smxon", "rmxon", "smam", "rmam", "xonc",
    "xoffc", "enacs", "smln", "rmln", "kbeg", "kcan", "kclo", "kcmd",
    "kcpy", "kcrt", "kend", "kent", "kext", "kfnd", "khlp", "kmrk",
    "kmsg", "kmov", "knxt", "kopn", "kopt", "kprv", "kprt", "krdo",
    "kref", "krfr", "krpl", "krst", "kres", "ksav", "kspd", "kund",
    "kBEG", "kCAN", "kCMD", "kCPY", "kCRT", "kDC", "kDL", "kslt", "kEND",
    "kEOL", "kEXT", "kFND", "kHLP", "kHOM", "kIC", "kLFT", "kMSG", "kMOV",
    "kNXT", "kOPT", "kPRV", "kPRT", "kRDO", "kRPL", "kRIT", "kRES",
    "kSAV", "kSPD", "kUND", "rfi", "kf11", "kf12", "kf13", "kf14", "kf15",
    "kf16", "kf17", "kf18", "kf19", "kf20", "kf21", "kf22", "kf23",
    "kf24", "kf25", "kf26", "kf27", "kf28", "kf29", "kf30", "kf31",
    "kf32", "kf33", "kf34", "kf35", "kf36", "kf37", "kf38", "kf39",
    "kf40", "kf41", "kf42", "kf43", "kf44", "kf45", "kf46", "kf47",
    "kf48", "kf49", "kf50", "kf51", "kf52", "kf53", "kf54", "kf55",
    "kf56", "kf57", "kf58", "kf59", "kf60", "kf61", "kf62", "kf63",
    "el1", "mgc", "smgl", "smgr", "fln", "sclk", "dclk", "rmclk", "cwin",
    "wingo", "hup", "dial", "qdial", "tone", "pulse", "hook", "pause",
    "wait", "u0", "u1", "u2", "u3", "u4", "u5", "u6", "u7", "u8", "u9",
    "op", "oc", "initc", "initp", "scp", "setf", "setb", "cpi", "lpi",
    "chr", "cvr", "defc", "swidm", "sdrfq", "sitm", "slm", "smicm",
    "snlq", "snrmq", "sshm", "ssubm", "ssupm", "sum", "rwidm", "ritm",
    "rlm", "rmicm", "rshm", "rsubm", "rsupm", "rum", "mhpa", "mcud1",
    "mcub1", "mcuf1", "mvpa", "mcuu1", "porder", "mcud", "mcub", "mcuf",
    "mcuu", "scs", "smgb", "smgbp", "smglp", "smgrp", "smgt", "smgtp",
    "sbim", "scsd", "rbim", "rcsd", "subcs", "supcs", "docr", "zerom",
    "csnm", "kmous", "minfo", "reqmp", "getm", "setaf", "setab", "pfxl",
    "devt", "csin", "s0ds", "s1ds", "s2ds", "s3ds", "smglr", "smgtb",
    "birep", "binel", "bicr", "colornm", "defbi", "endbi", "setcolor",
    "slines", "dispc", "smpch", "rmpch", "smsc", "rmsc", "pctrm", "scesc",
    "scesa", "ehhlm", "elhlm", "elohlm", "erhlm", "ethlm", "evhlm",
    "sgr1", "slength", "OTi2", "OTrs", "OTnl", "OTbc", "OTko", "OTma",
    "OTG2", "OTG3", "OTG1", "OTG4", "OTGR", "OTGL", "OTGU", "OTGD",
    "OTGH", "OTGV", "OTGC", "meml", "memu", "box1",
]

_INIT_XTGETTCAP_CAPS = frozenset((
    'TN', 'RGB', 'colors', 'blink', 'sitm', 'ritm', 'cvvis', 'Smulx', 'Setulc', 'Ms'
))

_FULL_XTGETTCAP_CAPS = tuple(
    sorted(set(_CANONICAL_BOOL_CAPS) | set(_CANONICAL_NUM_CAPS) | set(_CANONICAL_STR_CAPS))
)

_BOOL_SET = frozenset(_CANONICAL_BOOL_CAPS)
_NUM_SET = frozenset(_CANONICAL_NUM_CAPS)
_STR_SET = frozenset(_CANONICAL_STR_CAPS)

_RE_XTGETTCAP_RESPONSE = re.compile(
    r'\x1bP([01])\+r([0-9a-fA-F]+)(?:=([0-9a-fA-F]*))?\x1b\\')
_RE_CPR = re.compile(r'\x1b\[(\d+);(\d+)R')
_RE_CPR_BOUNDARY = re.compile(r'\x1b\[[0-9]+;[0-9]+R')
_RE_DECRPM = re.compile(r'\x1b\[\?(\d+);([0-4])\$y')
_RE_RESIZE = re.compile(r'\x1b\[48;(\d+);(\d+);(\d+);(\d+)t')

_TERMINFO_MAGIC = 0o432
_TERMINFO_MAGIC2 = 0o1036
_SENTINEL_ABSENT = -1

_BOOL_INDEX = {name: idx for idx, name in enumerate(_CANONICAL_BOOL_CAPS)}
_NUM_INDEX = {name: idx for idx, name in enumerate(_CANONICAL_NUM_CAPS)}
_STR_INDEX = {name: idx for idx, name in enumerate(_CANONICAL_STR_CAPS)}

_TERMINFO_ESCAPE = {
    'E': '\x1b', 'e': '\x1b',
    'n': '\n', 't': '\t', 'r': '\r',
    'b': '\b', 'f': '\f', 's': ' ',
    '\\': '\\', '^': '^', ':': ':',
}

_TERMINFO_TO_TERMCAP_BOOL = {
    "am": "am", "bce": "ut", "km": "km", "mc5i": "5i",
    "mir": "mi", "msgr": "ms", "npc": "NP", "xenl": "xn",
    "hs": "hs", "in": "in", "da": "da", "db": "db",
    "eo": "eo", "eslok": "es", "gn": "gn", "hc": "hc",
    "hz": "hz", "lpix": "YB", "ndscr": "ND", "nrrmc": "NR",
    "os": "os", "sam": "SA", "ul": "ul", "xb": "xb",
    "xn": "xn", "xt": "xt",
}

_TERMINFO_TO_TERMCAP_NUM = {
    "colors": "Co", "cols": "co", "lines": "li", "it": "it",
    "pairs": "pa", "btns": "BT", "bufsz": "Ya", "lm": "lm",
    "lh": "lh", "lw": "lw", "ma": "ma", "mw": "mw",
    "ncv": "NC", "nlab": "Nl", "pb": "pb", "sg": "sg",
    "ug": "ug", "vt": "vt", "ws": "ws", "wnum": "dw",
    "wsl": "ws",
}

_TERMINFO_TO_TERMCAP_STR = {
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


def verbose(msg, enabled):
    if enabled:
        print(f"ttyscan: {msg}", file=sys.stderr)


def hex_encode(s):
    return s.encode('ascii').hex()


def hex_decode(h):
    try:
        return bytes.fromhex(h).decode('ascii', errors='strict')
    except ValueError:
        return ''


def unescape_terminfo(value):
    result = []
    idx = 0
    while idx < len(value):
        cur = value[idx]
        if cur == '\\' and idx + 1 < len(value):
            nxt = value[idx + 1]
            esc = _TERMINFO_ESCAPE.get(nxt)
            if esc is not None:
                result.append(esc)
                idx += 2
                continue
            if nxt in '01234567':
                end = idx + 1
                while end < len(value) and value[end] in '01234567':
                    end += 1
                result.append(chr(int(value[idx + 1:end], 8)))
                idx = end
                continue
        elif cur == '^' and idx + 1 < len(value):
            nxt = value[idx + 1]
            if 'A' <= nxt <= '_':
                result.append(chr(ord(nxt) - ord('A') + 1))
                idx += 2
                continue
            if nxt == '?':
                result.append('\x7f')
                idx += 2
                continue
        result.append(cur)
        idx += 1
    return ''.join(result)


def open_tty():
    try:
        r_fd = os.open('/dev/tty', os.O_RDONLY | os.O_NOCTTY)
        w_fd = os.open('/dev/tty', os.O_WRONLY | os.O_NOCTTY)
        return r_fd, w_fd
    except OSError as exc:
        warn(f"cannot open /dev/tty: {exc}")
        return None, None


def get_winsize(fd):
    try:
        buf = array.array('H', [0, 0, 0, 0])
        fcntl.ioctl(fd, termios.TIOCGWINSZ, buf)
        return buf[1] or 80, buf[0] or 24
    except OSError:
        return 80, 24


def set_cbreak(fd):
    if fd is None:
        return None
    try:
        saved = termios.tcgetattr(fd)
        tty.setcbreak(fd, when=termios.TCSANOW)
        return saved
    except termios.error as exc:
        warn(f"cannot set cbreak mode: {exc}")
        return None


def restore_termios(fd, saved):
    if fd is None or saved is None:
        return
    try:
        termios.tcsetattr(fd, termios.TCSADRAIN, saved)
    except termios.error as exc:
        warn(f"cannot restore terminal mode: {exc}")


def write_all(fd, data):
    if fd is None:
        return
    if isinstance(data, str):
        data = data.encode('ascii', errors='replace')
    remaining = data
    while remaining:
        try:
            n = os.write(fd, remaining)
            remaining = remaining[n:]
        except OSError as exc:
            warn(f"write error: {exc}")
            break


def read_available(r_fd, timeout):
    buf = bytearray()
    stime = time.monotonic()
    max_size = 131072
    while True:
        timeleft = 0.0 if buf else timeout - (time.monotonic() - stime)
        if not buf and timeleft <= 0:
            break
        try:
            ready, _, _ = select.select([r_fd], [], [], timeleft)
        except OSError as exc:
            warn(f"select error: {exc}")
            break
        if not ready:
            break
        try:
            chunk = os.read(r_fd, 4096)
        except OSError as exc:
            warn(f"read error: {exc}")
            break
        if not chunk:
            break
        buf.extend(chunk)
        if len(buf) > max_size:
            break
    return bytes(buf)


def read_until(r_fd, w_fd, queries, pattern, timeout):
    for q in queries:
        write_all(w_fd, q)
    write_all(w_fd, b'\x1b[6n')
    stime = time.monotonic()
    buf = ''
    max_size = 131072
    while True:
        timeleft = timeout - (time.monotonic() - stime)
        if timeleft <= 0:
            break
        raw = read_available(r_fd, timeleft)
        if not raw:
            break
        buf += raw.decode('latin-1', errors='replace')
        if (match := re.search(pattern, buf)) is not None:
            return match, buf
        if len(buf) > max_size:
            break
    return None, buf


def xtgettcap_query(r_fd, w_fd, caps, timeout):
    if not caps:
        return {}
    queries = [f'\x1bP+q{hex_encode(c)}\x1b\\' for c in caps]
    match, data = read_until(r_fd, w_fd, queries, _RE_CPR_BOUNDARY.pattern, timeout)
    if match is None:
        return {}
    data = data[:match.start()] + data[match.end():]
    capabilities = {}
    for m in _RE_XTGETTCAP_RESPONSE.finditer(data):
        if m.group(1) == '1':
            name = hex_decode(m.group(2))
            val_hex = m.group(3)
            if val_hex is not None:
                value = unescape_terminfo(hex_decode(val_hex))
            else:
                value = ''
            capabilities[name] = value
    return capabilities


def decrqm_query(r_fd, w_fd, mode, timeout):
    result = read_until(r_fd, w_fd,
                        [f'\x1b[?{mode}$p'],
                        _RE_CPR_BOUNDARY.pattern, timeout)
    if (match := result[0]) is None:
        return None
    data = result[1][:match.start()] + result[1][match.end():]
    for m in _RE_DECRPM.finditer(data):
        if int(m.group(1)) == mode:
            return int(m.group(2))
    return None


def detect_size(r_fd, w_fd, verbose_enabled):
    has_inband = (decrpm := decrqm_query(r_fd, w_fd, 2048, 0.25)) is not None and decrpm == 2

    if has_inband:
        write_all(w_fd, '\x1b[?2048h')
        raw = read_available(r_fd, 0.25).decode('latin-1', errors='replace')
        if (resize_match := _RE_RESIZE.search(raw)):
            rows = int(resize_match.group(1))
            cols = int(resize_match.group(2))
            verbose(f"size via Mode 2048 in-band: {rows}x{cols}", verbose_enabled)
            write_all(w_fd, '\x1b[?2048l')
            return rows, cols, 'inband'

    cpr1_match, data = read_until(r_fd, w_fd, [], _RE_CPR.pattern, 0.25)
    orig_y = orig_x = None
    if cpr1_match:
        orig_y = int(cpr1_match.group(1))
        orig_x = int(cpr1_match.group(2))

    write_all(w_fd, '\x1b[1000;1000H')
    cpr2_match, _ = read_until(r_fd, w_fd, [], _RE_CPR.pattern, 0.25)

    if has_inband:
        write_all(w_fd, '\x1b[?2048l')

    if orig_y is not None:
        write_all(w_fd, f'\x1b[{orig_y};{orig_x}H')

    if cpr2_match:
        rows = int(cpr2_match.group(1))
        cols = int(cpr2_match.group(2))
        if rows == 999 or cols == 999:
            verbose(f"rejecting bogus CPR size {rows}x{cols}", verbose_enabled)
            return None
        verbose(f"size via dual CPR: {rows}x{cols}", verbose_enabled)
        return rows, cols, 'cpr'

    verbose("CPR size detection", verbose_enabled)
    write_all(w_fd, '\x1b[1000;1000H')
    fb_match, _ = read_until(r_fd, w_fd, [], _RE_CPR.pattern, 0.25)
    if fb_match:
        rows = int(fb_match.group(1))
        cols = int(fb_match.group(2))
        if rows != 999 and cols != 999:
            verbose(f"size via CPR: {rows}x{cols}", verbose_enabled)
            return rows, cols, 'fallback_cpr'

    verbose("size detection failed", verbose_enabled)
    return None


def classify_caps(capabilities):
    bool_caps = set()
    num_caps = {}
    str_caps = {}
    for name, value in capabilities.items():
        if name == 'RGB':
            continue
        if not value:
            if name in _BOOL_SET:
                bool_caps.add(name)
        elif name in _NUM_SET:
            if value.isdigit():
                num_caps[name] = int(value)
        elif name in _STR_SET:
            str_caps[name] = value
    return {'bool_caps': bool_caps, 'num_caps': num_caps, 'str_caps': str_caps}


def pack_short_le(buf, offset, value):
    packed = struct.pack("<h", value)
    buf[offset:offset + 2] = packed


def build_terminfo_binary(term, str_caps, num_caps, bool_caps):
    names = f"{term}|XTGETTCAP-discovered terminal"
    names_bytes = names.encode("ascii", errors="replace") + b"\x00"
    name_size = len(names_bytes)
    bool_indices = [_BOOL_INDEX[cap] for cap in bool_caps if cap in _BOOL_INDEX]
    bool_max = max(bool_indices) + 1 if bool_indices else 0
    bool_data = bytearray(bool_max)
    for idx in bool_indices:
        bool_data[idx] = 1
    num_entries = [(_NUM_INDEX[cap], val) for cap, val in num_caps.items()
                   if cap in _NUM_INDEX]
    num_max = max(idx for idx, _ in num_entries) + 1 if num_entries else 0
    use_32bit = any(val > 32767 or val < -32768 for _, val in num_entries)
    num_entry_size = 4 if use_32bit else 2
    magic = _TERMINFO_MAGIC2 if use_32bit else _TERMINFO_MAGIC
    num_data = bytearray(num_max * num_entry_size)
    for idx, val in num_entries:
        if use_32bit:
            struct.pack_into("<i", num_data, idx * 4, val)
        else:
            pack_short_le(num_data, idx * 2, val)
    num_used = set(idx for idx, _ in num_entries)
    for i in range(num_max):
        if i not in num_used:
            if use_32bit:
                struct.pack_into("<i", num_data, i * 4, _SENTINEL_ABSENT)
            else:
                pack_short_le(num_data, i * 2, _SENTINEL_ABSENT)
    str_entries = [(_STR_INDEX[cap], val.encode("utf-8", errors="replace"))
                   for cap, val in str_caps.items() if cap in _STR_INDEX]
    str_max = max(idx for idx, _ in str_entries) + 1 if str_entries else 0
    str_table_parts = []
    offsets = {}
    for idx, raw in sorted(str_entries):
        offsets[idx] = len(b"".join(str_table_parts))
        str_table_parts.append(raw + b"\x00")
    str_table = b"".join(str_table_parts)
    offset_data = bytearray(str_max * 2)
    for i in range(str_max):
        if i in offsets:
            pack_short_le(offset_data, i * 2, offsets[i])
        else:
            pack_short_le(offset_data, i * 2, _SENTINEL_ABSENT)
    header = bytearray(12)
    pack_short_le(header, 0, magic)
    pack_short_le(header, 2, name_size)
    pack_short_le(header, 4, bool_max)
    pack_short_le(header, 6, num_max)
    pack_short_le(header, 8, str_max)
    pack_short_le(header, 10, len(str_table))
    parts = [bytes(header), names_bytes, bytes(bool_data)]
    if (name_size + bool_max) % 2 != 0:
        parts.append(b"\x00")
    parts.append(bytes(num_data))
    parts.append(bytes(offset_data))
    parts.append(str_table)
    return b"".join(parts)


def sanitize_term_name(name):
    cleaned = re.sub(r'[^a-zA-Z0-9._-]', '', name)
    cleaned = cleaned.lstrip('.')
    return cleaned if cleaned else 'unknown'


def terminfo_file_path(term, base_dir):
    return base_dir / term[0] / term


def terminfo_installed_at(term, base_dir):
    return terminfo_file_path(term, base_dir).exists()


def ttyscan_terminfo_dir():
    xdg = os.environ.get(
        "XDG_CONFIG_HOME",
        os.path.join(os.path.expanduser("~"), ".config"),
    )
    return Path(xdg) / "ttyscan" / "terminfo"


def has_terminfo(term):
    try:
        import curses
        curses.setupterm(term)
        return bool(curses.tigetstr("clear"))
    except Exception:
        return False


def write_terminfo(term, str_caps, num_caps, bool_caps, dest_dir):
    safe_term = sanitize_term_name(term)
    data = build_terminfo_binary(safe_term, str_caps, num_caps, bool_caps)
    file_path = terminfo_file_path(safe_term, dest_dir)
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_bytes(data)
    return True


def escape_value(value, terminfo=False):
    simple = {
        "\x1b": "\\E", "\n": "\\n", "\t": "\\t", "\r": "\\r",
        "\b": "\\b", "\f": "\\f", "\\": "\\\\", "^": "\\^",
    }
    if terminfo:
        simple[" "] = "\\s"
        simple[":"] = "\\:"
    result = []
    for ch in value:
        if ch in simple:
            result.append(simple[ch])
            continue
        code = ord(ch)
        if code < 32:
            result.append(f"^{chr(code + 64)}")
        elif code == 127:
            result.append("^?")
        else:
            result.append(ch)
    return "".join(result)


def shell_escape(value):
    if not value:
        return "''"
    escaped = value.replace("'", "'\\''")
    return f"'{escaped}'"


def build_termcap_entry(term, str_caps, num_caps, bool_caps):
    parts = [f"{term}|XTGETTCAP-discovered terminal:"]
    for cap in sorted(bool_caps):
        tc_name = _TERMINFO_TO_TERMCAP_BOOL.get(cap)
        if tc_name:
            parts.append(f":{tc_name}:")
    for cap in sorted(num_caps):
        tc_name = _TERMINFO_TO_TERMCAP_NUM.get(cap)
        if tc_name:
            parts.append(f":{tc_name}#{num_caps[cap]}:")
    for cap in sorted(str_caps):
        tc_name = _TERMINFO_TO_TERMCAP_STR.get(cap)
        if tc_name:
            value = escape_value(str_caps[cap])
            parts.append(f":{tc_name}={value}:")
    return "".join(parts)


def normalize_terminal_name(raw):
    if raw == "WezTerm":
        return "wezterm"
    return raw


def has_meaningful_caps(str_caps, num_caps, bool_caps):
    screen_str_caps = {k for k in str_caps if not k.startswith('k')}
    if screen_str_caps:
        return True
    if bool_caps:
        return True
    meaningful_nums = {k for k in num_caps if k not in ('colors', 'Co')}
    if meaningful_nums:
        return True
    return False


def check_colorterm(caps, force):
    rgb = caps.get("RGB", "")
    try:
        if rgb and int(rgb.split("/", 1)[0]) == 8:
            if force or os.environ.get("COLORTERM") != "truecolor":
                return "export COLORTERM=truecolor"
    except ValueError:
        pass
    return None


def check_term(caps, force):
    tn = caps.get("TN")
    if tn:
        tn = normalize_terminal_name(tn)
        if force or tn != os.environ.get("TERM"):
            return f"export TERM={tn}"
    return None


def check_lines_columns(rows, cols, winsize, force):
    term_cols, term_rows = winsize
    if not force and (rows, cols) == (term_rows, term_cols):
        if ((env_lines := os.environ.get("LINES")) is None or env_lines == str(rows)) and \
           ((env_cols := os.environ.get("COLUMNS")) is None or env_cols == str(cols)):
            return None
    exports = []
    env_lines = os.environ.get("LINES")
    env_cols = os.environ.get("COLUMNS")
    if force or env_lines != str(rows):
        exports.append(f"export LINES={rows}")
    if force or env_cols != str(cols):
        exports.append(f"export COLUMNS={cols}")
    return exports or None


def generate_exports(verbose_enabled=False, force=False, termcap=False):
    verbose("probing terminal via XTGETTCAP ...", verbose_enabled)

    r_fd, w_fd = open_tty()
    if r_fd is None or w_fd is None:
        verbose("no terminal available", verbose_enabled)
        return []

    saved = set_cbreak(r_fd)
    try:
        winsize = get_winsize(r_fd)

        init_caps = xtgettcap_query(r_fd, w_fd, _INIT_XTGETTCAP_CAPS,
                                    timeout=_TTYSCAN_QUERY_TIMEOUT)
        if not init_caps:
            verbose("XTGETTCAP not supported by this terminal", verbose_enabled)
            return []

        tn_raw = init_caps.get("TN")
        if not tn_raw:
            verbose("no TN (terminal name) capability, cannot export further",
                    verbose_enabled)
            return []

        tn = normalize_terminal_name(tn_raw)

        exports = []

        ct_export = check_colorterm(init_caps, force)
        if ct_export:
            exports.append(ct_export)

        term_export = check_term(init_caps, force)
        if term_export:
            exports.append(term_export)

        size = detect_size(r_fd, w_fd, verbose_enabled)
        if size:
            rows, cols, source = size
            term_cols, term_rows = winsize
            if source != 'inband' and (
                rows == 999 or cols == 999
                or rows < term_rows or cols < term_cols
            ):
                verbose(
                    f"rejecting CPR size {rows}x{cols} "
                    f"(term reports {term_rows}x{term_cols})",
                    verbose_enabled,
                )
            else:
                lc = check_lines_columns(rows, cols, winsize, force)
                if lc:
                    exports.extend(lc)

        if not force and not termcap and has_terminfo(tn):
            verbose(f"XTGETTCAP supported, terminal: {tn}", verbose_enabled)
            verbose("terminfo already available in system database", verbose_enabled)
            return exports

        remaining_caps = [c for c in _FULL_XTGETTCAP_CAPS
                          if c not in _INIT_XTGETTCAP_CAPS]
        t0 = time.monotonic()
        full_caps = xtgettcap_query(r_fd, w_fd, remaining_caps,
                                    timeout=_TTYSCAN_QUERY_TIMEOUT)
        elapsed_ms = int((time.monotonic() - t0) * 1000)

        full_caps.update(init_caps)
        classified = classify_caps(full_caps)
        str_caps = classified['str_caps']
        num_caps = classified['num_caps']
        bool_caps = classified['bool_caps']

        n_caps = len(full_caps)
        verbose(
            f"XTGETTCAP supported, terminal: {tn}; "
            f"received {n_caps} caps "
            f"({len(bool_caps)} bool, {len(num_caps)} num, {len(str_caps)} str) "
            f"in {elapsed_ms}ms",
            verbose_enabled,
        )

        if not has_meaningful_caps(str_caps, num_caps, bool_caps):
            verbose(
                "only bare-minimum capabilities (TN/colors/RGB), "
                "skipping TERMINFO/TERMCAP export",
                verbose_enabled,
            )
            return exports

        terminfo_dir = ttyscan_terminfo_dir()
        safe_term = sanitize_term_name(tn)

        if not has_terminfo(tn) or force:
            write_terminfo(tn, str_caps, num_caps, bool_caps, terminfo_dir)
            verbose(f"writing {terminfo_file_path(safe_term, terminfo_dir)}",
                    verbose_enabled)
            terminfo_value = str(terminfo_dir)
            current_terminfo = os.environ.get("TERMINFO")
            if force or current_terminfo != terminfo_value:
                exports.append(f"export TERMINFO={terminfo_value}")
        else:
            verbose("terminfo already available in system database", verbose_enabled)

        if termcap:
            entry = build_termcap_entry(tn, str_caps, num_caps, bool_caps)
            if entry and (force or os.environ.get("TERMCAP") != entry):
                exports.append(f"export TERMCAP={shell_escape(entry)}")

        return exports

    finally:
        restore_termios(r_fd, saved)
        if r_fd is not None:
            try:
                os.close(r_fd)
            except OSError:
                pass
        if w_fd is not None:
            try:
                os.close(w_fd)
            except OSError:
                pass


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="ttyscan",
        description="Export terminal capabilities discovered via XTGETTCAP",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Print diagnostic information to stderr",
    )
    parser.add_argument(
        "-f", "--force", action="store_true",
        help="Force export of all values even if unchanged",
    )
    parser.add_argument(
        "-t", "--termcap", action="store_true",
        help="Also export TERMCAP value",
    )
    args = parser.parse_args(argv)

    exports = generate_exports(
        verbose_enabled=args.verbose,
        force=args.force,
        termcap=args.termcap,
    )
    for line in exports:
        print(line)


if __name__ == '__main__':
    main()
