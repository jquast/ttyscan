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

__version__ = "0.0.9"

_VERBOSE = False


def warn(msg):
    print(f"ttyscan: {msg}", file=sys.stderr)


def verbose(msg):
    if _VERBOSE:
        print(f"ttyscan: {msg}", file=sys.stderr)


def shell_escape(value):
    if not value:
        return "''"
    escaped = value.replace("'", "'\\''")
    return f"'{escaped}'"


def env_exports(force, *pairs, quote=shell_escape):
    return [f"export {name}={quote(str(value))}" for name, value in pairs
            if force or os.environ.get(name, "") != str(value)]


def size_exports(rows, cols, winsize, force):
    pairs = (("LINES", rows), ("COLUMNS", cols))
    if not force and (rows, cols) == (winsize[1], winsize[0]) and all(
            os.environ.get(name) in (None, str(value)) for name, value in pairs):
        return []
    return env_exports(force, *pairs, quote=str)


try:
    _TTYSCAN_QUERY_TIMEOUT = float(os.environ.get('TTYSCAN_QUERY_TIMEOUT', '10.0'))
except ValueError:
    warn(f"TTYSCAN_QUERY_TIMEOUT value "
         f"{os.environ['TTYSCAN_QUERY_TIMEOUT']!r} "
         f"is not a valid float, using default 10.0")
    _TTYSCAN_QUERY_TIMEOUT = 10.0

_CANONICAL_BOOL_CAPS = (
    "AX bw am xsb xhp xenl eo gn hc km hs in da db mir msgr os eslok xt hz ul xon "
    "nxon mc5i chts nrrmc npc ndscr ccc bce hls xhpa crxm daisy xvpa sam cpix "
    "lpix OTbs OTns OTnc OTMT OTNL OTpt OTxr").split()

_CANONICAL_NUM_CAPS = (
    "cols it lines lm xmc pb vt wsl nlab lh lw ma wnum colors pairs ncv bufsz "
    "spinv spinh maddr mjump mcs mls npins U8 orc orl orhi orvi cps widcs btns "
    "bitwin bitype OTug OTdC OTdN OTdB OTdT OTkn").split()

_CANONICAL_STR_CAPS = (
    "cbt bel cr csr tbc clear el ed hpa cmdch cup cud1 home civis cub1 mrcup "
    "cnorm cuf1 ll cuu1 cvvis dch1 dl1 dsl hd smacs blink bold smcup smdc dim "
    "smir invis prot rev smso smul ech rmacs sgr0 rmcup rmdc rmir rmso rmul flash "
    "ff fsl is1 is2 is3 if ich1 il1 ip kbs ktbc kclr kctab kdch1 kdl1 kcud1 krmir "
    "kel ked kf0 kf1 kf10 kf2 kf3 kf4 kf5 kf6 kf7 kf8 kf9 khome kich1 kil1 kcub1 "
    "kll knp kpp kcuf1 kind kri khts kcuu1 rmkx smkx lf0 lf1 lf10 lf2 lf3 lf4 lf5 "
    "lf6 lf7 lf8 lf9 rmm smm nel pad dch dl cud ich indn il cub cuf rin cuu pfkey "
    "pfloc pfx mc0 mc4 mc5 rep rs1 rs2 rs3 rf rc vpa sc ind ri sgr hts wind ht "
    "tsl uc hu iprog ka1 ka3 kb2 kc1 kc3 mc5p rmp acsc pln kcbt smxon rmxon smam "
    "rmam xonc xoffc enacs smln rmln kbeg kcan kclo kcmd kcpy kcrt kend kent kext "
    "kfnd khlp kmrk kmsg kmov knxt kopn kopt kprv kprt krdo kref krfr krpl krst "
    "kres ksav kspd kund kBEG kCAN kCMD kCPY kCRT kDC kDL kslt kEND kEOL kEXT "
    "kFND kHLP kHOM kIC kLFT kMSG kMOV kNXT kOPT kPRV kPRT kRDO kRPL kRIT kRES "
    "kSAV kSPD kUND rfi kf11 kf12 kf13 kf14 kf15 kf16 kf17 kf18 kf19 kf20 kf21 "
    "kf22 kf23 kf24 kf25 kf26 kf27 kf28 kf29 kf30 kf31 kf32 kf33 kf34 kf35 kf36 "
    "kf37 kf38 kf39 kf40 kf41 kf42 kf43 kf44 kf45 kf46 kf47 kf48 kf49 kf50 kf51 "
    "kf52 kf53 kf54 kf55 kf56 kf57 kf58 kf59 kf60 kf61 kf62 kf63 el1 mgc smgl "
    "smgr fln sclk dclk rmclk cwin wingo hup dial qdial tone pulse hook pause "
    "wait u0 u1 u2 u3 u4 u5 u6 u7 u8 u9 op oc initc initp scp setf setb cpi lpi "
    "chr cvr defc swidm sdrfq sitm slm smicm snlq snrmq sshm ssubm ssupm sum "
    "rwidm ritm rlm rmicm rshm rsubm rsupm rum mhpa mcud1 mcub1 mcuf1 mvpa mcuu1 "
    "porder mcud mcub mcuf mcuu scs smgb smgbp smglp smgrp smgt smgtp sbim scsd "
    "rbim rcsd subcs supcs docr zerom csnm kmous minfo reqmp getm setaf setab "
    "pfxl devt csin s0ds s1ds s2ds s3ds smglr smgtb birep binel bicr colornm "
    "defbi endbi setcolor slines dispc smpch rmpch smsc rmsc pctrm scesc scesa "
    "ehhlm elhlm elohlm erhlm ethlm evhlm sgr1 slength OTi2 OTrs OTnl OTbc OTko "
    "OTma OTG2 OTG3 OTG1 OTG4 OTGR OTGL OTGU OTGD OTGH OTGV OTGC meml memu box1 "
    "BD BE Cr Cs E3 Ms PE PS Rmol RV S0 Se Setulc Smol Smulx Ss TS XM XR").split()

_INIT_XTGETTCAP_CAPS = frozenset((
    'TN', 'RGB', 'colors', 'blink', 'sitm', 'ritm', 'cvvis', 'Smulx', 'Setulc', 'Ms'
))

_FULL_XTGETTCAP_CAPS = tuple(
    sorted(set(_CANONICAL_BOOL_CAPS) | set(_CANONICAL_NUM_CAPS) | set(_CANONICAL_STR_CAPS))
)

# VTE-based terminals (GNOME Terminal, et al.) send malformed ``\\x1bP0+r\\x1b\\\\``
# (empty hex name) for unsupported capabilities, so zero-or-more hex digits.
_RE_XTGETTCAP_RESPONSE = re.compile(
    r'\x1bP([01])\+r([0-9a-fA-F]*)(?:=([0-9a-fA-F]*))?\x1b\\')
_RE_XTVERSION_RESPONSE = re.compile(r'\x1bP>\|(.+?)\x1b\\')
_RE_CPR = re.compile(r'\x1b\[(\d+);(\d+)R')
_RE_CPR_BOUNDARY = re.compile(r'\x1b\[[0-9]+;[0-9]+R')
_RE_DECRPM = re.compile(r'\x1b\[\?(\d+);([0-4])\$y')
_RE_RESIZE = re.compile(r'\x1b\[48;(\d+);(\d+);(\d+);(\d+)t')
_RE_DECRQSS_RESPONSE = re.compile(r'\x1bP([01])\$r([^\x1b]*)\x1b\\')

_TERMINFO_MAGIC = 0o432
_TERMINFO_MAGIC2 = 0o1036
_SENTINEL_ABSENT = -1
_MAX_INPUT = 131072

_BOOL_INDEX = {name: idx for idx, name in enumerate(_CANONICAL_BOOL_CAPS)}
_NUM_INDEX = {name: idx for idx, name in enumerate(_CANONICAL_NUM_CAPS)}
_STR_INDEX = {name: idx for idx, name in enumerate(_CANONICAL_STR_CAPS)}

_TERMINFO_ESCAPE = {
    'E': '\x1b', 'e': '\x1b',
    'n': '\n', 't': '\t', 'r': '\r',
    'b': '\b', 'f': '\f', 's': ' ',
    '\\': '\\', '^': '^', ':': ':',
}

_TERMINFO_TO_TERMCAP_BOOL = dict(p.split(':') for p in (
    "am:am bce:ut km:km mc5i:5i mir:mi msgr:ms npc:NP xenl:xn hs:hs in:in da:da "
    "db:db eo:eo eslok:es gn:gn hc:hc hz:hz lpix:YB ndscr:ND nrrmc:NR os:os "
    "sam:SA ul:ul xb:xb xn:xn xt:xt").split())

_TERMINFO_TO_TERMCAP_NUM = dict(p.split(':') for p in (
    "colors:Co cols:co lines:li it:it pairs:pa btns:BT bufsz:Ya lm:lm lh:lh lw:lw "
    "ma:ma mw:mw ncv:NC nlab:Nl pb:pb sg:sg ug:ug vt:vt ws:ws wnum:dw wsl:ws").split())

_TERMINFO_TO_TERMCAP_STR = dict(p.split(':') for p in (
    "acsc:ac bel:bl blink:mb bold:md cbt:bt civis:vi clear:cl cnorm:ve cr:cr "
    "csr:cs cub1:le cud:DO cud1:do cuf1:nd cup:cm cuu1:up cvvis:vs dch1:dC dim:mh "
    "dl1:dl dsl:ds ech:ec ed:cd el:ce el1:cb flash:vb fsl:fs home:ho hpa:ch "
    "hts:st ht:ta ich1:ic il1:al ind:sf invis:mk iprog:iP is1:i1 is2:is is3:i3 "
    "kb2:K2 kbs:kb kcbt:kB kcub1:kl kcud1:kd kcuf1:kr kcuu1:ku kdch1:kD kend:@7 "
    "kent:@8 kf1:k1 kf2:k2 kf3:k3 kf4:k4 kf5:k5 kf6:k6 kf7:k7 kf8:k8 kf9:k9 "
    "kf10:k0 kf11:F1 kf12:F2 kfnd:kF khlp:%1 khome:kh kich1:kI kind:kH knp:kN "
    "kpp:kP kprv:kR kspd:@9 ktbc:ka mc0:ps mc4:pf mc5:po mc5p:pO nel:nw op:op "
    "pad:pc pln:pn prot:mp rep:rp rev:mr ri:sr rmacs:ae rmcup:te rmdc:ed rmir:ei "
    "rmkx:ke rmso:se rmul:ue rs1:r1 rs2:r2 rs3:r3 sgr:sa sgr0:me sitm:ZH ritm:ZR "
    "smacs:as smcup:ti smdc:dm smir:im smkx:ks smso:so smul:us tbc:ct tsl:ts "
    "vpa:cv wind:wi wingo:WS").split())


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
        return os.open('/dev/tty', os.O_RDWR | os.O_NOCTTY)
    except OSError as exc:
        warn(f"cannot open /dev/tty: {exc}")
        return None


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


def read_available(fd, timeout):
    buf = bytearray()
    stime = time.monotonic()
    while True:
        timeleft = 0.0 if buf else timeout - (time.monotonic() - stime)
        if not buf and timeleft <= 0:
            break
        try:
            ready, _, _ = select.select([fd], [], [], timeleft)
        except OSError as exc:
            warn(f"select error: {exc}")
            break
        if not ready:
            break
        try:
            chunk = os.read(fd, 4096)
        except OSError as exc:
            warn(f"read error: {exc}")
            break
        if not chunk:
            break
        buf.extend(chunk)
        if len(buf) > _MAX_INPUT:
            break
    return bytes(buf)


def read_chunks(fd, timeout):
    start = time.monotonic()
    while True:
        left = timeout - (time.monotonic() - start)
        if left <= 0:
            return
        chunk = read_available(fd, left)
        if not chunk:
            return
        yield chunk.decode('latin-1', errors='replace')


class NoCPRReply(Exception):
    """Raised when the terminal does not answer a cursor position report."""


def read_until(fd, queries, pattern=_RE_CPR_BOUNDARY.pattern,
               timeout=_TTYSCAN_QUERY_TIMEOUT):
    """Read until ``pattern`` matches, using a cursor position report as fence.

    The fence reply proves the terminal is answering, and a missing reply means
    nothing will arrive.  Bytes after the fence belong to no query: a late
    reply, or a keystroke typed meanwhile, and a tty read cannot hand either
    back.
    """
    for q in queries:
        write_all(fd, q)
    write_all(fd, b'\x1b[6n')
    buf = ''
    for chunk in read_chunks(fd, timeout):
        buf += chunk
        match = re.search(pattern, buf)
        if match is not None:
            return match, buf
        if len(buf) > _MAX_INPUT:
            raise NoCPRReply("no fence in 128 KiB of input")
    raise NoCPRReply("no cursor position report")


def read_cpr(fd, timeout=_TTYSCAN_QUERY_TIMEOUT, minimum=None):
    """Read a cursor position report and return ``(rows, cols)``.

    ``minimum`` is the ``(cols, rows)`` size of the tty.  A probe that parks the
    cursor past the last cell is answered with at least the screen size, so a
    smaller report is a late answer to an earlier query and is skipped.
    Raises ``NoCPRReply`` when no acceptable report arrives before ``timeout``.
    """
    write_all(fd, b'\x1b[6n')
    buf = ''
    for chunk in read_chunks(fd, timeout):
        buf += chunk
        for match in _RE_CPR.finditer(buf):
            rows = int(match.group(1))
            cols = int(match.group(2))
            if minimum is None or (rows >= minimum[1] and cols >= minimum[0]):
                return rows, cols
    raise NoCPRReply("no cursor position report")


def query(fd, requests, pattern, timeout=_TTYSCAN_QUERY_TIMEOUT):
    fence, data = read_until(fd, requests, timeout=timeout)
    return re.finditer(pattern, data[:fence.start()] + data[fence.end():])


def xtgettcap_query(fd, caps, timeout=_TTYSCAN_QUERY_TIMEOUT):
    """Return the capabilities for *caps* with the number of replies received."""
    if not caps:
        return {}, 0
    replies = list(query(fd, [f'\x1bP+q{hex_encode(c)}\x1b\\' for c in caps],
                         _RE_XTGETTCAP_RESPONSE, timeout))
    found = {hex_decode(m.group(2)): unescape_terminfo(hex_decode(m.group(3) or ''))
             for m in replies if m.group(1) == '1'}
    return found, len(replies)


def check_xtgettcap_replies(init_answered, init_asked, answered, asked):
    """Warn when a terminal that answered every opening query lost replies.

    A terminal that answers unknown capabilities with a refusal answers every
    query, so a short batch means the reply was cut.  A terminal that answers
    only selected capabilities is short by nature and says nothing.
    """
    if init_answered == init_asked and answered < asked:
        warn(f"XTGETTCAP: {answered} of {asked} queries answered, "
             f"the batch may be truncated")


def xtversion_query(fd, timeout=_TTYSCAN_QUERY_TIMEOUT):
    for m in query(fd, ['\x1b[>q'], _RE_XTVERSION_RESPONSE, timeout):
        text = m.group(1)
        if ' ' in text:
            return tuple(text.split(' ', 1))
        if '(' in text:
            name, version = text.split('(', 1)
            return name, version.rstrip(')')
        return text, ''
    return None


def decrqm_query(fd, mode, timeout=_TTYSCAN_QUERY_TIMEOUT):
    for m in query(fd, [f'\x1b[?{mode}$p'], _RE_DECRPM, timeout):
        if int(m.group(1)) == mode:
            return int(m.group(2))
    return None


def decqss_query(fd, setting_id, timeout=_TTYSCAN_QUERY_TIMEOUT):
    """Query terminal state via DECRQSS.

    Sends ``DCS $ q <setting_id> ST`` with a CPR boundary fence.  Returns the
    decoded parameter string on success, with the echoed setting identifier
    stripped.  Returns ``None`` when the terminal does not support DECRQSS or
    the setting is invalid.
    """
    for m in query(fd, [f'\x1bP$q{setting_id}\x1b\\'], _RE_DECRQSS_RESPONSE, timeout):
        if m.group(1) == '1':
            text = m.group(2)
            return text[:-len(setting_id)] if text.endswith(setting_id) else text
    return None


def probe_truecolor(fd, timeout):
    """Detect truecolor support via DECRQSS SGR set/query/restore."""
    original = decqss_query(fd, 'm', timeout)
    if original is None:
        verbose("DECRQSS not supported by this terminal")
        return False
    write_all(fd, '\x1b[48:2:1:2:3m')
    probed = decqss_query(fd, 'm', timeout)
    write_all(fd, f'\x1b[{original}m')
    if probed is None:
        verbose("DECRQSS probe query failed")
        return False
    # Terminals may normalize the response, e.g. "48:2::1:2:3" or
    # "48;2;1;2;3", so match the RGB triple with either delimiter.
    accepted = bool(re.search(r'48[:;]2[:;]*1[:;]2[:;]3', probed))
    if not accepted:
        verbose(f"DECRQSS truecolor probe: color not accepted: {probed!r}")
    return accepted


def detect_size(fd, winsize, timeout=_TTYSCAN_QUERY_TIMEOUT):
    has_inband = decrqm_query(fd, 2048, timeout) == 2
    if has_inband:
        cpr, data = read_until(fd, ['\x1b[?2048h'], _RE_CPR.pattern, timeout)
        resize = _RE_RESIZE.search(data[:cpr.start()])
        if resize:
            rows = int(resize.group(1))
            cols = int(resize.group(2))
            verbose(f"size via Mode 2048 in-band: {rows}x{cols}")
            write_all(fd, '\x1b[?2048l')
            return rows, cols, 'inband'

    write_all(fd, '\x1b7\x1b[1000;1000H')
    size = read_cpr(fd, timeout, minimum=winsize)
    write_all(fd, '\x1b8')

    if has_inband:
        write_all(fd, '\x1b[?2048l')

    if size is None:
        verbose("size detection failed")
        return None
    rows, cols = size
    if rows == 999 or cols == 999:
        verbose(f"rejecting bogus CPR size {rows}x{cols}")
        return None
    verbose(f"size via CPR: {rows}x{cols}")
    return rows, cols, 'cpr'


def classify_caps(capabilities):
    return {
        'bool_caps': {name for name, value in capabilities.items()
                      if name in _BOOL_INDEX and not value},
        'num_caps': {name: int(value) for name, value in capabilities.items()
                     if name in _NUM_INDEX and value.isdigit()},
        'str_caps': {name: value for name, value in capabilities.items()
                     if name in _STR_INDEX and value},
    }


def build_terminfo_binary(term, str_caps, num_caps, bool_caps):
    names = f"{term}|XTGETTCAP-discovered terminal".encode("ascii", "replace") + b"\x00"
    flags = {_BOOL_INDEX[cap]: 1 for cap in bool_caps if cap in _BOOL_INDEX}
    bool_max = max(flags, default=-1) + 1
    bool_data = bytes(flags.get(idx, 0) for idx in range(bool_max))
    nums = {_NUM_INDEX[cap]: val for cap, val in num_caps.items()
            if cap in _NUM_INDEX}
    num_max = max(nums, default=-1) + 1
    fmt = "<i" if any(not -32768 <= val <= 32767 for val in nums.values()) else "<h"
    entry_size = struct.calcsize(fmt)
    num_data = bytearray(num_max * entry_size)
    for idx in range(num_max):
        struct.pack_into(fmt, num_data, idx * entry_size,
                         nums.get(idx, _SENTINEL_ABSENT))
    strings = {_STR_INDEX[cap]: val.encode("utf-8", "replace")
               for cap, val in str_caps.items() if cap in _STR_INDEX}
    str_max = max(strings, default=-1) + 1
    offsets = {}
    table = []
    pos = 0
    for idx in sorted(strings):
        offsets[idx] = pos
        raw = strings[idx] + b"\x00"
        table.append(raw)
        pos += len(raw)
    str_table = b"".join(table)
    offset_data = bytearray(str_max * 2)
    for idx in range(str_max):
        struct.pack_into("<h", offset_data, idx * 2,
                         offsets.get(idx, _SENTINEL_ABSENT))
    magic = _TERMINFO_MAGIC2 if fmt == "<i" else _TERMINFO_MAGIC
    header = struct.pack("<6h", magic, len(names), bool_max, num_max,
                         str_max, len(str_table))
    padding = b"\x00" if (len(names) + bool_max) % 2 else b""
    return b"".join((header, names, bool_data, padding, bytes(num_data),
                     bytes(offset_data), str_table))


def sanitize_term_name(name):
    cleaned = re.sub(r'[^a-zA-Z0-9._-]', '', name)
    cleaned = cleaned.lstrip('.')
    return cleaned if cleaned else 'unknown'


def terminfo_file_path(term, base_dir):
    return base_dir / term[0] / term


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
        escaped = simple.get(ch)
        if escaped is None:
            escaped = '^' + chr(ord(ch) ^ 0x40) if ch < ' ' or ch == '\x7f' else ch
        result.append(escaped)
    return "".join(result)


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


def has_meaningful_caps(str_caps, num_caps, bool_caps):
    return bool(bool_caps or any(not cap.startswith('k') for cap in str_caps)
                or any(cap != 'colors' for cap in num_caps))


def generate_exports(verbose_enabled=False, force=False, termcap=False):
    global _VERBOSE
    _VERBOSE = verbose_enabled

    fd = open_tty()
    if fd is None:
        verbose("no terminal available")
        return []

    saved = set_cbreak(fd)
    try:
        winsize = get_winsize(fd)

        init_caps, init_answered = xtgettcap_query(fd, _INIT_XTGETTCAP_CAPS)

        exports = []

        if force or os.environ.get("TERM_PROGRAM") is None:
            xtversion = xtversion_query(fd)
            if xtversion:
                name, version = xtversion
                verbose(f"XTVERSION: {name} {version}")
                exports += env_exports(force, ("TERM_PROGRAM", name),
                                       ("TERM_PROGRAM_VERSION", version))
            else:
                verbose("XTVERSION not supported by this terminal")
        else:
            verbose("skipping XTVERSION (TERM_PROGRAM already set)")

        try:
            rgb_tc = int(init_caps.get("RGB", "").split("/", 1)[0]) == 8
        except ValueError:
            rgb_tc = False
        env_tc = os.environ.get("COLORTERM") in ("truecolor", "24bit")
        probe_tc = False
        if force or not (env_tc or rgb_tc):
            probe_tc = probe_truecolor(fd, _TTYSCAN_QUERY_TIMEOUT)
            if probe_tc:
                verbose("truecolor confirmed via DECRQSS")

        if (probe_tc or rgb_tc) and (
                force or os.environ.get("COLORTERM") != "truecolor"):
            exports.append("export COLORTERM=truecolor")

        size = detect_size(fd, winsize)
        if size:
            rows, cols, source = size
            if source != 'inband' and (rows < winsize[1] or cols < winsize[0]):
                verbose(
                    f"rejecting CPR size {rows}x{cols} "
                    f"(term reports {winsize[1]}x{winsize[0]})",
                )
            else:
                exports += size_exports(rows, cols, winsize, force)

        if not init_caps:
            verbose("XTGETTCAP not supported by this terminal")
            return exports

        tn_raw = init_caps.get("TN")
        if not tn_raw:
            verbose("no TN (terminal name) capability, cannot export further")
            return exports

        tn = 'wezterm' if tn_raw == 'WezTerm' else tn_raw
        exports += env_exports(force, ("TERM", tn), quote=str)

        terminfo_dir = ttyscan_terminfo_dir()
        safe_term = sanitize_term_name(tn)
        path = terminfo_file_path(safe_term, terminfo_dir)
        system_ti = has_terminfo(tn)
        local_ti = path.exists()

        if not (force or termcap) and (system_ti or local_ti):
            if not system_ti:
                exports += env_exports(force, ("TERMINFO", terminfo_dir), quote=str)
            verbose(f"XTGETTCAP supported, terminal: {tn}")
            verbose("terminfo already available in system database"
                    if system_ti else f"terminfo exists at {path}")
            return exports

        remaining = [cap for cap in _FULL_XTGETTCAP_CAPS
                     if cap not in _INIT_XTGETTCAP_CAPS]
        t0 = time.monotonic()
        full_caps, full_answered = xtgettcap_query(fd, remaining)
        elapsed_ms = int((time.monotonic() - t0) * 1000)
        check_xtgettcap_replies(init_answered, len(_INIT_XTGETTCAP_CAPS),
                                full_answered, len(remaining))

        full_caps.update(init_caps)
        classified = classify_caps(full_caps)
        str_caps = classified['str_caps']
        num_caps = classified['num_caps']
        bool_caps = classified['bool_caps']

        verbose(
            f"XTGETTCAP supported, terminal: {tn}; "
            f"received {len(full_caps)} caps "
            f"({len(bool_caps)} bool, {len(num_caps)} num, {len(str_caps)} str) "
            f"from {full_answered} of {len(remaining)} replies "
            f"in {elapsed_ms}ms",
        )

        if not has_meaningful_caps(str_caps, num_caps, bool_caps):
            verbose(
                "only bare-minimum capabilities (TN/colors/RGB), "
                "skipping TERMINFO/TERMCAP export",
            )
            return exports

        if force or not (system_ti or local_ti):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(build_terminfo_binary(
                safe_term, str_caps, num_caps, bool_caps))
            verbose(f"writing {path}")
        elif system_ti:
            verbose("terminfo already available in system database")
        else:
            verbose(f"terminfo exists at {path}")

        if force or not system_ti:
            exports += env_exports(force, ("TERMINFO", terminfo_dir), quote=str)

        if termcap:
            entry = build_termcap_entry(tn, str_caps, num_caps, bool_caps)
            if force or os.environ.get("TERMCAP") != entry:
                exports.append(f"export TERMCAP={shell_escape(entry)}")

        return exports

    finally:
        termios.tcflush(fd, termios.TCIFLUSH)
        restore_termios(fd, saved)
        os.close(fd)


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
    parser.add_argument(
        "--version", action="version",
        version=f"ttyscan {__version__}",
    )
    args = parser.parse_args(argv)

    try:
        exports = generate_exports(args.verbose, args.force, args.termcap)
    except NoCPRReply as exc:
        sys.exit(f"ttyscan: {exc} (is this an interactive terminal?)")

    for line in exports:
        print(line)


if __name__ == '__main__':
    main()
