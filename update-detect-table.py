#!/usr/bin/env python3
"""Generate the terminal quiz table embedded in ttyscan.py from ucs-detect data."""

import argparse
import codecs
import importlib.util
import itertools
import re
import subprocess
import sys
import unicodedata
from collections import Counter, defaultdict
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.exit("update-detect-table: PyYAML is required")

CATEGORIES = (
    ("narrow_results", "table_narrow", "NARROW_CHARACTERS"),
    ("emoji_zwj_results", "table_zwj", "EMOJI_ZWJ_SEQUENCES"),
    ("sri_results", "table_sri", "STANDALONE_REGIONAL_INDICATORS"),
)

# Multiplexers can relay host DA1 and widths, and so are unreliable for this purpose
EXCLUDE = frozenset({"GNU Screen", "tmux", "Zellij"})

START = "# BEGIN GENERATED TERMINAL QUIZ: update-detect-table.py"
END = "# END GENERATED TERMINAL QUIZ"

ROOT = Path(__file__).resolve().parent
DEFAULT_DATA = ROOT.parent / "ucs-detect" / "data"
DEFAULT_TARGET = ROOT / "ttyscan.py"


def version_key(value):
    return tuple(int(part) for part in str(value).split(".") if part.isdigit())


def decode_wchar(value):
    try:
        return codecs.decode(value.encode("latin-1"), "unicode_escape")
    except UnicodeEncodeError:
        return value


def load_runs(data_dir):
    runs = []
    for path in sorted(Path(data_dir).glob("*.yaml")):
        with path.open(encoding="utf-8") as handle:
            run = yaml.safe_load(handle)
        run["_file"] = path.name
        runs.append(run)
    if not runs:
        raise SystemExit("update-detect-table: no YAML data in %s" % data_dir)
    return runs


def majority_version(runs):
    counts = Counter(run.get("wcwidth_version") for run in runs
                     if run.get("wcwidth_version"))
    if not counts:
        raise SystemExit("update-detect-table: no wcwidth_version in the data")
    return max(counts, key=lambda value: (counts[value], version_key(value)))


def unique_tn(run):
    results = run.get("terminal_results") or {}
    capabilities = (results.get("xtgettcap") or {}).get("capabilities") or {}
    name = capabilities.get("TN", "")
    return bool(name) and name.lower() not in ("xterm", "xterm-256color", "unknown")


def parse_da1(raw):
    match = re.fullmatch(r"\x1b\[(\??)([0-9;]*)c", raw or "")
    if match is None:
        raise SystemExit("update-detect-table: unparsable DA1 reply %r" % (raw,))
    params = [int(part) for part in match.group(2).split(";") if part.isdigit()]
    if not params:
        raise SystemExit("update-detect-table: empty DA1 reply %r" % (raw,))
    return match.group(1), params[0], tuple(sorted(params[1:]))


def load_width_table(data_dir, module, variable):
    path = Path(data_dir).resolve().parent / "ucs_detect" / (module + ".py")
    if not path.is_file():
        raise SystemExit("update-detect-table: missing %s; --data-dir must point "
                         "inside a ucs-detect checkout" % path)
    spec = importlib.util.spec_from_file_location("_ttyscan_" + module, str(path))
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return getattr(loaded, variable)[0][1]


def build_rows(runs, data_dir):
    """Return one row per terminal with the probe widths that were measured for it."""
    usable, skipped = [], []
    for run in runs:
        version = run.get("wcwidth_version")
        if (version and version_key(version) >= (0, 8)
                and run.get("unicode_version")):
            usable.append(run)
        else:
            skipped.append((run.get("_file", run.get("software_name")), version))
    unicode_versions = {run.get("unicode_version") for run in usable}
    if len(unicode_versions) != 1:
        raise SystemExit("update-detect-table: mixed Unicode versions %r"
                         % (sorted(unicode_versions),))

    failed, expected, category, total = {}, {}, {}, defaultdict(int)
    for run in usable:
        name = run["software_name"]
        version = run.get("wcwidth_version")
        for category_name, _module, _variable in CATEGORIES:
            for body in ((run.get("test_results") or {}).get(category_name) or {}).values():
                total[(name, category_name)] = max(
                    total[(name, category_name)], (body or {}).get("n_total") or 0)
                for record in (body or {}).get("failed_codepoints") or []:
                    grapheme = decode_wchar(record["wchar"])
                    failed[(name, grapheme)] = record["measured_by_terminal"]
                    category[grapheme] = category_name
                    width = expected.setdefault(
                        (version, grapheme), record["measured_by_wcwidth"])
                    if width != record["measured_by_wcwidth"]:
                        raise SystemExit(
                            "update-detect-table: wcwidth disagrees on %r in %r: %r vs %r"
                            % (grapheme, version, width,
                               record["measured_by_wcwidth"]))

    width_ranks = {}
    for category_name, module, variable in CATEGORIES:
        table = load_width_table(data_dir, module, variable)
        width_ranks[category_name] = {
            (chr(entry) if isinstance(entry, int) else entry): index
            for index, entry in enumerate(table)
        }

    def measured_width(name, grapheme, version):
        if (name, grapheme) in failed:
            return failed[(name, grapheme)]
        kind = category.get(grapheme)
        rank = width_ranks.get(kind, {}).get(grapheme)
        if rank is None or rank >= total.get((name, kind), 0):
            return None
        return expected.get((version, grapheme))

    rows = []
    for run in usable:
        results = run.get("terminal_results") or {}
        name = run["software_name"]
        if name in EXCLUDE:
            print("excluding %s" % name, file=sys.stderr)
            continue
        version = run.get("wcwidth_version")
        values = {}
        for grapheme in category:
            if not usable_probe(grapheme):
                continue
            width = measured_width(name, grapheme, version)
            if width is not None:
                values[grapheme] = width
        rows.append({
            "name": name,
            "da1": parse_da1((results.get("device_attributes") or {}).get("raw") or ""),
            "values": values,
            "primary": not (results.get("software_method") in ("XTVERSION", "ENQ")
                            or unique_tn(run)),
        })
    if len({row["name"] for row in rows}) != len(rows):
        raise SystemExit("update-detect-table: duplicate terminal name")
    return prune_shadows(rows), skipped, expected


def usable_probe(grapheme):
    """Reject new codepoints, context-sensitive marks and ambiguous widths."""
    for char in grapheme:
        codepoint = ord(char)
        if codepoint <= 0x1F9FF or codepoint in (0x200D, 0xFE0F):
            continue
        if 0x1FAF0 <= codepoint <= 0x1FAFF:
            continue
        return False
    if len(grapheme) == 1:
        if unicodedata.category(grapheme) in ("Mn", "Me", "Cf", "Zs"):
            return False
        if unicodedata.east_asian_width(grapheme) == "A":
            return False
    return True


def choose_probes(rows):
    """Cover every pair of same DA1 terminals with the fewest measured probes."""
    groups = defaultdict(list)
    for index, row in enumerate(rows):
        groups[row["da1"]].append(index)
    remaining = []
    for members in groups.values():
        remaining.extend(itertools.combinations(members, 2))

    candidates = {grapheme for row in rows for grapheme in row["values"]}
    order, unseparated = [], []
    while remaining:
        best = None
        for grapheme in candidates:
            covered = [(a, b) for a, b in remaining
                       if grapheme in rows[a]["values"] and grapheme in rows[b]["values"]
                       and rows[a]["values"][grapheme] != rows[b]["values"][grapheme]]
            if not covered:
                continue
            emoji = 0 if len(grapheme) > 1 else 1
            score = (len(covered), -emoji, len(grapheme), grapheme)
            if best is None or score > best[0]:
                best = (score, grapheme, covered)
        if best is None:
            unseparated = [(rows[a]["name"], rows[b]["name"]) for a, b in remaining]
            break
        _, grapheme, covered = best
        order.append(grapheme)
        done = set(covered)
        remaining = [pair for pair in remaining if pair not in done]
    return order, unseparated


def prune_shadows(rows):
    """Drop rows that only make a measurable terminal ambiguous.

    A terminal that normally identifies itself is useful in the quiz only when
    probes separate it from every measurable terminal that shares its DA1.
    """
    groups = {row["da1"] for row in rows if row["primary"]}
    selected = [row for row in rows
                if row["primary"] or row["da1"] in groups]
    while True:
        _probes, unseparated = choose_probes(selected)
        by_name = {row["name"]: row for row in selected}
        drop = set()
        for first, second in unseparated:
            pair = ((first, by_name[first]), (second, by_name[second]))
            if all(row["primary"] for _name, row in pair):
                continue
            drop.update(name for name, row in pair if not row["primary"])
        if not drop:
            return selected
        selected = [row for row in selected if row["name"] not in drop]


def source_note(data_dir, runs, probe_count, terminal_count):
    commit, dirty = "unversioned", ""
    try:
        commit = subprocess.check_output(
            ["git", "-C", str(data_dir), "rev-parse", "--short", "HEAD"],
            universal_newlines=True, stderr=subprocess.DEVNULL).strip()
        status = subprocess.check_output(
            ["git", "-C", str(data_dir), "status", "--porcelain", "--", "."],
            universal_newlines=True, stderr=subprocess.DEVNULL)
        if status.strip():
            dirty = ", working tree modified"
    except (OSError, subprocess.CalledProcessError):
        pass
    return "ucs-detect data @ %s%s: %d runs, %d terminals, %d probes" % (
        commit, dirty, len(runs), terminal_count, probe_count)


def render_block(rows, probes, note):
    lines = [
        START,
        "# " + note,
        "_TERM_PROBES = (",
    ]
    for probe in probes:
        lines.append("    %s," % ascii(probe))
    lines.extend([
        ")",
        "",
        "_TERM_QUIZ = (",
    ])
    for row in sorted(rows, key=lambda item: (item["da1"], item["name"])):
        widths = {index: row["values"][probe]
                  for index, probe in enumerate(probes) if probe in row["values"]}
        inner = ", ".join("%d: %d" % (index, widths[index]) for index in sorted(widths))
        lines.append("    (%r," % (row["da1"],))
        lines.append("     %s, {%s})," % (ascii(row["name"]), inner))
    lines.append(")")
    lines.append(END)
    return "\n".join(lines)


def replace_block(text, block):
    start = text.index(START)
    end = text.index(END, start) + len(END)
    return text[:start] + block + text[end:]


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="update-detect-table.py",
        description="Regenerate the terminal quiz embedded in ttyscan.py",
    )
    parser.add_argument("--data-dir", type=Path, default=DEFAULT_DATA,
                        help="ucs-detect data directory (default: %(default)s)")
    parser.add_argument("--target", type=Path, default=DEFAULT_TARGET,
                        help="file holding the generated block (default: %(default)s)")
    parser.add_argument("--check", action="store_true",
                        help="fail if the block is out of date")
    args = parser.parse_args(argv)

    runs = load_runs(args.data_dir)
    rows, skipped, expected = build_rows(runs, args.data_dir)
    for filename, version in skipped:
        print("skipping %s: wcwidth %s" % (filename, version), file=sys.stderr)
    probes, unseparated = choose_probes(rows)
    if unseparated:
        print("warning: cannot separate %r" % (unseparated,), file=sys.stderr)
    note = source_note(args.data_dir,
                       [run for run in runs
                        if run.get("_file") not in {name for name, _ in skipped}],
                       len(probes), len(rows))
    block = render_block(rows, probes, note)

    text = args.target.read_text(encoding="utf-8")
    updated = replace_block(text, block)
    if args.check:
        if updated != text:
            print("%s is out of date; run %s" % (args.target, sys.argv[0]),
                  file=sys.stderr)
            return 1
        return 0
    args.target.write_text(updated, encoding="utf-8")
    print("updated %s: %d terminals, %d probes, %d graphemes"
          % (args.target, len(rows), len(probes), len(expected)))
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
