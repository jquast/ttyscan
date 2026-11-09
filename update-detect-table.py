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
    """Return the YAML runs in *data_dir*, each tagged with its file name."""
    runs = []
    for path in sorted(Path(data_dir).glob("*.yaml")):
        with path.open(encoding="utf-8") as handle:
            run = yaml.safe_load(handle)
        run["source_file"] = path.name
        runs.append(run)
    if not runs:
        raise SystemExit(f"update-detect-table: no YAML data in {data_dir}")
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
        raise SystemExit(f"update-detect-table: unparsable DA1 reply {raw!r}")
    params = [int(part) for part in match.group(2).split(";") if part.isdigit()]
    if not params:
        raise SystemExit(f"update-detect-table: empty DA1 reply {raw!r}")
    return match.group(1), params[0], tuple(sorted(params[1:]))


def load_width_table(data_dir, module, variable):
    path = Path(data_dir).resolve().parent / "ucs_detect" / (module + ".py")
    if not path.is_file():
        raise SystemExit(
            f"update-detect-table: missing {path}; "
            "--data-dir must point inside a ucs-detect checkout")
    spec = importlib.util.spec_from_file_location("_ttyscan_" + module, str(path))
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return getattr(loaded, variable)[0][1]


def select_runs(runs):
    """Return current-version runs and the names of the skipped ones."""
    usable, skipped = [], []
    for run in runs:
        version = run.get("wcwidth_version")
        if (version and version_key(version) >= (0, 8)
                and run.get("unicode_version")):
            usable.append(run)
        else:
            skipped.append((run.get("source_file", run.get("software_name")), version))
    return usable, skipped


def collect_measurements(runs):
    """Return failed widths, expected widths, probe categories, and test totals."""
    failed, expected, category = {}, {}, {}
    total = defaultdict(int)
    for run in runs:
        name = run["software_name"]
        version = run.get("wcwidth_version")
        for category_name, _, _ in CATEGORIES:
            results = (run.get("test_results") or {}).get(category_name) or {}
            for body in results.values():
                body = body or {}
                total[(name, category_name)] = max(
                    total[(name, category_name)], body.get("n_total") or 0)
                for record in body.get("failed_codepoints") or []:
                    grapheme = decode_wchar(record["wchar"])
                    failed[(name, grapheme)] = record["measured_by_terminal"]
                    category[grapheme] = category_name
                    width = expected.setdefault(
                        (version, grapheme), record["measured_by_wcwidth"])
                    if width != record["measured_by_wcwidth"]:
                        raise SystemExit(
                            "update-detect-table: wcwidth disagrees on "
                            f"{grapheme!r} in {version!r}: {width!r} vs "
                            f"{record['measured_by_wcwidth']!r}")
    return failed, expected, category, total


def load_width_ranks(data_dir):
    """Return each width table as a map from grapheme to its ranked index."""
    ranks = {}
    for category_name, module, variable in CATEGORIES:
        table = load_width_table(data_dir, module, variable)
        ranks[category_name] = {
            (chr(entry) if isinstance(entry, int) else entry): index
            for index, entry in enumerate(table)
        }
    return ranks


def build_row(run, probes, measured_width):
    """Return one quiz row for *run*, or ``None`` when it is excluded."""
    name = run["software_name"]
    if name in EXCLUDE:
        print(f"excluding {name}", file=sys.stderr)
        return None
    version = run.get("wcwidth_version")
    values = {}
    for grapheme in probes:
        if not usable_probe(grapheme):
            continue
        width = measured_width(name, grapheme, version)
        if width is not None:
            values[grapheme] = width
    results = run.get("terminal_results") or {}
    return {
        "name": name,
        "da1": parse_da1((results.get("device_attributes") or {}).get("raw") or ""),
        "values": values,
        "primary": not (results.get("software_method") in ("XTVERSION", "ENQ")
                        or unique_tn(run)),
    }


def build_rows(runs, data_dir):
    """Return one row per terminal with the probe widths that were measured for it."""
    usable, skipped = select_runs(runs)
    unicode_versions = {run.get("unicode_version") for run in usable}
    if len(unicode_versions) != 1:
        raise SystemExit(
            "update-detect-table: mixed Unicode versions "
            f"{sorted(unicode_versions)!r}")

    failed, expected, category, total = collect_measurements(usable)
    width_ranks = load_width_ranks(data_dir)

    def measured_width(name, grapheme, version):
        if (name, grapheme) in failed:
            return failed[(name, grapheme)]
        kind = category.get(grapheme)
        rank = width_ranks.get(kind, {}).get(grapheme)
        if rank is None or rank >= total.get((name, kind), 0):
            return None
        return expected.get((version, grapheme))

    rows = [build_row(run, category, measured_width) for run in usable]
    rows = [row for row in rows if row is not None]
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


def da1_pairs(rows):
    """Return index pairs of terminals sharing a DA1 reply signature."""
    groups = defaultdict(list)
    for index, row in enumerate(rows):
        groups[row["da1"]].append(index)
    pairs = []
    for members in groups.values():
        pairs.extend(itertools.combinations(members, 2))
    return pairs


def choose_probes(rows):
    """Cover every pair of same DA1 terminals with the fewest measured probes."""
    remaining = da1_pairs(rows)
    candidates = {grapheme for row in rows for grapheme in row["values"]}
    order, unseparated = [], []
    while remaining:
        best = (None, None, [])
        for grapheme in candidates:
            covered = [(a, b) for a, b in remaining
                       if grapheme in rows[a]["values"]
                       and grapheme in rows[b]["values"]
                       and rows[a]["values"][grapheme] != rows[b]["values"][grapheme]]
            if not covered:
                continue
            emoji = 0 if len(grapheme) > 1 else 1
            score = (len(covered), -emoji, len(grapheme), grapheme)
            if best[0] is None or score > best[0]:
                best = (score, grapheme, covered)
        if best[0] is None:
            unseparated = [(rows[a]["name"], rows[b]["name"]) for a, b in remaining]
            break
        _, grapheme, covered = best
        order.append(grapheme)
        done = set(covered)
        remaining = [pair for pair in remaining if pair not in done]
    return order, unseparated


def prune_shadows(rows):
    """Drop rows that only make a measurable terminal ambiguous."""
    groups = {row["da1"] for row in rows if row["primary"]}
    selected = [row for row in rows
                if row["primary"] or row["da1"] in groups]
    while True:
        _, unseparated = choose_probes(selected)
        by_name = {row["name"]: row for row in selected}
        drop = set()
        for first, second in unseparated:
            pair = ((first, by_name[first]), (second, by_name[second]))
            if all(row["primary"] for _, row in pair):
                continue
            drop.update(name for name, row in pair if not row["primary"])
        if not drop:
            return selected
        selected = [row for row in selected if row["name"] not in drop]


def source_note(data_dir, runs, probe_count, terminal_count):
    """Return the generated-block header naming the data commit and counts."""
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
    return (f"ucs-detect data @ {commit}{dirty}: {len(runs)} runs, "
            f"{terminal_count} terminals, {probe_count} probes")


def render_block(rows, probes, note):
    """Return the generated block text for *rows*, *probes*, and *note*."""
    lines = [
        START,
        "# " + note,
        "TERM_PROBES = (",
    ]
    for probe in probes:
        lines.append(f"    {ascii(probe)},")
    lines.extend([
        ")",
        "",
        "TERM_QUIZ = (",
    ])
    for row in sorted(rows, key=lambda item: (item["da1"], item["name"])):
        widths = {index: row["values"][probe]
                  for index, probe in enumerate(probes) if probe in row["values"]}
        inner = ", ".join(f"{index}: {widths[index]}" for index in sorted(widths))
        lines.append(f"    TerminalProfile({ascii(row['name'])},")
        lines.append(f"                    {row['da1']!r}, {{{inner}}}),")
    lines.append(")")
    lines.append(END)
    return "\n".join(lines)


def replace_block(text, block):
    start = text.index(START)
    end = text.index(END, start) + len(END)
    return text[:start] + block + text[end:]


def main(argv=None):
    """Regenerate or check the embedded quiz block and return an exit status."""
    parser = argparse.ArgumentParser(
        prog="update-detect-table.py",
        description="Regenerate the terminal quiz embedded in ttyscan.py",
    )
    parser.add_argument("--data-dir", type=Path, default=DEFAULT_DATA,
                        help=f"ucs-detect data directory (default: {DEFAULT_DATA})")
    parser.add_argument("--target", type=Path, default=DEFAULT_TARGET,
                        help=f"file holding the generated block (default: {DEFAULT_TARGET})")
    parser.add_argument("--check", action="store_true",
                        help="fail if the block is out of date")
    args = parser.parse_args(argv)

    runs = load_runs(args.data_dir)
    rows, skipped, expected = build_rows(runs, args.data_dir)
    for filename, version in skipped:
        print(f"skipping {filename}: wcwidth {version}", file=sys.stderr)
    probes, unseparated = choose_probes(rows)
    if unseparated:
        print(f"warning: cannot separate {unseparated!r}", file=sys.stderr)
    note = source_note(args.data_dir,
                       [run for run in runs
                        if run.get("source_file") not in {name for name, _ in skipped}],
                       len(probes), len(rows))
    block = render_block(rows, probes, note)

    text = args.target.read_text(encoding="utf-8")
    updated = replace_block(text, block)
    if args.check:
        if updated != text:
            print(f"{args.target} is out of date; run {sys.argv[0]}",
                  file=sys.stderr)
            return 1
        return 0
    args.target.write_text(updated, encoding="utf-8")
    print(f"updated {args.target}: {len(rows)} terminals, {len(probes)} probes, "
          f"{len(expected)} graphemes")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
