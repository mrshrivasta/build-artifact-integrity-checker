#!/usr/bin/env python3
"""
Build Artifact Integrity Checker — Command Line Interface
Developed by Karanam Shrivasta
GitHub: https://github.com/mrshrivasta | LinkedIn: https://www.linkedin.com/in/karanam-shrivasta

DISCLAIMER: Computes REAL SHA-256 hashes of real files on this machine.
Only run against paths you own or are authorized to assess. Provided AS IS,
no warranty. See README.md for the full disclaimer.

BASELINE CACHE: the CLI has no web session/database, so it keeps its own
real local baseline cache file — by default `.bai_baseline.json` written in
the current working directory — keyed by the absolute target path. The
FIRST time you scan a given path, that scan's real sha256/size/mtime
snapshot is written into the cache (BAI-005, no diff possible yet). Every
SUBSEQUENT scan of the SAME absolute path reads that cached snapshot back
out, diffs it against the new real scan, reports BAI-001..004/006 findings,
and then overwrites the cache entry with the new snapshot so the next run
diffs against this one. Use --baseline-file to point at a different cache
location (e.g. to keep a dedicated cache per CI job).

Usage:
    python3 cli/main.py scan ./dist --depth 4
    python3 cli/main.py scan ./dist                 # first run: establishes baseline (BAI-005)
    python3 cli/main.py scan ./dist                 # second run: diffs against the cached baseline
    python3 cli/main.py scan ./dist --json
    python3 cli/main.py scan ./dist --csv out.csv
    python3 cli/main.py scan ./dist --baseline-file /tmp/ci-baseline.json
    python3 cli/main.py rules
"""
import argparse
import csv
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.security_engine import ScanEngine
from app.detection_rules import ALL_RULES

BANNER = """\
==============================================================
 Build Artifact Integrity Checker (CLI)
 Developed by Karanam Shrivasta
 GitHub:   https://github.com/mrshrivasta
 LinkedIn: https://www.linkedin.com/in/karanam-shrivasta
 DISCLAIMER: Authorized use only. Provided AS IS, no warranty.
==============================================================\
"""

SEVERITY_COLOR = {
    "critical": "\033[95m",
    "high": "\033[91m",
    "medium": "\033[93m",
    "low": "\033[92m",
}
RESET = "\033[0m"

DEFAULT_BASELINE_FILE = ".bai_baseline.json"


def _load_baseline_cache(baseline_file):
    """Real local JSON cache: {absolute_target_path: {relative_path: {sha256, size, mtime}}}."""
    if not os.path.exists(baseline_file):
        return {}
    try:
        with open(baseline_file, "r") as fh:
            return json.load(fh)
    except (json.JSONDecodeError, OSError):
        return {}


def _save_baseline_cache(baseline_file, cache):
    with open(baseline_file, "w") as fh:
        json.dump(cache, fh, indent=2)


def cmd_scan(args):
    print(BANNER)
    abs_target = os.path.abspath(args.path)
    print(f"Scanning: {abs_target}  (max depth {args.depth}, max files {args.max_files})")
    print(f"Baseline cache: {os.path.abspath(args.baseline_file)}\n")

    cache = _load_baseline_cache(args.baseline_file)
    previous_snapshot = cache.get(abs_target)  # None on the very first scan of this path

    engine = ScanEngine(
        abs_target,
        previous_snapshot=previous_snapshot,
        max_depth=args.depth,
        excludes=args.exclude.split(",") if args.exclude else None,
        max_files=args.max_files,
    )
    result = engine.run()

    # Persist the new real snapshot as the baseline for the NEXT run of this path.
    cache[abs_target] = result["snapshot"]
    _save_baseline_cache(args.baseline_file, cache)

    if args.json:
        print(json.dumps(result, indent=2, default=str))
        if result["findings"] and any(f["rule_id"] != "BAI-005" for f in result["findings"]):
            sys.exit(1)
        sys.exit(0)

    print(f"Files scanned : {result['files_scanned']}")
    print(f"Dirs scanned  : {result['dirs_scanned']}")
    print(f"Errors        : {result['errors_count']}")
    print(f"Elapsed       : {result['elapsed_seconds']}s")
    print(f"Findings      : {len(result['findings'])}\n")

    for f in result["findings"]:
        color = SEVERITY_COLOR.get(f["severity"], "")
        print(f"{color}[{f['severity'].upper():8}]{RESET} {f['rule_id']} {f['rule_name']}")
        print(f"           path: {f['file_path']}")
        print(f"           hash: {f['permissions_octal']}")
        print(f"           {f['description']}\n")

    if args.csv:
        with open(args.csv, "w", newline="") as fh:
            writer = csv.writer(fh)
            writer.writerow(["rule_id", "rule_name", "severity", "file_path", "hash_compare", "description"])
            for f in result["findings"]:
                writer.writerow([f["rule_id"], f["rule_name"], f["severity"], f["file_path"], f["permissions_octal"], f["description"]])
        print(f"CSV report written to {args.csv}")

    # Non-BAI-005 findings represent real drift since the last cached baseline.
    actionable = [f for f in result["findings"] if f["rule_id"] != "BAI-005"]
    if actionable:
        sys.exit(1)  # non-zero exit for CI pipelines when integrity issues are found
    sys.exit(0)


def cmd_rules(args):
    print(BANNER)
    print("Detection rules:\n")
    for rule in ALL_RULES:
        doc = (rule.__doc__ or "").strip().split("\n")[0]
        print(f" - {rule.__name__}: {doc}")


def build_parser():
    parser = argparse.ArgumentParser(
        prog="bai-cli",
        description="Build Artifact Integrity Checker — real SHA-256 build-output hash diffing (by Karanam Shrivasta).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser("scan", help="Scan a real build-output directory and diff it against the last cached baseline")
    scan_p.add_argument("path", help="Build-output directory to scan (e.g. ./dist)")
    scan_p.add_argument("--depth", type=int, default=12, help="Max recursion depth (default 12)")
    scan_p.add_argument("--max-files", type=int, default=20000, dest="max_files", help="Safety cap on files scanned")
    scan_p.add_argument("--exclude", type=str, default="", help="Comma-separated path prefixes to exclude")
    scan_p.add_argument("--json", action="store_true", help="Output raw JSON")
    scan_p.add_argument("--csv", type=str, default=None, help="Write findings to a CSV file")
    scan_p.add_argument(
        "--baseline-file", type=str, default=DEFAULT_BASELINE_FILE, dest="baseline_file",
        help=(
            "Path to the local JSON baseline cache file used to remember the previous scan's "
            "real hash snapshot for each target path across separate CLI runs "
            f"(default: ./{DEFAULT_BASELINE_FILE} in the current directory)."
        ),
    )
    scan_p.set_defaults(func=cmd_scan)

    rules_p = sub.add_parser("rules", help="List all detection rules")
    rules_p.set_defaults(func=cmd_rules)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
