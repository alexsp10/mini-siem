"""Command-line interface: ``minisiem ingest | detect | alerts | report | validate | run``."""

from __future__ import annotations

import argparse
import glob
import sys
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from .engine import run_rules
from .parsers import FORMATS, parse_file
from .report import render_report
from .rules import Rule, load_rules
from .schema import LEVELS, Alert, level_rank
from .storage import Store


class CliError(Exception):
    pass


def _expand(paths: Sequence[str]) -> list[Path]:
    """Expand files, directories (recursively) and glob patterns (Windows shells don't expand them)."""
    files: list[Path] = []
    for pattern in paths:
        matches = glob.glob(pattern, recursive=True) if any(c in pattern for c in "*?[") else [pattern]
        if not matches:
            raise CliError(f"no files match {pattern!r}")
        for match in matches:
            path = Path(match)
            if path.is_dir():
                files.extend(sorted(p for p in path.rglob("*") if p.is_file() and not p.name.startswith(".")))
            elif path.is_file():
                files.append(path)
            else:
                raise CliError(f"{match} does not exist")
    return files


def _table(headers: list[str], rows: list[list[str]], widths: list[int]) -> str:
    def cell(text: str, width: int) -> str:
        text = text.replace("\n", " ")
        return (text if len(text) <= width else text[: width - 3] + "...").ljust(width)

    lines = ["  ".join(cell(h, w) for h, w in zip(headers, widths, strict=True)).rstrip()]
    lines.append("  ".join("-" * w for w in widths))
    lines += ["  ".join(cell(c, w) for c, w in zip(row, widths, strict=True)).rstrip() for row in rows]
    return "\n".join(lines)


def _print_alerts(alerts: list[Alert]) -> None:
    if not alerts:
        print("No alerts.")
        return
    rows = [
        [
            a.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            a.level.upper(),
            a.title,
            ",".join(a.context("host.name", 2)) or "-",
            a.summary,
        ]
        for a in alerts
    ]
    print(_table(["TIME (UTC)", "LEVEL", "RULE", "HOST", "DETAILS"], rows, [19, 8, 44, 12, 70]))


def _load_rules_or_fail(path: str) -> list[Rule]:
    rules, errors = load_rules(path)
    if errors:
        for error in errors:
            print(f"rule error: {error}", file=sys.stderr)
        raise CliError(f"{len(errors)} rule error(s); fix them or run 'minisiem validate --rules {path}'")
    if not rules:
        raise CliError(f"no rules found in {path}")
    return rules


# ---------------------------------------------------------------------------- commands


def cmd_ingest(args: argparse.Namespace, store: Store) -> int:
    total_new = 0
    for file in _expand(args.paths):
        try:
            result = parse_file(file, args.format, year=args.year)
        except (OSError, ValueError) as exc:
            raise CliError(f"could not parse {file}: {exc}") from None
        new = store.add_events(result.events)
        total_new += new
        skipped = f", {result.skipped} skipped" if result.skipped else ""
        print(f"{file}: {len(result.events)} events ({result.format}), {new} new{skipped}")
    print(f"Ingested {total_new} new events into {store.path}")
    return 0


def cmd_detect(args: argparse.Namespace, store: Store) -> int:
    rules = _load_rules_or_fail(args.rules)
    events = store.load_events()
    alerts = run_rules(rules, events)
    store.replace_alerts(alerts)
    print(f"Ran {len(rules)} rules over {len(events)} events: {len(alerts)} alert(s)\n")
    _print_alerts(alerts)
    if args.fail_on and any(level_rank(a.level) >= level_rank(args.fail_on) for a in alerts):
        return 2
    return 0


def cmd_alerts(args: argparse.Namespace, store: Store) -> int:
    _print_alerts(store.load_alerts(args.level))
    return 0


def cmd_report(args: argparse.Namespace, store: Store) -> int:
    output = Path(args.output)
    output.write_text(render_report(store.stats(), store.load_alerts()), encoding="utf-8")
    print(f"Report written to {output.resolve()}")
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    rules, errors = load_rules(args.rules)
    for error in errors:
        print(f"ERROR {error}", file=sys.stderr)
    if rules:
        rows = [[r.id, r.level, r.kind, ", ".join(r.techniques)] for r in sorted(rules, key=lambda r: r.id)]
        print(_table(["RULE", "LEVEL", "KIND", "ATT&CK"], rows, [32, 9, 9, 40]))
    print(f"\n{len(rules)} valid rule(s), {len(errors)} error(s)")
    return 1 if errors or not rules else 0


def cmd_run(args: argparse.Namespace, store: Store) -> int:
    cmd_ingest(args, store)
    print()
    code = cmd_detect(args, store)
    print()
    cmd_report(args, store)
    return code


# ---------------------------------------------------------------------------- entry point


def build_parser() -> argparse.ArgumentParser:
    db = argparse.ArgumentParser(add_help=False)
    db.add_argument("--db", default="minisiem.db", help="SQLite database file (default: minisiem.db)")
    inputs = argparse.ArgumentParser(add_help=False)
    inputs.add_argument("paths", nargs="+", help="log files, directories or glob patterns")
    inputs.add_argument("--format", choices=FORMATS, default="auto", help="input format (default: auto-detect)")
    inputs.add_argument("--year", type=int, help="year for syslog timestamps that lack one (default: current)")
    rules = argparse.ArgumentParser(add_help=False)
    rules.add_argument("--rules", default="rules", help="rule file or directory (default: ./rules)")
    detect = argparse.ArgumentParser(add_help=False)
    detect.add_argument("--fail-on", choices=LEVELS, help="exit with status 2 if any alert is at least this level")
    report = argparse.ArgumentParser(add_help=False)
    report.add_argument("-o", "--output", default="report.html", help="HTML report path (default: report.html)")

    parser = argparse.ArgumentParser(
        prog="minisiem", description="Mini SIEM: ingest logs, run Sigma-style detection rules, report alerts."
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("ingest", parents=[db, inputs], help="parse logs and store normalised events")
    sub.add_parser("detect", parents=[db, rules, detect], help="run detection rules over stored events")
    alerts = sub.add_parser("alerts", parents=[db], help="list stored alerts")
    alerts.add_argument("--level", choices=LEVELS, help="only show alerts at or above this level")
    sub.add_parser("report", parents=[db, report], help="write the HTML dashboard")
    sub.add_parser("validate", parents=[rules], help="lint detection rules")
    run = sub.add_parser("run", parents=[db, inputs, rules, detect, report], help="ingest + detect + report")
    run.add_argument("--fresh", action="store_true", help="delete the database first")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "validate":
            return cmd_validate(args)
        if args.command == "run" and args.fresh:
            Path(args.db).unlink(missing_ok=True)
        with Store(args.db) as store:
            handler = {
                "ingest": cmd_ingest,
                "detect": cmd_detect,
                "alerts": cmd_alerts,
                "report": cmd_report,
                "run": cmd_run,
            }[args.command]
            return handler(args, store)
    except CliError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
