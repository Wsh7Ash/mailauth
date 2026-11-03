"""Command line interface: ``mailauth check|stats|explain``.

Exit codes
----------
0  no contract errors
1  at least one contract error
2  usage error or unreadable file
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .contract import RULE_CATALOGUE, analyse, render_text, section_table, to_json

DEFAULT_TARGET = "SKILL.md"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _cmd_check(args: argparse.Namespace) -> int:
    path = Path(args.path)
    report = analyse(_read(path), str(path))
    if args.json:
        print(to_json(report))
    elif not args.quiet:
        print(render_text(report))
    return 0 if report.ok else 1


def _cmd_stats(args: argparse.Namespace) -> int:
    path = Path(args.path)
    report = analyse(_read(path), str(path))
    if args.json:
        print(to_json(report))
        return 0 if report.ok else 1
    print(f"{'sec':<4}{'words':>7}{'floor':>7}  title")
    for row in section_table(_read(path)):
        mark = " " if row["ok"] else "!"
        print(f"{mark}{row['letter']:<3}{row['words']:>7}{row['floor']:>7}  {row['title']}")
    print(f"\ntotal body words: {report.total_words}")
    return 0 if report.ok else 1


def _cmd_explain(args: argparse.Namespace) -> int:
    print("rule   meaning")
    for rule, meaning in RULE_CATALOGUE.items():
        print(f"{rule:<7}{meaning}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mailauth",
        description="Check a single-file cybersecurity skill against the A..P contract.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser("check", help="validate a SKILL.md against the contract")
    check.add_argument("path", nargs="?", default=DEFAULT_TARGET)
    check.add_argument("--json", action="store_true", help="emit a JSON report")
    check.add_argument("--quiet", action="store_true", help="print nothing on success")
    check.set_defaults(func=_cmd_check)

    stats = sub.add_parser("stats", help="show per-section word counts")
    stats.add_argument("path", nargs="?", default=DEFAULT_TARGET)
    stats.add_argument("--json", action="store_true")
    stats.set_defaults(func=_cmd_stats)

    explain = sub.add_parser("explain", help="list every rule id and its meaning")
    explain.set_defaults(func=_cmd_explain)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except FileNotFoundError as exc:
        print(f"error: cannot read {exc.filename}", file=sys.stderr)
        return 2
    except UnicodeDecodeError as exc:
        print(f"error: file is not valid UTF-8: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
