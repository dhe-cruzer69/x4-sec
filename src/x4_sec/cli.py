from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .rules import all_rules
from .sarif import to_sarif
from .scanner import scan_path

SEVERITY_ORDER = {"none": -1, "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _print_human(findings: list) -> None:
    if not findings:
        print("No findings.")
        return
    for f in findings:
        print(f"{f.severity:8} {f.file}:{f.line}  [{f.rule}]  {f.message}")
        print(f"         → {f.remediation}")
    print(f"\nfindings={len(findings)}")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="x4-sec",
        description="Security scanner for AI-agent, MCP, skills, and hooks",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    scan = sub.add_parser("scan", help="Scan a path or config")
    scan.add_argument("path", nargs="?", default=".", help="Root path (default: .)")
    scan.add_argument("--mcp", metavar="FILE", help="Focus on MCP config")
    scan.add_argument("--skills", metavar="DIR", help="Focus on skills directory")
    scan.add_argument("--agent", metavar="FILE", help="Focus on agent definition")
    scan.add_argument("--json", action="store_true", help="JSON output")
    scan.add_argument("--sarif", metavar="FILE", help="Write SARIF 2.1.0")
    scan.add_argument(
        "--fail-on",
        choices=["none", "low", "medium", "high", "critical"],
        default="critical",
        help="Exit 1 if findings at or above this severity (default: critical)",
    )

    sub.add_parser("rules", help="List rule IDs")

    args = p.parse_args(argv)

    if args.cmd == "rules":
        for r in all_rules():
            print(f"{r['id']:16} {r['severity']:8} {r['category']:18} {r['message']}")
        return 0

    if args.cmd == "scan":
        mode = "all"
        root = Path(args.path)
        if args.mcp:
            mode = "mcp"
            root = Path(args.mcp).parent if Path(args.mcp).is_file() else Path(args.mcp)
        elif args.skills:
            mode = "skills"
            root = Path(args.skills)
        elif args.agent:
            mode = "agent"
            root = Path(args.agent).parent if Path(args.agent).is_file() else Path(args.agent)

        if not root.exists():
            print(f"error: path not found: {root}", file=sys.stderr)
            return 2

        findings = scan_path(root, mode=mode)

        if args.json:
            print(json.dumps([f.to_dict() for f in findings], indent=2))
        else:
            _print_human(findings)

        if args.sarif:
            Path(args.sarif).write_text(to_sarif(findings), encoding="utf-8")
            print(f"sarif written: {args.sarif}", file=sys.stderr)

        threshold = SEVERITY_ORDER[args.fail_on]
        if threshold >= 0:
            for f in findings:
                if SEVERITY_ORDER.get(f.severity.lower(), 0) >= threshold:
                    return 1
        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
