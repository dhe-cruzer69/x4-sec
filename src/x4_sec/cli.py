from __future__ import annotations
import argparse, json
from pathlib import Path
from .scanner import scan_path
from .sarif import to_sarif

def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="x4-sec")
    p.add_argument("path", nargs="?", default=".")
    p.add_argument("--json", action="store_true")
    p.add_argument("--sarif")
    p.add_argument("--fail-on", choices=["none","low","medium","high","critical"], default="critical")
    a = p.parse_args(argv)
    findings = scan_path(Path(a.path))
    if a.json: print(json.dumps([f.__dict__ for f in findings], indent=2))
    else:
        for f in findings: print(f"{f.severity:8} {f.file}:{f.line}  {f.rule}  {f.message}")
        print(f"findings={len(findings)}")
    if a.sarif: Path(a.sarif).write_text(to_sarif(findings))
    order = {"none":-1,"low":0,"medium":1,"high":2,"critical":3}
    th = order[a.fail_on]
    if any(order.get(f.severity.lower(),0) >= th and th >= 0 for f in findings): return 1
    return 0

if __name__ == "__main__": raise SystemExit(main())
