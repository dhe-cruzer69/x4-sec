from __future__ import annotations
import json
from .scanner import Finding

def to_sarif(findings: list[Finding]) -> str:
    results = [{
        "ruleId": f.rule,
        "level": {"CRITICAL":"error","HIGH":"error","MEDIUM":"warning","LOW":"note"}.get(f.severity,"warning"),
        "message": {"text": f.message},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.file}, "region": {"startLine": f.line}}}],
    } for f in findings]
    return json.dumps({"$schema":"https://json.schemastore.org/sarif-2.1.0.json","version":"2.1.0",
        "runs":[{"tool":{"driver":{"name":"x4-sec","version":"0.1.0"}},"results":results}]}, indent=2)+"\n"
