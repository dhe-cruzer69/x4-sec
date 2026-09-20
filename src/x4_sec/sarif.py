from __future__ import annotations

import json
from typing import Any

from .models import Finding

LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
}


def to_sarif(findings: list[Finding], tool_name: str = "x4-sec", version: str = "0.1.0") -> str:
    results: list[dict[str, Any]] = []
    for f in findings:
        results.append(
            {
                "ruleId": f.rule,
                "level": LEVEL.get(f.severity, "warning"),
                "message": {"text": f"{f.message} — {f.remediation}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.file},
                            "region": {"startLine": max(1, f.line)},
                        }
                    }
                ],
                "properties": {
                    "category": f.category,
                    "confidence": f.confidence,
                    "severity": f.severity,
                },
            }
        )
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": version,
                        "informationUri": "https://github.com/dhe-cruzer69/x4-sec",
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(doc, indent=2) + "\n"
