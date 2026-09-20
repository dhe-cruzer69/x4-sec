from __future__ import annotations
import re
from dataclasses import dataclass
from pathlib import Path

@dataclass
class Finding:
    severity: str; rule: str; file: str; line: int
    message: str; confidence: float; remediation: str

RULES = [
    {"id":"X4-CRED-001","severity":"CRITICAL","pattern":re.compile(r"curl\s+[^|\n]*\|\s*(ba)?sh",re.I),
     "message":"Pipe-to-shell","remediation":"Remove curl|sh","confidence":0.95},
    {"id":"X4-PROMPT-001","severity":"HIGH","pattern":re.compile(r"ignore\s+(all\s+)?previous\s+instructions",re.I),
     "message":"Prompt-injection phrase","remediation":"Sanitize","confidence":0.9},
    {"id":"X4-SECRET-001","severity":"HIGH","pattern":re.compile(r"(sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16})"),
     "message":"Credential-shaped token","remediation":"Rotate; store outside VCS","confidence":0.85},
]
GLOBS = ["**/.claude/**","**/.cursor/**","**/mcp.json","**/mcp.yaml","**/SKILL.md","**/CLAUDE.md","**/*.sh","**/Dockerfile"]

def scan_path(root: Path) -> list[Finding]:
    root = root.resolve(); files=set(); findings=[]
    for g in GLOBS: files.update(root.glob(g))
    for path in sorted(files):
        if not path.is_file(): continue
        try: text = path.read_text(encoding="utf-8", errors="replace")
        except OSError: continue
        for i, line in enumerate(text.splitlines(), 1):
            for rule in RULES:
                if rule["pattern"].search(line):
                    findings.append(Finding(rule["severity"], rule["id"], str(path.relative_to(root)), i,
                                            rule["message"], rule["confidence"], rule["remediation"]))
    return findings
