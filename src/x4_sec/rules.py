from __future__ import annotations

import re
from typing import Pattern

# Each rule: id, severity, category, pattern, message, remediation, confidence
RULE_DEFS: list[dict] = [
    {
        "id": "X4-CRED-001",
        "severity": "CRITICAL",
        "category": "dangerous-shell",
        "pattern": re.compile(r"curl\s+[^|\n]*\|\s*(?:ba)?sh", re.I),
        "message": "Pipe-to-shell (curl | bash)",
        "remediation": "Download, verify checksum, then execute explicitly",
        "confidence": 0.95,
    },
    {
        "id": "X4-CRED-002",
        "severity": "CRITICAL",
        "category": "dangerous-shell",
        "pattern": re.compile(r"wget\s+[^|\n]*\|\s*(?:ba)?sh", re.I),
        "message": "Pipe-to-shell (wget | sh)",
        "remediation": "Download and verify before execution",
        "confidence": 0.95,
    },
    {
        "id": "X4-SECRET-001",
        "severity": "HIGH",
        "category": "secrets",
        "pattern": re.compile(
            r"(sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{36,}|gho_[A-Za-z0-9]{36,}"
            r"|AKIA[0-9A-Z]{16}|-----BEGIN (?:RSA |EC )?PRIVATE KEY-----)"
        ),
        "message": "Credential-shaped token or private key",
        "remediation": "Rotate immediately; store outside VCS; use secret manager",
        "confidence": 0.9,
    },
    {
        "id": "X4-PROMPT-001",
        "severity": "HIGH",
        "category": "prompt-injection",
        "pattern": re.compile(
            r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions", re.I
        ),
        "message": "Classic prompt-injection phrase",
        "remediation": "Sanitize untrusted content; use structured tool I/O",
        "confidence": 0.9,
    },
    {
        "id": "X4-PROMPT-002",
        "severity": "MEDIUM",
        "category": "prompt-injection",
        "pattern": re.compile(
            r"(?:you are now|jailbreak|DAN mode|developer mode enabled)", re.I
        ),
        "message": "Jailbreak / role-override language",
        "remediation": "Treat as untrusted input; reject or sandbox",
        "confidence": 0.75,
    },
    {
        "id": "X4-PRIV-001",
        "severity": "HIGH",
        "category": "privilege",
        "pattern": re.compile(r"\bsudo\s+(?:-u\s+\S+\s+)?(?:rm|chmod|chown|dd)\b", re.I),
        "message": "Elevated destructive command",
        "remediation": "Require explicit human approval; avoid sudo in agent paths",
        "confidence": 0.85,
    },
    {
        "id": "X4-NET-001",
        "severity": "MEDIUM",
        "category": "network",
        "pattern": re.compile(
            r"https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\d{1,3}(?:\.\d{1,3}){3})", re.I
        ),
        "message": "Hardcoded loopback / private URL (review intent)",
        "remediation": "Confirm intentional; prefer config over hardcode",
        "confidence": 0.5,
    },
    {
        "id": "X4-FS-001",
        "severity": "MEDIUM",
        "category": "filesystem",
        "pattern": re.compile(r"(?:rm\s+-rf\s+/|chmod\s+-R\s+777)", re.I),
        "message": "Dangerous filesystem pattern",
        "remediation": "Restrict paths; never chmod 777 recursively",
        "confidence": 0.9,
    },
    {
        "id": "X4-MCP-001",
        "severity": "HIGH",
        "category": "mcp",
        "pattern": re.compile(r'"(?:allow|permissions)"\s*:\s*\[\s*"\*"\s*\]', re.I),
        "message": "Wildcard MCP / tool permission",
        "remediation": "Enumerate allowed tools explicitly",
        "confidence": 0.85,
    },
]


def all_rules() -> list[dict]:
    return list(RULE_DEFS)
