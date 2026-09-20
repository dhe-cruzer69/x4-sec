from __future__ import annotations

from pathlib import Path

from .models import Finding
from .rules import RULE_DEFS

# Globs tuned for agent / MCP / skill / hook layouts
DEFAULT_GLOBS = [
    "**/.claude/**",
    "**/.cursor/**",
    "**/.codex/**",
    "**/mcp.json",
    "**/mcp.yaml",
    "**/mcp.yml",
    "**/server.json",
    "**/SKILL.md",
    "**/CLAUDE.md",
    "**/AGENTS.md",
    "**/agent.yaml",
    "**/agent.yml",
    "**/hooks/**",
    "**/*.sh",
    "**/Dockerfile",
    "**/docker-compose*.yml",
    "**/.env*",
    "**/pyproject.toml",
    "**/package.json",
]

SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", ".tox", "dist", "build"}


def _iter_files(root: Path, globs: list[str] | None = None) -> list[Path]:
    root = root.resolve()
    files: set[Path] = set()
    patterns = globs or DEFAULT_GLOBS
    for g in patterns:
        for p in root.glob(g):
            if not p.is_file():
                continue
            if any(part in SKIP_DIRS for part in p.parts):
                continue
            files.add(p)
    return sorted(files)


def scan_path(
    root: Path,
    *,
    mode: str = "all",
    globs: list[str] | None = None,
) -> list[Finding]:
    """Scan a path. mode: all | mcp | skills | agent."""
    root = root.resolve()
    if mode == "mcp":
        globs = ["**/mcp.json", "**/mcp.yaml", "**/mcp.yml", "**/server.json", "**/*.json"]
    elif mode == "skills":
        globs = ["**/SKILL.md", "**/skills/**", "**/*.md"]
    elif mode == "agent":
        globs = ["**/agent.yaml", "**/agent.yml", "**/AGENTS.md", "**/CLAUDE.md"]

    findings: list[Finding] = []
    for path in _iter_files(root, globs):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = str(path.relative_to(root)) if path.is_relative_to(root) else str(path)
        for i, line in enumerate(text.splitlines(), 1):
            for rule in RULE_DEFS:
                if rule["pattern"].search(line):
                    findings.append(
                        Finding(
                            severity=rule["severity"],
                            rule=rule["id"],
                            file=rel,
                            line=i,
                            message=rule["message"],
                            confidence=rule["confidence"],
                            remediation=rule["remediation"],
                            category=rule["category"],
                        )
                    )
    return findings
