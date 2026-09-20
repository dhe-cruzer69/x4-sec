# x4-sec

[![CI](https://github.com/dhe-cruzer69/x4-sec/actions/workflows/ci.yml/badge.svg)](https://github.com/dhe-cruzer69/x4-sec/actions)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)

**Security scanner for AI-agent projects, MCP servers, skills, hooks, and agent configs.**

Part of the X4 developer-tool ecosystem:

```text
x4-skills → x4-mcpgen → x4-sec → x4-runtime → x4-obs
```

## 30-second demo

```bash
pip install -e ".[dev]"
x4-sec scan .
x4-sec scan --mcp mcp.json
x4-sec scan --skills ./skills
x4-sec scan --json
x4-sec scan --sarif findings.sarif
```

## What it checks

| Category | Examples |
|----------|----------|
| Secrets | `sk-…`, `ghp_…`, AWS keys, private keys |
| Dangerous shell | `curl \| bash`, `wget \| sh`, eval of remote content |
| Prompt injection | “ignore previous instructions”, jailbreak phrases |
| MCP permissions | overly broad tools, missing allow-lists |
| Hooks / skills | unsafe file ops, network without approval |
| Config mistakes | world-writable paths, debug flags in prod |
| Privilege patterns | sudo, setuid, unrestricted FS |

## CLI

```bash
x4-sec scan [PATH]              # scan project tree
x4-sec scan --mcp server.json   # MCP config focus
x4-sec scan --skills ./skills   # skill bundles
x4-sec scan --agent agent.yaml  # agent definition
x4-sec scan --json               # machine-readable
x4-sec scan --sarif out.sarif    # GitHub Code Scanning
x4-sec scan --fail-on high       # exit 1 on high+
x4-sec rules                    # list rule IDs
```

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | No findings at or above `--fail-on` |
| 1 | Findings at threshold |
| 2 | Usage / internal error |

## Architecture

```text
Path / MCP / Skills / Agent
         │
         ▼
   Rule engine (regex + AST hooks)
         │
         ▼
  Findings → human | JSON | SARIF
```

## Security

- Read-only by default. No network calls during scan.
- No telemetry. Local-only.
- Report vulnerabilities via private GitHub security advisory.

## License

Apache-2.0
