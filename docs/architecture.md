# Architecture

```text
CLI (scan | rules)
        │
        ▼
   scanner.scan_path()
        │
        ├── rules.RULE_DEFS (regex engine)
        └── file globs (agent / MCP / skills / hooks)
                │
                ▼
           Finding[]
                │
        ┌───────┼───────┐
        ▼       ▼       ▼
     human    JSON    SARIF
```

Future: optional AST-based Python/JS analysis and OpenTelemetry export via x4-obs contracts.
