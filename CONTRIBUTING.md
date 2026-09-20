# Contributing

1. Fork and branch from `main`.
2. Add or update tests for every behavior change.
3. Run `ruff check .`, `mypy src`, `pytest -q`.
4. Document new rule IDs in README and `x4-sec rules`.
5. Keep scans local-only — no network side effects.

## Adding a rule

1. Append to `RULE_DEFS` in `src/x4_sec/rules.py`.
2. Add a regression test under `tests/`.
3. Keep confidence honest (0.0–1.0).
