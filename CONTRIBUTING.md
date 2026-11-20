# Contributing to Ilmarinen

Ilmarinen has one responsibility: detect unexpected content changes to user-selected files. See [docs/scope.md](docs/scope.md). Please open an issue to discuss substantial or scope-changing proposals first.

## Development

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate    macOS/Linux: source .venv/bin/activate
python -m pip install -e ".[dev]"
python -m pytest
```

## Guidelines

- Behaviour changes need tests. Filesystem behaviour needs tests for races and special files where the platform allows them.
- Output must keep conforming to `borealis-agent-report/1`. Never edit `tests/standards/`; re-copy it from the standards repository instead.
- Never weaken a fail-closed path to make a test pass.
- Technical identifiers are ASCII-only.
- Use only temporary directories and synthetic files in tests. Never submit real reports, baselines, file listings or secrets.
