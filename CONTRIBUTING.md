# Contributing

Thanks for your interest in confirmesc.

## Scope

confirmesc is a tool for authorized security testing and education. Keep
contributions target-agnostic: no check may hardcode a hostname, IP, username,
or CTF-specific path. Every check must work against any Linux box.

## Development

```bash
git clone https://github.com/capture0x/confirmesc
cd confirmesc
pip install -e ".[mcp]" pytest
pytest -q
```

## Guidelines

- A finding is only `CONFIRMED` when the exploitable condition is directly
  observed on the live system. Keep that bar.
- No destructive actions, even under `--active`. If confirming something would
  require modifying system state, keep it passive/heuristic (`LIKELY`/`INFO`).
- Add a test for every new check or fix.
- Run `pytest -q` before opening a pull request; CI runs it on Python 3.10
  through 3.12.

## Adding a check

Subclass `confirmesc.core.base.Check` and register it in
`confirmesc/checks/__init__.py`. See the "Extending" section in the README.
