# Contributing to totum-verify

Thank you for helping keep independent cryptographic verification simple, auditable, and rock-solid.

## Core Invariants

Every pull request must preserve these invariants (enforced automatically by CI):

1. **Zero internal or third-party dependencies beyond `cryptography`.** External auditors must be able to read `_verifier.py` end-to-end and run it with nothing but Python stdlib + `cryptography`.
2. **Never execute fetched data.** Remote responses are parsed strictly with `json.loads` — no `eval`, `exec`, `pickle`, `yaml`, `subprocess`, or dynamic imports.
3. **Fail closed.** Tampered payloads, unknown `kid`s, invalid signatures, malformed URLs, non-public DNS answers, redirects, and truncated responses must fail explicitly with a non-zero exit code.

## Local Development

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e . pytest
pytest -q
```

Verify live checkpoints:

```bash
totum-verify --remote https://totum.run
```
