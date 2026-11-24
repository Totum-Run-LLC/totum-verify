"""CLI entry point. Re-exports the verifier's `main()` as `cli()`.

Invocable via:
  $ totum-verify --remote https://totum.run
  $ totum-verify --remote https://totum.run --chain-id atelier_audit_chain_v3
  $ totum-verify --receipt receipt.json --remote https://totum.run
  $ python -m totum_verify --remote https://totum.run
"""

from totum_verify._verifier import main as cli


if __name__ == "__main__":
    cli()
