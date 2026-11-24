# totum-verify

[![PyPI version](https://img.shields.io/pypi/v/totum-verify.svg)](https://pypi.org/project/totum-verify/)
[![CI](https://github.com/Totum-Run-LLC/totum-verify/actions/workflows/ci.yml/badge.svg)](https://github.com/Totum-Run-LLC/totum-verify/actions/workflows/ci.yml)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](./LICENSE)

**Independent, zero-internal-dependency cryptographic verifier for Totum audit chains and AI action receipts.**

Re-verifies every SHA-256 hash link, metadata-bound transaction ID, and Ed25519 signature locally on your machine using only the Python standard library and [`cryptography`](https://cryptography.io/). Read the entire single-file verifier ([`src/totum_verify/_verifier.py`](./src/totum_verify/_verifier.py)) before running it.

---

## Install

From PyPI:

```bash
pip install totum-verify
```

Or directly from this public repository today:

```bash
pip install git+https://github.com/Totum-Run-LLC/totum-verify.git
```

Or run the verifier with zero installation beyond `cryptography`:

```bash
pip install cryptography
python3 src/totum_verify/_verifier.py --remote https://totum.run
```

---

## 10-Second Live Verification

Verify every signed Ed25519 checkpoint published by [`https://totum.run`](https://totum.run):

```bash
totum-verify --remote https://totum.run
```

Example output:

```text
OK · checkpoints-only mode · 5073 checkpoints (last @ 2026-06-10T12:15:52Z, kid=k-84da2bde)
```

What this does:
1. Fetches `/.well-known/atelier_chain_meta.json` (chain genesis anchor).
2. Fetches `/.well-known/atelier_chain_keys.json` (published Ed25519 public keys keyed by `kid`).
3. Fetches `/.well-known/atelier_checkpoints.jsonl` (signed checkpoints).
4. Re-canonicalizes every checkpoint payload and verifies every Ed25519 signature locally.

To also inspect a specific chain feed:

```bash
totum-verify --remote https://totum.run --chain-id atelier_audit_chain_v3
```

---

## Offline Single-Receipt Verification

Verify an individual Totum transaction receipt (`payload_hash`, `tx_id` binding, and Ed25519 signature) against a local public-key file or keys fetched over hardened HTTPS:

```bash
# Against a local key file (totum-chain-pubkey.json or atelier_chain_keys.json)
totum-verify --receipt receipt.json --keys totum-chain-pubkey.json

# Fetching published public keys over pinned HTTPS
totum-verify --receipt receipt.json --remote https://totum.run
```

Machine-readable CI output (`--json`):

```bash
totum-verify --receipt receipt.json --keys totum-chain-pubkey.json --json
```

```json
{
  "ok": true,
  "tx_id": "4e9a1c02b7f183d0",
  "kind": "action_receipt",
  "payload_hash_ok": true,
  "tx_id_ok": true,
  "signature_state": "verified",
  "kid": "k-84da2bde",
  "errors": []
}
```

Unsigned receipts **fail closed** by default (`exit 1`). Pass `--allow-unsigned` only if you intentionally want to audit payload/ID hashes on legacy unsigned rows.

---

## Local Chain Verification

Verify exported JSONL ledger artifacts completely offline:

```bash
totum-verify \
  --feed public_feed_recent.jsonl \
  --feed public_feed_live.jsonl \
  --meta chain_meta.json \
  --keys atelier_chain_keys.json \
  --checkpoints checkpoints.jsonl
```

---

## Python API

```python
from totum_verify import verify_chain, verify_receipt

# Verify a single receipt dict against a public key bundle
receipt_result = verify_receipt(receipt_dict, keys_bundle)
assert receipt_result["ok"] is True
assert receipt_result["signature_state"] == "verified"

# Verify a local chain and signed checkpoints
chain_result = verify_chain(
    feed_paths=["public_feed_live.jsonl"],
    meta_path="chain_meta.json",
    checkpoints_path="checkpoints.jsonl",
    keys_path="atelier_chain_keys.json",
)
assert chain_result["ok"] is True
```

---

## Cryptographic Specification

| Primitive | Construction |
| :--- | :--- |
| **Canonical JSON** | UTF-8 `json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)` |
| **Genesis anchor** | `sha256(canonical(chain_meta))` |
| **Event hash link** | `sha256(prev_event_hash_ascii + "\n" + canonical(row_without_computed_fields))` |
| **Receipt payload hash** | `sha256(canonical(receipt["payload"]))` |
| **Receipt `tx_id` binding** | `sha256(f"{parent_tx_id or ''}|{ts}|{kind}|{actor_id}|{payload_hash}")[:16]` |
| **Checkpoint signature** | Ed25519 over `canonical(checkpoint_without_sig_b64)` verified with `keys[kid]["pub_b64"]` |
| **Transaction signature** | `signature = "<kid>:<sig_b64>"` — Ed25519 over `canonical(receipt_without_signature)` |

---

## Exit Codes

| Code | Meaning |
| ---: | :--- |
| `0` | Integrity and Ed25519 signatures verified — zero breaks. |
| `1` | Hash link, `payload_hash`, `tx_id`, or Ed25519 signature failed (or network error). |
| `2` | Invalid CLI arguments (e.g. non-HTTPS `--remote`, credentials in URL, non-public host). |
| `3` | `cryptography` library is not installed. |

---

## Security & Hardening Guarantees

- **Zero Totum-internal dependencies:** Only Python stdlib + `cryptography`. Enforced by AST tests in CI.
- **SSRF & DNS-rebinding defense:** `--remote` requires `https://`, rejects credentials/queries/fragments, resolves DNS and verifies **every** returned IP is globally routable (blocking loopback, RFC 1918 private, link-local / cloud metadata `169.254.0.0/16`, CGNAT, and IPv4-mapped IPv6), and pins the TCP socket to the vetted IP while enforcing hostname TLS/SNI verification.
- **No redirects, bounded reads, hard deadline:** HTTP 3xx responses are refused; per-artifact byte caps (`1 MiB` meta/keys, `32 MiB` checkpoints, `64 MiB` chain) and a hard 60-second watchdog prevent slow-drip DoS.
- **Data-only parsing:** Fetched bytes are parsed strictly via `json.loads` — never executed, imported, or written to disk.

---

## Links & Security

- Totum platform: [`https://totum.run`](https://totum.run)
- Public transparency ledger & weekly aggregate refusal counts: [`https://totum.run/transparency`](https://totum.run/transparency)
- Live proof portal: [`https://totum.run/transparency/verify`](https://totum.run/transparency/verify)
- Security, data isolation & offline verification guide: [`https://totum.run/blog/totum-security-privacy-and-offline-verification`](https://totum.run/blog/totum-security-privacy-and-offline-verification)
- Machine-readable documentation digest (`llms.txt`): [`https://totum.run/llms.txt`](https://totum.run/llms.txt)
- Security policy & vulnerability disclosure: [`SECURITY.md`](./SECURITY.md)
- Contributing guide: [`CONTRIBUTING.md`](./CONTRIBUTING.md)
- License: [MIT](./LICENSE)
