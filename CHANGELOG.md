# Changelog

All notable changes to `totum-verify` are documented in this file.

## [0.2.2] - 2026-11-23

### Security & Hardening
- Fail closed (`first_break_index` set) on non-object items in remote `feed_rows` instead of skipping them.
- Walk every row's `event_hash`, strictly monotonic integer `seq`, and contiguous `prev_event_hash` links in remote `--chain-id` slices (removing the partial-slice walk bypass), while routing out-of-order or invalid-sequence slices through strict full-chain verification.
- Unconditionally require every contiguous run in a non-genesis slice to anchor to at least one verified signed checkpoint `(length, head_hash)`, even when `require_checkpoints=False` or remote checkpoint/key artifacts are empty or missing.
- Guard `_compute_event_hash` against non-string `prev_event_hash` and `UnicodeEncodeError`.
- Point package homepage and documentation to the live public verifier at `https://totum.run/transparency/verify`.

## [0.2.1] - 2026-11-23

### Security & Hardening
- Fail closed on missing `--feed` files and non-JSON/non-object lines in local feeds instead of skipping them.
- Fail closed in remote checkpoints-only CLI mode when zero valid signatures are verified or malformed checkpoint lines are present.
- Bind verified checkpoint `head_hash` and `length` against the walked chain in full-chain mode (detecting checkpoint/feed substitution and tail truncation).

## [0.2.0] - 2026-11-23

### Added
- Offline single-receipt verification via `verify_receipt()` and CLI `--receipt PATH` (supports both `totum-chain-pubkey.json` single-key and `atelier_chain_keys.json` multi-key bundle formats, plus `--remote https://...` key fetch and explicit `--allow-unsigned` opt-in).
- Hardened remote HTTPS fetcher: HTTPS-only validation, public-IP-only DNS resolution with socket IP pinning (SSRF & DNS rebinding defense), no-redirect enforcement, per-artifact size caps, and a 60-second overall watchdog deadline.
- Public GitHub repository (`Totum-Run-LLC/totum-verify`), full standalone test suite, multi-Python CI (3.9–3.12), and zero-token PyPI Trusted Publishing (OIDC) workflow.

### Fixed
- Remote checkpoints-only CLI plain-text output now reports `OK · checkpoints-only mode · <M> checkpoints (last @ <ts>, kid=<kid>)` instead of `OK · -1 rows · <M> checkpoints` (JSON output retains `length: -1` for backward compatibility).

## [0.1.0] - 2026-05-14

- Initial hermetic atelier audit-chain verifier release.
