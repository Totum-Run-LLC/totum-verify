# Changelog

All notable changes to `totum-verify` are documented in this file.

## [0.2.0] - 2026-11-23

### Added
- Offline single-receipt verification via `verify_receipt()` and CLI `--receipt PATH` (supports both `totum-chain-pubkey.json` single-key and `atelier_chain_keys.json` multi-key bundle formats, plus `--remote https://...` key fetch and explicit `--allow-unsigned` opt-in).
- Hardened remote HTTPS fetcher: HTTPS-only validation, public-IP-only DNS resolution with socket IP pinning (SSRF & DNS rebinding defense), no-redirect enforcement, per-artifact size caps, and a 60-second overall watchdog deadline.
- Public GitHub repository (`Totum-Run-LLC/totum-verify`), full standalone test suite, multi-Python CI (3.9–3.12), and zero-token PyPI Trusted Publishing (OIDC) workflow.

### Fixed
- Remote checkpoints-only CLI plain-text output now reports `OK · checkpoints-only mode · <M> checkpoints (last @ <ts>, kid=<kid>)` instead of `OK · -1 rows · <M> checkpoints` (JSON output retains `length: -1` for backward compatibility).

## [0.1.0] - 2026-05-14

- Initial hermetic atelier audit-chain verifier release.
