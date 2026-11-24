# Security Policy

## Supported Versions

| Version | Supported |
| :--- | :--- |
| `0.2.x` | Yes |
| `< 0.2.0` | No — upgrade to `0.2.0+` for SSRF/DNS-pinning remote hardening and `--receipt` verification |

## Security Properties & Threat Model

`totum-verify` is designed to be run by independent auditors on untrusted remote endpoints and exported ledgers:

- **Zero internal dependencies:** Only Python stdlib + `cryptography`.
- **Fail-closed verification:** Missing keys, unknown `kid`s, unsigned receipts (unless `--allow-unsigned` is explicitly passed), tampered payloads, and broken hash links all exit non-zero.
- **Hardened remote fetch:** Enforces `https://`, rejects non-public IPs (including split DNS and IPv4-mapped IPv6), pins the validated IP on the TLS socket, refuses HTTP redirects, caps response sizes, and aborts slow exchanges via a hard deadline watchdog.

## Reporting a Vulnerability

Please do **not** open public GitHub issues for suspected security vulnerabilities, signature verification bypasses, or SSRF bugs.

Email **`security@totum.run`** with:
- A minimal reproduction or proof-of-concept
- Affected version (`totum-verify` version and Python version)
- Expected vs. observed verification outcome

We acknowledge reports within 48 hours and coordinate a fix and disclosure timeline.
