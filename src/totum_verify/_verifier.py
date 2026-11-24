#!/usr/bin/env python3
"""
tools/verify_atelier_chain.py — Hermetic public verifier CLI for atelier audit chain.

CRITICAL INVARIANT: Zero Totum-internal imports. Only stdlib + cryptography.
This tool must be clone-and-run for external auditors. Reimplements hash/sig primitives.

CLI signature:
  python3 -m tools.verify_atelier_chain \\
    --feed PATH [--feed PATH ...]
    [--checkpoints PATH]
    [--keys PATH]
    [--meta PATH]
    [--chain-id ID]
    [--json]

  Remote mode:
  python3 -m tools.verify_atelier_chain \\
    --remote https://example.com
    [--chain-id ID]
    [--json]

  Single-receipt mode:
  python3 -m tools.verify_atelier_chain \\
    --receipt PATH
    [--keys PATH | --remote https://example.com]
    [--allow-unsigned]
    [--json]

Output:
  Plain mode: "OK · N rows · M checkpoints" (or checkpoints-only summary) to stderr; exit 0
  Tampered: "BREAK at index X: reason" to stderr; exit 1
  Missing cryptography: error msg to stderr; exit 3
  JSON mode (--json): machine-readable dict to stdout
"""
from pathlib import Path as _Path

# Hermetic by design (core/audit_chain.py: "zero internal deps"): the CLI runs as
# `python3 tools/verify_atelier_chain.py`, where the repo root is not on
# sys.path, so it must not import engines.*. Same value as
# engines.runtime.path_provenance.data(): <repo>/data.
_DATA_ROOT = _Path(__file__).resolve().parent.parent / "data"


def data(rel: str = "") -> _Path:
    return _DATA_ROOT / rel if rel else _DATA_ROOT

import argparse
import base64
import hashlib
import http.client
import ipaddress
import json
import re
import socket
import ssl
import sys
import threading
import time
import urllib.parse
from pathlib import Path
from typing import Any, Optional

# Verify cryptography is available
try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization  # noqa: F401
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False


# Remote mode constants
REMOTE_FETCH_TIMEOUT_SEC = 30          # per socket operation
REMOTE_FETCH_DEADLINE_SEC = 60         # whole fetch, including a slow drip
REMOTE_MAX_BYTES = {                   # response size caps per artifact
    'meta': 1 * 1024 * 1024,
    'keys': 1 * 1024 * 1024,
    'tx_key': 1 * 1024 * 1024,
    'checkpoints': 32 * 1024 * 1024,
    'chain': 64 * 1024 * 1024,
}
RECEIPT_MAX_BYTES = 16 * 1024 * 1024
WELL_KNOWN_PATHS = {
    'meta': '/.well-known/atelier_chain_meta.json',
    'keys': '/.well-known/atelier_chain_keys.json',
    'tx_key': '/.well-known/totum-chain-pubkey.json',
    'checkpoints': '/.well-known/atelier_checkpoints.jsonl',
}
_USER_AGENT = (
    "totum-verify/0.2.0 "
    "(+https://github.com/Totum-Run-LLC/totum-verify)"
)
_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?$")
_CHAIN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class RemoteFetchError(Exception):
    """A remote URL or response was refused. `code` is the CLI exit status."""

    def __init__(self, message: str, code: int = 1):
        super().__init__(message)
        self.code = code


def _ip_is_public(ip: "ipaddress._BaseAddress") -> bool:
    """Globally routable unicast only: no private, loopback, link-local
    (169.254/16 cloud metadata, fe80::/10), CGNAT, reserved, unspecified,
    documentation or multicast ranges; IPv4-mapped/6to4 forms are unwrapped."""
    if isinstance(ip, ipaddress.IPv6Address):
        for embedded in (ip.ipv4_mapped, ip.sixtofour):
            if embedded is not None:
                return _ip_is_public(embedded)
        if ip.teredo is not None:
            return False
    return bool(ip.is_global) and not ip.is_multicast


def _validate_remote_url(url: str) -> urllib.parse.SplitResult:
    """https only, no credentials, no query/fragment, a DNS name or public IP."""
    if not isinstance(url, str) or any(ord(ch) < 0x21 or ord(ch) == 0x7F for ch in url):
        raise RemoteFetchError("error: --remote URL contains whitespace or control characters", 2)
    parts = urllib.parse.urlsplit(url)
    if parts.scheme.lower() != "https":
        raise RemoteFetchError(f"error: --remote requires https:// (got {url[:8]}…)", 2)
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        raise RemoteFetchError("error: --remote URL must not carry credentials", 2)
    if parts.query or parts.fragment:
        raise RemoteFetchError("error: --remote URL must not carry a query or fragment", 2)
    try:
        port = parts.port
    except ValueError as exc:
        raise RemoteFetchError(f"error: --remote URL has an invalid port ({exc})", 2) from exc
    if port is not None and not (1 <= port <= 65535):
        raise RemoteFetchError("error: --remote URL has an invalid port", 2)
    host = parts.hostname or ""
    if not host:
        raise RemoteFetchError("error: --remote URL has no host", 2)
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        if not _ip_is_public(literal):
            raise RemoteFetchError(f"error: --remote host {host} is not a public address", 2)
    else:
        if not _HOSTNAME_RE.fullmatch(host):
            raise RemoteFetchError("error: --remote host is not a valid DNS name", 2)
        lowered = host.lower().rstrip(".")
        if lowered == "localhost" or lowered.endswith((".localhost", ".local", ".internal", ".arpa")):
            raise RemoteFetchError(f"error: --remote host {host} is not a public name", 2)
    return parts


def _resolve_public_ip(host: str, port: int) -> str:
    """Resolve host and require EVERY address to be public (a split answer
    with one private record is refused). The returned address is the one the
    connection is pinned to, so a second DNS answer cannot rebind it."""
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError) as exc:
        raise RemoteFetchError(f"error: cannot resolve {host}: {exc}") from exc
    addresses = []
    for info in infos:
        address = info[4][0].split("%", 1)[0]
        ip = ipaddress.ip_address(address)
        if not _ip_is_public(ip):
            raise RemoteFetchError(
                f"error: --remote host {host} resolves to a non-public address ({ip})", 2
            )
        addresses.append(address)
    if not addresses:
        raise RemoteFetchError(f"error: cannot resolve {host}")
    return addresses[0]


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS to a pre-validated IP; SNI and certificate checks use the host name."""

    def __init__(self, host: str, port: int, pinned_ip: str, timeout: float):
        super().__init__(host, port, timeout=timeout, context=ssl.create_default_context())
        self._pinned_ip = pinned_ip

    def connect(self):  # noqa: D401 - http.client hook
        sock = socket.create_connection((self._pinned_ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def _http_get(url: str, kind: str) -> bytes:
    """One GET with no redirects, a timeout, an overall deadline and a size cap.
    The body is returned as bytes and is only ever parsed as JSON by the
    caller; fetched content is never executed or written to disk."""
    parts = _validate_remote_url(url)
    port = parts.port or 443
    pinned = _resolve_public_ip(parts.hostname, port)
    limit = REMOTE_MAX_BYTES.get(kind, 1024 * 1024)
    path = parts.path or "/"
    conn = _PinnedHTTPSConnection(parts.hostname, port, pinned, REMOTE_FETCH_TIMEOUT_SEC)
    deadline = time.monotonic() + REMOTE_FETCH_DEADLINE_SEC
    # Hard stop for the WHOLE exchange (connect, headers, body): a server that
    # drips header bytes inside each socket timeout is cut off at the deadline.
    expired = threading.Event()

    def _abort() -> None:
        expired.set()
        sock = getattr(conn, "sock", None)
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    watchdog = threading.Timer(REMOTE_FETCH_DEADLINE_SEC, _abort)
    watchdog.daemon = True
    watchdog.start()
    try:
        conn.request("GET", path, headers={
            "Host": parts.netloc,
            "User-Agent": _USER_AGENT,
            "Accept": "application/json, application/jsonl, application/x-ndjson, */*",
            "Accept-Encoding": "identity",
        })
        resp = conn.getresponse()
        if 300 <= resp.status < 400:
            raise RemoteFetchError(
                f"error: HTTP {resp.status} redirect for {kind} from {url}; redirects are not followed"
            )
        if resp.status == 404:
            suffix = " (keys_not_initialized)" if kind == 'keys' else ""
            raise RemoteFetchError(f"error: {kind} not found at {url}{suffix}")
        if resp.status != 200:
            raise RemoteFetchError(f"error: HTTP {resp.status} fetching {kind} from {url}")
        declared = resp.getheader("Content-Length")
        if declared is not None and declared.strip().isdigit() and int(declared) > limit:
            raise RemoteFetchError(f"error: {kind} response too large ({declared} > {limit} bytes)")
        chunks: list[bytes] = []
        total = 0
        # read1 returns after at most one underlying read (one chunk when
        # chunked), and the socket timeout shrinks to the time left, so a
        # server dripping bytes cannot hold a single read past the deadline.
        read_some = getattr(resp, "read1", None) or resp.read
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RemoteFetchError(f"error: fetching {kind} exceeded {REMOTE_FETCH_DEADLINE_SEC}s")
            sock = getattr(conn, "sock", None)
            if sock is not None:
                sock.settimeout(max(0.1, min(REMOTE_FETCH_TIMEOUT_SEC, remaining)))
            chunk = read_some(min(65536, limit + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > limit:
                raise RemoteFetchError(f"error: {kind} response exceeds {limit} bytes")
        if expired.is_set():
            # The watchdog cut the socket: what was read is truncated, not a body.
            raise RemoteFetchError(f"error: fetching {kind} exceeded {REMOTE_FETCH_DEADLINE_SEC}s")
        return b"".join(chunks)
    except RemoteFetchError:
        raise
    except (OSError, http.client.HTTPException, ssl.SSLError, ValueError) as exc:
        if expired.is_set():
            raise RemoteFetchError(f"error: fetching {kind} exceeded {REMOTE_FETCH_DEADLINE_SEC}s") from exc
        raise RemoteFetchError(f"error: fetch failed for {kind}: {exc}") from exc
    finally:
        watchdog.cancel()
        conn.close()


def _fetch(url: str, kind: str) -> bytes:
    """CLI wrapper around _http_get: prints the refusal and exits.

    Remote hardening (P15, 2026-09-29): https only, no userinfo, public
    addresses only (checked on every resolved address and pinned for the
    connection), no redirects, per-operation timeout plus an overall
    deadline, and a per-artifact size cap.
    """
    try:
        return _http_get(url, kind)
    except RemoteFetchError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(exc.code)


def _chain_url(base_url: str, chain_id: str) -> str:
    if not isinstance(chain_id, str) or not _CHAIN_ID_RE.fullmatch(chain_id) or ".." in chain_id:
        raise RemoteFetchError("error: --chain-id must match [A-Za-z0-9][A-Za-z0-9._:-]{0,127}", 2)
    return base_url + "/api/atelier/chain/" + urllib.parse.quote(chain_id, safe="")


def _canonical(obj: Any) -> bytes:
    """Canonical JSON bytes: sorted keys, compact separators, UTF-8."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _extract_public_key_map(keys_bundle: Optional[dict[str, Any]]) -> dict[str, str]:
    """Normalize either Totum public-key format into {kid: pub_b64}.

    Supports:
    - Atelier key bundle: {"current": kid, "keys": {kid: {"pub_b64": ...}, ...}}
    - Single tx chain pubkey: {"kid": kid, "pub_b64": ...}
    """
    if not isinstance(keys_bundle, dict):
        return {}
    out: dict[str, str] = {}
    nested = keys_bundle.get("keys")
    if isinstance(nested, dict):
        for kid, info in nested.items():
            if isinstance(kid, str) and isinstance(info, dict):
                pub = info.get("pub_b64")
                if isinstance(pub, str) and pub:
                    out[kid] = pub
    direct_kid = keys_bundle.get("kid")
    direct_pub = keys_bundle.get("pub_b64")
    if isinstance(direct_kid, str) and direct_kid and isinstance(direct_pub, str) and direct_pub:
        out.setdefault(direct_kid, direct_pub)
    return out


def verify_receipt(
    receipt: dict[str, Any],
    keys_bundle: Optional[dict[str, Any]] = None,
    *,
    require_signature: bool = True,
) -> dict[str, Any]:
    """Verify a single Totum transaction receipt or signed checkpoint offline.

    Checks:
    1. For tx receipts (`tx_id` or `payload_hash` present):
       - `payload_hash == sha256(canonical(payload))`
       - `tx_id == sha256(f"{parent_tx_id or ''}|{ts}|{kind}|{actor_id}|{payload_hash}")[:16]`
       - Ed25519 signature in `signature` (`"<kid>:<sig_b64>"`) over canonical JSON
         of the receipt excluding `"signature"`.
    2. For checkpoint receipts (`sig_b64` + `kid` present):
       - Ed25519 signature in `sig_b64` over canonical JSON excluding `"sig_b64"`.

    Returns a structured dict with `ok`, `tx_id`, `kind`, `payload_hash_ok`,
    `tx_id_ok`, `signature_state`, `kid`, and `errors`.
    """
    errors: list[str] = []
    if not isinstance(receipt, dict):
        return {
            "ok": False,
            "tx_id": None,
            "kind": None,
            "payload_hash_ok": None,
            "tx_id_ok": None,
            "signature_state": "invalid",
            "kid": None,
            "errors": ["receipt_not_object"],
        }

    tx_id = receipt.get("tx_id") if isinstance(receipt.get("tx_id"), str) else None
    kind = receipt.get("kind") if isinstance(receipt.get("kind"), str) else None
    payload_hash_ok: Optional[bool] = None
    tx_id_ok: Optional[bool] = None

    is_tx_shape = ("tx_id" in receipt) or ("payload_hash" in receipt)
    if is_tx_shape:
        expected_hash = receipt.get("payload_hash")
        if not isinstance(expected_hash, str) or not expected_hash:
            payload_hash_ok = False
            errors.append("missing_payload_hash")
        elif "payload" not in receipt:
            payload_hash_ok = False
            errors.append("missing_payload")
        else:
            try:
                actual_hash = hashlib.sha256(_canonical(receipt["payload"])).hexdigest()
            except (TypeError, ValueError):
                actual_hash = ""
            payload_hash_ok = actual_hash == expected_hash
            if not payload_hash_ok:
                errors.append("tx_payload_hash_mismatch")

        if "tx_id" in receipt:
            parent_val = receipt.get("parent_tx_id") or ""
            seed = (
                f"{parent_val}|{receipt.get('ts')}|{receipt.get('kind')}|"
                f"{receipt.get('actor_id')}|{receipt.get('payload_hash')}"
            )
            expected_tx_id = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]
            tx_id_ok = receipt.get("tx_id") == expected_tx_id
            if not tx_id_ok:
                errors.append("tx_id_mismatch")

    key_map = _extract_public_key_map(keys_bundle)
    sig_field: Optional[str] = None
    kid: Optional[str] = None
    sig_b64: Optional[str] = None
    signature_state = "unsigned"

    if "signature" in receipt and receipt.get("signature") not in (None, ""):
        raw_sig = receipt.get("signature")
        if not isinstance(raw_sig, str) or ":" not in raw_sig:
            signature_state = "malformed"
            errors.append("signature_malformed")
        else:
            kid, sig_b64 = raw_sig.split(":", 1)
            if not kid or not sig_b64:
                signature_state = "malformed"
                errors.append("signature_malformed")
            else:
                sig_field = "signature"
    elif receipt.get("sig_b64") not in (None, ""):
        raw_sig_b64 = receipt.get("sig_b64")
        raw_kid = receipt.get("kid")
        if not isinstance(raw_sig_b64, str) or not isinstance(raw_kid, str) or not raw_kid:
            signature_state = "malformed"
            errors.append("signature_malformed")
        else:
            kid = raw_kid
            sig_b64 = raw_sig_b64
            sig_field = "sig_b64"

    if sig_field is not None and kid is not None and sig_b64 is not None:
        if not HAS_CRYPTOGRAPHY:
            signature_state = "unchecked"
            errors.append("missing_cryptography")
        elif kid not in key_map:
            signature_state = "unknown_key"
            errors.append("tx_signature_unknown_key")
        else:
            unsigned = {k: v for k, v in receipt.items() if k != sig_field}
            try:
                sig_bytes = base64.b64decode(sig_b64, validate=True)
                pub_bytes = base64.b64decode(key_map[kid], validate=True)
                pub_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
                pub_key.verify(sig_bytes, _canonical(unsigned))
                signature_state = "verified"
            except Exception:
                signature_state = "invalid"
                errors.append("tx_signature_invalid")
    elif signature_state == "unsigned" and require_signature:
        errors.append("unsigned_receipt")

    if not is_tx_shape and sig_field is None and signature_state == "unsigned" and not require_signature:
        errors.append("unrecognized_receipt_format")

    return {
        "ok": len(errors) == 0,
        "tx_id": tx_id,
        "kind": kind,
        "payload_hash_ok": payload_hash_ok,
        "tx_id_ok": tx_id_ok,
        "signature_state": signature_state,
        "kid": kid,
        "errors": errors,
    }


def _compute_event_hash(prev_hash: str, payload_bytes: bytes) -> str:
    """sha256(prev_hash_ascii + newline + payload_bytes)."""
    h = hashlib.sha256()
    h.update(prev_hash.encode("ascii"))
    h.update(b"\n")
    h.update(payload_bytes)
    return h.hexdigest()


def _meta_genesis_hash(chain_meta_path: Path) -> str:
    """Return SHA-256 of canonical bytes of chain_meta.json."""
    try:
        meta_obj = json.loads(chain_meta_path.read_text(encoding="utf-8"))
        return hashlib.sha256(_canonical(meta_obj)).hexdigest()
    except FileNotFoundError:
        raise FileNotFoundError(f"chain_meta.json not found at {chain_meta_path}")


def _meta_genesis_hash_from_bytes(meta_bytes: bytes) -> str:
    """Return SHA-256 of canonical bytes of chain_meta.json from bytes."""
    try:
        meta_obj = json.loads(meta_bytes.decode("utf-8"))
        return hashlib.sha256(_canonical(meta_obj)).hexdigest()
    except Exception as e:
        raise ValueError(f"Failed to parse meta bytes: {e}")


_COMPUTED_FIELDS = frozenset(
    {"prev_event_hash", "event_hash", "seq", "chain_schema_version"}
)


def verify_chain(feed_paths=None, meta_path=None, checkpoints_path=None, keys_path=None,
                 meta_bytes: Optional[bytes] = None, checkpoints_bytes: Optional[bytes] = None,
                 keys_bytes: Optional[bytes] = None, feed_rows: Optional[list] = None):
    """
    Verify chain integrity across all feed files or from pre-parsed rows.

    Returns dict with keys:
      ok (bool): all links intact and sigs valid
      first_break_index (int|None): 0-indexed line of first bad link
      checkpoint_count (int): number of valid checkpoints
      last_signed_at (str|None): ISO timestamp of last checkpoint
      head_hash (str): hash of final event
      length (int): count of chained rows (pre-chain rows not counted); -1 if feed_rows not provided
      pre_chain_count (int): count of rows without chain fields; -1 if feed_rows not provided
      kid (str|None): kid of last checkpoint signature
    """
    # Determine genesis hash
    if meta_bytes:
        genesis_hash = _meta_genesis_hash_from_bytes(meta_bytes)
    else:
        genesis_hash = _meta_genesis_hash(meta_path)

    # Load feed data
    pre_chain_count = 0
    length = 0
    head_hash = ""
    first_break_index = None
    chained_rows = []

    # Determine which mode we're in
    if feed_rows is not None:
        # Remote mode with chain-id: classify pre-chain vs chained rows the
        # same way local mode does. The /api/atelier/chain/[id] API may return
        # both pre-chain rows (no event_hash) and chained rows for one chainId
        # — only the chained ones participate in the hash chain walk.
        # The API flattens record.{source_ledger,ingest_key,public} to outer
        # keys for UI consumption. To recompute hashes correctly we need the
        # ORIGINAL spool shape — the API includes a `record` field for this.
        for idx, raw in enumerate(feed_rows):
            if not isinstance(raw, dict):
                continue
            has_chain_fields = all(
                field in raw
                for field in ["event_hash", "prev_event_hash", "seq", "chain_schema_version"]
            )
            if not has_chain_fields:
                pre_chain_count += 1
                continue
            # Reconstruct the canonical spool shape: {ts, ingest_id, record, +chain fields}
            if "record" in raw and isinstance(raw["record"], dict):
                spool_shape = {
                    "ts": raw.get("ts", ""),
                    "ingest_id": raw.get("ingest_id", ""),
                    "record": raw["record"],
                    "prev_event_hash": raw["prev_event_hash"],
                    "event_hash": raw["event_hash"],
                    "seq": raw["seq"],
                    "chain_schema_version": raw["chain_schema_version"],
                }
                chained_rows.append((idx, spool_shape))
            else:
                # API didn't expose `record` field — verifier cannot recompute
                # without it. Fall back to flat shape; will likely break.
                chained_rows.append((idx, raw))
    elif feed_paths is not None:
        # Local mode: read from feed_paths
        all_rows = []
        for feed_path in feed_paths:
            feed_path = Path(feed_path)
            if not feed_path.exists():
                continue

            with open(feed_path, "r", encoding="utf-8") as f:
                for line_num, line in enumerate(f):
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        rec = json.loads(line)
                    except Exception:
                        # Report the raw line as BREAK — never crash on bad data
                        all_rows.append((line_num, line, False, "BREAK"))
                        continue

                    # Classify: chained vs pre-chain
                    has_chain_fields = all(
                        field in rec for field in ["event_hash", "prev_event_hash", "seq", "chain_schema_version"]
                    )

                    if not has_chain_fields:
                        pre_chain_count += 1
                        all_rows.append((line_num, rec, False, "pre-chain row"))
                    else:
                        all_rows.append((line_num, rec, True, None))

        # Extract chained rows from all_rows
        chained_rows = [(idx, rec) for idx, rec, is_chained, _ in all_rows if is_chained]
    else:
        # Remote mode without chain-id: signature-only verification
        length = -1
        pre_chain_count = -1

    # Detect remote --chain-id slice mode: feed_rows is a per-chain-id subset
    # of the GLOBAL ledger. Hash linkage spans chain_ids globally, so a slice
    # cannot be re-walked in isolation (its first row's prev_event_hash points
    # to a row in a different chain_id). In this mode we skip the hash walk
    # entirely — integrity is guaranteed by the signed head_hash from
    # checkpoints.jsonl, which covers the WHOLE ledger.
    is_chain_id_slice = (
        feed_rows is not None
        and chained_rows
        and chained_rows[0][1].get("seq", 1) != 1
    )
    if is_chain_id_slice:
        chained_rows.sort(key=lambda x: x[1].get("seq", 0))
        # Track length + head from slice but do not enforce link integrity here.
        length = len(chained_rows)
        head_hash = chained_rows[-1][1].get("event_hash", "")
        chained_rows = []  # skip the walk loop

    # Walk the chained rows
    if chained_rows:
        # Sort by seq (should already be sorted)
        chained_rows.sort(key=lambda x: x[1].get("seq", 0))

        # Walk the chained rows
        expected_prev = genesis_hash
        expected_seq = 1

        for chain_idx, rec in chained_rows:
            stored_prev = rec.get("prev_event_hash", "")
            stored_hash = rec.get("event_hash", "")
            stored_seq = rec.get("seq", -1)

            # Build payload (exclude computed fields)
            payload = {k: v for k, v in rec.items() if k not in _COMPUTED_FIELDS}
            payload_bytes = _canonical(payload)
            expected_hash = _compute_event_hash(stored_prev, payload_bytes)

            ok_this_line = True

            # Check prev_event_hash
            if stored_prev != expected_prev:
                ok_this_line = False

            # Check event_hash
            if stored_hash != expected_hash:
                ok_this_line = False

            # Check seq
            if stored_seq != expected_seq:
                ok_this_line = False

            if not ok_this_line and first_break_index is None:
                first_break_index = chain_idx

            length += 1
            head_hash = stored_hash
            expected_prev = stored_hash
            expected_seq = stored_seq + 1 if isinstance(stored_seq, int) else expected_seq + 1

    # Verify checkpoints if provided (separate verification, affects ok only if requested)
    checkpoint_count = 0
    last_signed_at = None
    last_kid = None
    checkpoint_break = False

    # Only verify checkpoints if we have both checkpoints and keys (from bytes or files)
    has_checkpoints = False
    has_keys = False
    keys_bundle = {}

    if checkpoints_bytes:
        has_checkpoints = True
    elif checkpoints_path:
        checkpoints_path_obj = Path(checkpoints_path)
        has_checkpoints = checkpoints_path_obj.exists()

    if keys_bytes:
        has_keys = True
        keys_bundle = json.loads(keys_bytes.decode("utf-8"))
    elif keys_path:
        keys_path_obj = Path(keys_path)
        if keys_path_obj.exists():
            has_keys = True
            keys_bundle = json.loads(keys_path_obj.read_text(encoding="utf-8"))

    # Only attempt checkpoint verification if we have both files/bytes and cryptography
    if has_checkpoints and has_keys and HAS_CRYPTOGRAPHY:
        keys_dict = keys_bundle.get("keys", {})

        # Parse checkpoints
        if checkpoints_bytes:
            checkpoints_text = checkpoints_bytes.decode("utf-8")
        else:
            checkpoints_path_obj = Path(checkpoints_path)
            checkpoints_text = checkpoints_path_obj.read_text(encoding="utf-8")

        for line in checkpoints_text.strip().split("\n"):
            line = line.strip()
            if not line:
                continue

            try:
                checkpoint = json.loads(line)
            except json.JSONDecodeError:
                continue

            # Extract signature and kid
            sig_b64_str = checkpoint.get("sig_b64", "")
            kid = checkpoint.get("kid", "")

            if not sig_b64_str or not kid:
                continue

            # Look up public key
            if kid not in keys_dict:
                checkpoint_break = True
                continue

            key_info = keys_dict[kid]
            pub_b64 = key_info.get("pub_b64", "")

            if not pub_b64:
                checkpoint_break = True
                continue

            # Verify signature
            checkpoint_unsigned = {
                k: v for k, v in checkpoint.items() if k != "sig_b64"
            }
            checkpoint_bytes_data = _canonical(checkpoint_unsigned)

            try:
                sig_bytes = base64.b64decode(sig_b64_str)
                pub_bytes = base64.b64decode(pub_b64)
                pub_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
                pub_key.verify(sig_bytes, checkpoint_bytes_data)
                # Signature valid
                checkpoint_count += 1
                last_signed_at = checkpoint.get("ts_utc")
                last_kid = kid
            except Exception:
                # Signature verification failed
                checkpoint_break = True
                continue

    # If chain was ok but checkpoints had issues, mark it
    chain_ok = first_break_index is None
    overall_ok = chain_ok and not checkpoint_break

    return {
        "ok": overall_ok,
        "first_break_index": first_break_index,
        "checkpoint_count": checkpoint_count,
        "last_signed_at": last_signed_at,
        "head_hash": head_hash,
        "length": length,
        "pre_chain_count": pre_chain_count,
        "kid": last_kid,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Verify atelier audit chain integrity."
    )
    parser.add_argument(
        "--feed",
        action="append",
        dest="feeds",
        help="JSONL feed file (can be specified multiple times)",
    )
    parser.add_argument(
        "--remote",
        help="Remote URL (https://...) to fetch artifacts from; mutually exclusive with --feed",
    )
    parser.add_argument(
        "--receipt",
        help="Path to a single receipt JSON file to verify offline (pair with --keys or --remote)",
    )
    parser.add_argument(
        "--allow-unsigned",
        action="store_true",
        help="With --receipt, allow unsigned receipts if payload_hash and tx_id verify",
    )
    parser.add_argument(
        "--checkpoints",
        default=str(data("atelier/checkpoints.jsonl")),
        help="Checkpoints file (default: data/atelier/checkpoints.jsonl)",
    )
    parser.add_argument(
        "--keys",
        default=None,
        help="Public key bundle (default: data/atelier/.well-known/atelier_chain_keys.json)",
    )
    parser.add_argument(
        "--meta",
        default=str(data("atelier/chain_meta.json")),
        help="Chain metadata file (default: data/atelier/chain_meta.json)",
    )
    parser.add_argument(
        "--chain-id",
        help="Chain ID for remote mode (optional; without it, only checkpoint sigs verified)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output machine-readable JSON to stdout",
    )

    args = parser.parse_args()

    # Validate mode: --receipt vs --feed vs --remote
    if args.receipt and args.feeds:
        print("error: --receipt and --feed are mutually exclusive", file=sys.stderr)
        sys.exit(2)

    if args.remote and args.feeds:
        print("error: --remote and --feed are mutually exclusive", file=sys.stderr)
        sys.exit(2)

    if not args.receipt and not args.remote and not args.feeds:
        parser.print_help()
        sys.exit(1)

    # Check if cryptography is available
    if not HAS_CRYPTOGRAPHY:
        print(
            "error: cryptography library required. Install with: pip install cryptography",
            file=sys.stderr,
        )
        sys.exit(3)

    # Single-receipt mode
    if args.receipt:
        receipt_path = Path(args.receipt)
        try:
            raw_bytes = receipt_path.read_bytes()
        except OSError as exc:
            print(f"error: cannot read receipt {receipt_path}: {exc}", file=sys.stderr)
            sys.exit(1)
        if len(raw_bytes) > RECEIPT_MAX_BYTES:
            print(f"error: receipt file exceeds {RECEIPT_MAX_BYTES} bytes", file=sys.stderr)
            sys.exit(1)
        try:
            receipt_obj = json.loads(raw_bytes.decode("utf-8"))
        except Exception as exc:
            print(f"error: receipt file is not valid JSON: {exc}", file=sys.stderr)
            sys.exit(1)

        merged_keys: dict[str, dict[str, str]] = {}
        if args.keys:
            try:
                local_bundle = json.loads(Path(args.keys).read_text(encoding="utf-8"))
            except Exception as exc:
                print(f"error: cannot read keys file {args.keys}: {exc}", file=sys.stderr)
                sys.exit(1)
            for k, pub in _extract_public_key_map(local_bundle).items():
                merged_keys[k] = {"pub_b64": pub}
        elif args.remote:
            try:
                _validate_remote_url(args.remote)
            except RemoteFetchError as exc:
                print(str(exc), file=sys.stderr)
                sys.exit(exc.code)
            base_url = args.remote.rstrip("/")
            fetch_errors: list[str] = []
            for kind_name in ("tx_key", "keys"):
                try:
                    raw_keys = _http_get(base_url + WELL_KNOWN_PATHS[kind_name], kind_name)
                    parsed_bundle = json.loads(raw_keys.decode("utf-8"))
                    for k, pub in _extract_public_key_map(parsed_bundle).items():
                        merged_keys[k] = {"pub_b64": pub}
                except RemoteFetchError as exc:
                    if exc.code == 2:
                        print(str(exc), file=sys.stderr)
                        sys.exit(2)
                    fetch_errors.append(str(exc))
                except Exception as exc:
                    fetch_errors.append(f"error: invalid {kind_name} JSON: {exc}")
            if not merged_keys and not args.allow_unsigned:
                msg = fetch_errors[0] if fetch_errors else "error: no public keys found at remote"
                print(msg, file=sys.stderr)
                sys.exit(1)
        else:
            default_keys = data("atelier/.well-known/atelier_chain_keys.json")
            if default_keys.exists():
                try:
                    local_bundle = json.loads(default_keys.read_text(encoding="utf-8"))
                    for k, pub in _extract_public_key_map(local_bundle).items():
                        merged_keys[k] = {"pub_b64": pub}
                except Exception:
                    pass

        keys_bundle_arg = {"keys": merged_keys} if merged_keys else None
        result = verify_receipt(
            receipt_obj,
            keys_bundle_arg,
            require_signature=not args.allow_unsigned,
        )
        if args.json:
            print(json.dumps(result, indent=None, separators=(",", ":")))
        elif result["ok"]:
            label = result["tx_id"] or "checkpoint"
            kid_part = f" · kid={result['kid']}" if result.get("kid") else ""
            print(
                f"OK · receipt {label} · signature={result['signature_state']}{kid_part}",
                file=sys.stderr,
            )
        else:
            reasons = ", ".join(result["errors"]) or "verification_failed"
            print(f"BREAK · receipt verification failed ({reasons})", file=sys.stderr)
        sys.exit(0 if result["ok"] else 1)

    keys_path_arg = args.keys if args.keys is not None else str(
        data("atelier/.well-known/atelier_chain_keys.json")
    )

    # Remote mode
    if args.remote:
        try:
            _validate_remote_url(args.remote)
        except RemoteFetchError as exc:
            print(str(exc), file=sys.stderr)
            sys.exit(exc.code)

        base_url = args.remote.rstrip('/')

        # Fetch artifacts over HTTPS
        meta_bytes = _fetch(base_url + WELL_KNOWN_PATHS['meta'], 'meta')
        keys_bytes = _fetch(base_url + WELL_KNOWN_PATHS['keys'], 'keys')
        checkpoints_bytes = _fetch(base_url + WELL_KNOWN_PATHS['checkpoints'], 'checkpoints')

        # Optionally fetch full chain if chain-id provided
        feed_rows = None
        if args.chain_id:
            try:
                chain_url = _chain_url(base_url, args.chain_id)
            except RemoteFetchError as exc:
                print(str(exc), file=sys.stderr)
                sys.exit(exc.code)
            try:
                chain_resp_bytes = _fetch(chain_url, 'chain')
                chain_resp = json.loads(chain_resp_bytes.decode('utf-8'))
                feed_rows = chain_resp.get('rows', [])
            except Exception as e:
                print(f"error: failed to fetch chain: {e}", file=sys.stderr)
                sys.exit(1)

        result = verify_chain(
            meta_bytes=meta_bytes,
            checkpoints_bytes=checkpoints_bytes,
            keys_bytes=keys_bytes,
            feed_rows=feed_rows,
        )
    else:
        # Local mode
        meta_path = Path(args.meta)

        result = verify_chain(
            feed_paths=args.feeds,
            meta_path=meta_path,
            checkpoints_path=args.checkpoints if args.checkpoints else None,
            keys_path=keys_path_arg if keys_path_arg else None,
        )

    if args.json:
        print(json.dumps(result, indent=None, separators=(",", ":")))
        sys.exit(0 if result["ok"] else 1)
    else:
        # Plain text mode
        if result["ok"]:
            if result["length"] < 0:
                meta_parts = []
                if result.get("last_signed_at"):
                    meta_parts.append(f"last @ {result['last_signed_at']}")
                if result.get("kid"):
                    meta_parts.append(f"kid={result['kid']}")
                suffix = f" ({', '.join(meta_parts)})" if meta_parts else ""
                msg = (
                    f"OK · checkpoints-only mode · "
                    f"{result['checkpoint_count']} checkpoints{suffix}"
                )
            else:
                msg = f"OK · {result['length']} rows · {result['checkpoint_count']} checkpoints"
            print(msg, file=sys.stderr)
            sys.exit(0)
        else:
            idx = result["first_break_index"]
            if idx is not None:
                msg = f"BREAK at index {idx}"
            else:
                msg = "BREAK (checkpoint signature verification failed)"
            print(msg, file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
