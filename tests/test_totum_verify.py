"""Standalone test suite for totum-verify (chain integrity, receipts, and SSRF hardening)."""
from __future__ import annotations

import ast
import base64
import hashlib
import json
import socket
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

import totum_verify
from totum_verify import RemoteFetchError, verify_chain, verify_receipt
import totum_verify._verifier as v

REPO_ROOT = Path(__file__).resolve().parents[1]


def _canonical(obj) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _compute_hash(prev_hash: str, payload: dict) -> str:
    h = hashlib.sha256()
    h.update(prev_hash.encode("ascii"))
    h.update(b"\n")
    h.update(_canonical(payload))
    return h.hexdigest()


def _make_keypair(kid: str = "k-test-01"):
    priv = ed25519.Ed25519PrivateKey.generate()
    pub_raw = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv, base64.b64encode(pub_raw).decode("ascii"), kid


def _build_chain(tmp_path: Path, count: int = 4, pre_chain: int = 0):
    meta = {
        "chain_id": "atelier_audit_chain_v3",
        "alg": "sha256",
        "schema_version": 1,
        "genesis_ts_utc": "2026-11-23T00:00:00Z",
    }
    meta_path = tmp_path / "chain_meta.json"
    meta_path.write_text(json.dumps(meta), encoding="utf-8")
    genesis = hashlib.sha256(_canonical(meta)).hexdigest()

    lines = []
    for i in range(pre_chain):
        lines.append(json.dumps({"ts": f"2026-05-01T0{i}:00:00Z", "ingest_id": f"pre-{i}", "data": i}))

    prev = genesis
    head = genesis
    for seq in range(1, count + 1):
        payload = {"ts": f"2026-11-23T0{seq}:00:00Z", "ingest_id": f"row-{seq}", "data": f"payload-{seq}"}
        ev_hash = _compute_hash(prev, payload)
        row = {
            **payload,
            "prev_event_hash": prev,
            "event_hash": ev_hash,
            "seq": seq,
            "chain_schema_version": 1,
        }
        lines.append(json.dumps(row, separators=(",", ":")))
        prev = ev_hash
        head = ev_hash

    feed_path = tmp_path / "feed.jsonl"
    feed_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return feed_path, meta_path, head, count


def _make_signed_tx_receipt(priv, kid: str, *, sign: bool = True) -> dict:
    payload = {"action": "send_email", "cost_usd": 0.0042, "venture": "acme"}
    payload_hash = hashlib.sha256(_canonical(payload)).hexdigest()
    parent_tx_id = "0011223344556677"
    ts = "2026-11-23T18:00:00Z"
    kind = "action_receipt"
    actor_id = "worker-sales-1"
    seed = f"{parent_tx_id}|{ts}|{kind}|{actor_id}|{payload_hash}"
    tx_id = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]
    rec = {
        "tx_id": tx_id,
        "parent_tx_id": parent_tx_id,
        "ts": ts,
        "kind": kind,
        "actor_id": actor_id,
        "payload_hash": payload_hash,
        "payload": payload,
        "signature": None,
    }
    if sign:
        unsigned = {k: v_ for k, v_ in rec.items() if k != "signature"}
        sig_b64 = base64.b64encode(priv.sign(_canonical(unsigned))).decode("ascii")
        rec["signature"] = f"{kid}:{sig_b64}"
    return rec


# ── Hermeticity & AST safety ─────────────────────────────────────────────────

def test_zero_internal_imports_and_no_dynamic_exec():
    tree = ast.parse(Path(v.__file__).read_text(encoding="utf-8"))
    banned_calls = {
        "eval", "exec", "compile", "__import__", "system", "popen",
        "loads_pickle", "load", "execfile", "run_path", "import_module",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            fn = node.func
            name = fn.id if isinstance(fn, ast.Name) else fn.attr if isinstance(fn, ast.Attribute) else None
            owner = fn.value.id if isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name) else None
            if name in banned_calls and (owner, name) not in {("json", "load"), ("re", "compile")}:
                raise AssertionError(f"Forbidden call: {owner}.{name}" if owner else f"Forbidden call: {name}")

    allowed_non_stdlib = {"cryptography"}
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])

    assert not imported & {"pickle", "marshal", "shelve", "subprocess", "runpy", "importlib", "code", "yaml"}
    stdlib = getattr(sys, "stdlib_module_names", set())
    if stdlib:
        unexpected = imported - stdlib - allowed_non_stdlib
        assert not unexpected, f"Unexpected third-party/internal imports: {unexpected}"


def test_public_exports_and_version_parity():
    pyproject = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert f'version = "{totum_verify.__version__}"' in pyproject
    assert callable(verify_chain)
    assert callable(verify_receipt)
    assert issubclass(RemoteFetchError, Exception)


# ── Chain & checkpoint verification ──────────────────────────────────────────

def test_clean_chain_with_pre_chain_rows_and_signed_checkpoint(tmp_path):
    feed_path, meta_path, head_hash, length = _build_chain(tmp_path, count=4, pre_chain=2)
    priv, pub_b64, kid = _make_keypair("k-ckpt-1")
    ckpt_unsigned = {
        "kid": kid,
        "ts_utc": "2026-11-23T20:00:00Z",
        "head_hash": head_hash,
        "length": length,
        "schema_version": 1,
    }
    ckpt = {**ckpt_unsigned, "sig_b64": base64.b64encode(priv.sign(_canonical(ckpt_unsigned))).decode("ascii")}
    ckpt_path = tmp_path / "checkpoints.jsonl"
    ckpt_path.write_text(json.dumps(ckpt) + "\n", encoding="utf-8")
    keys_path = tmp_path / "keys.json"
    keys_path.write_text(json.dumps({"current": kid, "keys": {kid: {"alg": "ed25519", "pub_b64": pub_b64}}}), encoding="utf-8")

    res = verify_chain(
        feed_paths=[feed_path],
        meta_path=meta_path,
        checkpoints_path=ckpt_path,
        keys_path=keys_path,
    )
    assert res["ok"] is True
    assert res["length"] == 4
    assert res["pre_chain_count"] == 2
    assert res["checkpoint_count"] == 1
    assert res["head_hash"] == head_hash
    assert res["kid"] == kid


def test_tampered_chain_fails_at_exact_index(tmp_path):
    feed_path, meta_path, _, _ = _build_chain(tmp_path, count=4)
    tampered = feed_path.read_text(encoding="utf-8").replace("payload-2", "tampered-2", 1)
    feed_path.write_text(tampered, encoding="utf-8")

    res = verify_chain(feed_paths=[feed_path], meta_path=meta_path)
    assert res["ok"] is False
    assert res["first_break_index"] == 1


def test_checkpoints_only_plain_text_has_no_negative_one_rows(monkeypatch, capsys):
    priv, pub_b64, kid = _make_keypair("k-only-1")
    meta_bytes = _canonical({"chain_id": "atelier_audit_chain_v3", "alg": "sha256", "schema_version": 1})
    keys_bytes = _canonical({"current": kid, "keys": {kid: {"alg": "ed25519", "pub_b64": pub_b64}}})
    ckpt_u = {"kid": kid, "ts_utc": "2026-11-23T20:00:00Z", "head_hash": "a" * 64, "length": 10, "schema_version": 1}
    ckpt_b = (_canonical({**ckpt_u, "sig_b64": base64.b64encode(priv.sign(_canonical(ckpt_u))).decode("ascii")}).decode() + "\n").encode()
    artifacts = {"meta": meta_bytes, "keys": keys_bytes, "checkpoints": ckpt_b}
    monkeypatch.setattr(v, "_fetch", lambda _url, kind: artifacts[kind])
    monkeypatch.setattr(sys, "argv", ["totum-verify", "--remote", "https://example.com"])

    with pytest.raises(SystemExit) as exc:
        v.main()
    assert exc.value.code == 0
    err = capsys.readouterr().err
    assert "-1 rows" not in err
    assert "OK · checkpoints-only mode · 1 checkpoints" in err


# ── Single-receipt offline verification ──────────────────────────────────────

def test_verify_receipt_tx_and_checkpoint_valid_and_tampered(tmp_path):
    priv, pub_b64, kid = _make_keypair("k-tx-1")
    rec = _make_signed_tx_receipt(priv, kid, sign=True)

    assert verify_receipt(rec, {"kid": kid, "pub_b64": pub_b64})["ok"] is True
    assert verify_receipt(rec, {"current": kid, "keys": {kid: {"pub_b64": pub_b64}}})["ok"] is True

    bad_payload = json.loads(json.dumps(rec))
    bad_payload["payload"]["cost_usd"] = 100.0
    r1 = verify_receipt(bad_payload, {"kid": kid, "pub_b64": pub_b64})
    assert r1["ok"] is False and "tx_payload_hash_mismatch" in r1["errors"]

    bad_actor = json.loads(json.dumps(rec))
    bad_actor["actor_id"] = "other"
    r2 = verify_receipt(bad_actor, {"kid": kid, "pub_b64": pub_b64})
    assert r2["ok"] is False and "tx_id_mismatch" in r2["errors"]

    unsigned = _make_signed_tx_receipt(priv, kid, sign=False)
    assert verify_receipt(unsigned, {"kid": kid, "pub_b64": pub_b64})["ok"] is False
    assert verify_receipt(unsigned, {"kid": kid, "pub_b64": pub_b64}, require_signature=False)["ok"] is True

    # CLI subprocess invocation via python -m totum_verify
    rec_path = tmp_path / "receipt.json"
    key_path = tmp_path / "pubkey.json"
    rec_path.write_text(json.dumps(rec), encoding="utf-8")
    key_path.write_text(json.dumps({"kid": kid, "pub_b64": pub_b64}), encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, "-m", "totum_verify", "--receipt", str(rec_path), "--keys", str(key_path), "--json"],
        cwd=str(REPO_ROOT),
        env={"PYTHONPATH": str(REPO_ROOT / "src")},
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout)["signature_state"] == "verified"


# ── Remote SSRF & transport hardening ────────────────────────────────────────

@pytest.mark.parametrize("url", [
    "http://example.com",
    "https://user:pw@example.com",
    "https://example.com/?q=1",
    "https://127.0.0.1",
    "https://169.254.169.254",
    "https://[::1]",
    "https://[::ffff:127.0.0.1]",
    "https://localhost",
    "https://metadata.google.internal",
])
def test_remote_url_rejects_unsafe_targets(url):
    with pytest.raises(RemoteFetchError) as exc:
        v._validate_remote_url(url)
    assert exc.value.code == 2


def test_split_dns_non_public_answer_refused(monkeypatch):
    def fake_getaddrinfo(host, port, *a, **k):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", port)),
        ]
    monkeypatch.setattr(v.socket, "getaddrinfo", fake_getaddrinfo)
    with pytest.raises(RemoteFetchError, match="non-public address"):
        v._http_get("https://rebind.example.com/.well-known/x", "meta")


def test_missing_and_corrupt_feed_fail_closed(tmp_path):
    meta_path = tmp_path / "chain_meta.json"
    meta_path.write_text(json.dumps({"chain_id": "test", "alg": "sha256", "schema_version": 1}), encoding="utf-8")
    assert verify_chain(feed_paths=[tmp_path / "missing.jsonl"], meta_path=meta_path)["ok"] is False
    bad = tmp_path / "bad.jsonl"
    bad.write_text('{"ts":"2026-11-23T00:00:00Z"}\n{not-json\n', encoding="utf-8")
    res = verify_chain(feed_paths=[bad], meta_path=meta_path)
    assert res["ok"] is False and res["first_break_index"] == 1


def test_checkpoints_only_cli_fails_closed_on_zero_checkpoints(monkeypatch):
    priv, pub_b64, kid = _make_keypair("k-empty")
    artifacts = {
        "meta": _canonical({"chain_id": "atelier_audit_chain_v3", "alg": "sha256", "schema_version": 1}),
        "keys": _canonical({"current": kid, "keys": {kid: {"alg": "ed25519", "pub_b64": pub_b64}}}),
        "checkpoints": b"",
    }
    monkeypatch.setattr(v, "_fetch", lambda _u, k: artifacts[k])
    monkeypatch.setattr(sys, "argv", ["totum-verify", "--remote", "https://example.com"])
    with pytest.raises(SystemExit) as exc:
        v.main()
    assert exc.value.code == 1


def test_checkpoint_head_hash_and_truncation_detected(tmp_path):
    feed_path, meta_path, head_hash, length = _build_chain(tmp_path, count=3)
    priv, pub_b64, kid = _make_keypair("k-bind")
    keys_path = tmp_path / "keys.json"
    keys_path.write_text(json.dumps({"current": kid, "keys": {kid: {"alg": "ed25519", "pub_b64": pub_b64}}}), encoding="utf-8")

    def _ckpt(h: str, n: int) -> Path:
        u = {"kid": kid, "ts_utc": "2026-11-23T12:00:00Z", "head_hash": h, "length": n, "schema_version": 1}
        p = tmp_path / "checkpoints.jsonl"
        p.write_text(json.dumps({**u, "sig_b64": base64.b64encode(priv.sign(_canonical(u))).decode()}) + "\n", encoding="utf-8")
        return p

    assert verify_chain(feed_paths=[feed_path], meta_path=meta_path, checkpoints_path=_ckpt(head_hash, length), keys_path=keys_path)["ok"] is True
    assert verify_chain(feed_paths=[feed_path], meta_path=meta_path, checkpoints_path=_ckpt("0" * 64, length), keys_path=keys_path)["ok"] is False
    assert verify_chain(feed_paths=[feed_path], meta_path=meta_path, checkpoints_path=_ckpt(head_hash, length + 2), keys_path=keys_path)["ok"] is False
