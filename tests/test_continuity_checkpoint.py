"""T8 (ONESHOT-4 batch 3, mirrored from the private repo): verify.py's
optional continuity-checkpoint check -- checkpoint.json (a signed tree
head) + inclusion_proof.json, proving a receipt is anchored under an
independently-signed, published checkpoint. Silent no-op when absent
(same posture as --anchors); additive to a plain dispute packet.

Builds its own tiny Merkle tree here with only stdlib + 'cryptography',
same "no actaseal import" posture as generate_demo_packet.py -- this
test module has no access to actaseal.anchoring, so the RFC 6962 leaf/
node hashing is reproduced inline rather than imported.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parent.parent
VERIFY_PY = ROOT / "verify.py"
GENERATOR = ROOT / "generate_demo_packet.py"

sys.path.insert(0, str(ROOT))
import generate_demo_packet as gen  # noqa: E402


def _run_verify(packet_dir: Path) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(VERIFY_PY), str(packet_dir)], capture_output=True, text=True)


def _leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _merkle_root(leaves: list[bytes]) -> bytes:
    if len(leaves) == 1:
        return leaves[0]
    split = 1
    while split * 2 < len(leaves):
        split *= 2
    return _node_hash(_merkle_root(leaves[:split]), _merkle_root(leaves[split:]))


def _audit_path(index: int, leaves: list[bytes]) -> list[bytes]:
    if len(leaves) <= 1:
        return []
    split = 1
    while split * 2 < len(leaves):
        split *= 2
    if index < split:
        return _audit_path(index, leaves[:split]) + [_merkle_root(leaves[split:])]
    return _audit_path(index - split, leaves[split:]) + [_merkle_root(leaves[:split])]


def _compute_receipt_hash(receipt: dict) -> str:
    unsigned = dict(receipt)
    unsigned.pop("signature", None)
    unsigned.pop("tsa_anchor", None)
    return gen.canonical_hash(unsigned)


def _write_checkpoint(packet_dir: Path, receipt_hash_hex: str, *, tamper_root=None, tamper_signature=False):
    leaves = [_leaf_hash(f"other-{i}".encode()) for i in range(3)]
    index = 2
    leaves.insert(index, _leaf_hash(receipt_hash_hex.encode()))

    root = _merkle_root(leaves)
    signing_key = Ed25519PrivateKey.generate()
    payload = {
        "log_id": "public-demo-log-1",
        "tree_size": len(leaves),
        "root_hash": root.hex(),
        "timestamp": "2026-07-19T00:00:00+00:00",
    }
    signature = signing_key.sign(gen.canonical_dumps(payload).encode("utf-8")).hex()
    if tamper_signature:
        signature = ("0" if signature[0] != "0" else "1") + signature[1:]
    sth = dict(payload, key_id="sth-demo-1", algorithm="ed25519", signature=signature)
    if tamper_root is not None:
        sth["root_hash"] = tamper_root

    public_key_hex = signing_key.public_key().public_bytes_raw().hex()
    checkpoint = {"sth": sth, "sth_public_key_hex": public_key_hex}
    (packet_dir / "checkpoint.json").write_text(gen.canonical_dumps(checkpoint), encoding="utf-8")

    proof = {
        "log_id": "public-demo-log-1",
        "entry_id": str(index),
        "signed_timestamp": "2026-07-19T00:00:00+00:00",
        "leaf_hash": leaves[index].hex(),
        "audit_path": [node.hex() for node in _audit_path(index, leaves)],
        "sth_root": root.hex(),
        "sth_tree_size": len(leaves),
    }
    (packet_dir / "inclusion_proof.json").write_text(gen.canonical_dumps(proof), encoding="utf-8")
    return checkpoint, proof


def test_valid_checkpoint_and_inclusion_proof_pass(tmp_path):
    subprocess.run([sys.executable, str(GENERATOR), str(tmp_path)], check=True)
    packet_dir = tmp_path / "demo-packet-unanchored"
    receipt = json.loads((packet_dir / "receipt.json").read_text())
    _write_checkpoint(packet_dir, _compute_receipt_hash(receipt))

    result = _run_verify(packet_dir)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "VERIFIED" in result.stdout


def test_packet_without_checkpoint_is_unaffected(tmp_path):
    subprocess.run([sys.executable, str(GENERATOR), str(tmp_path)], check=True)
    packet_dir = tmp_path / "demo-packet-unanchored"
    result = _run_verify(packet_dir)
    assert result.returncode == 0, result.stdout + result.stderr


def test_tampered_sth_root_fails(tmp_path):
    subprocess.run([sys.executable, str(GENERATOR), str(tmp_path)], check=True)
    packet_dir = tmp_path / "demo-packet-unanchored"
    receipt = json.loads((packet_dir / "receipt.json").read_text())
    _write_checkpoint(packet_dir, _compute_receipt_hash(receipt), tamper_root="1" * 64)

    result = _run_verify(packet_dir)
    assert result.returncode == 1
    assert "STH_SIGNATURE_INVALID" in result.stdout


def test_tampered_sth_signature_fails(tmp_path):
    subprocess.run([sys.executable, str(GENERATOR), str(tmp_path)], check=True)
    packet_dir = tmp_path / "demo-packet-unanchored"
    receipt = json.loads((packet_dir / "receipt.json").read_text())
    _write_checkpoint(packet_dir, _compute_receipt_hash(receipt), tamper_signature=True)

    result = _run_verify(packet_dir)
    assert result.returncode == 1
    assert "STH_SIGNATURE_INVALID" in result.stdout


def test_forged_inclusion_proof_leaf_fails(tmp_path):
    subprocess.run([sys.executable, str(GENERATOR), str(tmp_path)], check=True)
    packet_dir = tmp_path / "demo-packet-unanchored"
    receipt = json.loads((packet_dir / "receipt.json").read_text())
    _write_checkpoint(packet_dir, _compute_receipt_hash(receipt))

    proof = json.loads((packet_dir / "inclusion_proof.json").read_text())
    real_leaf = proof["leaf_hash"]
    proof["leaf_hash"] = ("0" if real_leaf[0] != "0" else "1") + real_leaf[1:]
    (packet_dir / "inclusion_proof.json").write_text(gen.canonical_dumps(proof), encoding="utf-8")

    result = _run_verify(packet_dir)
    assert result.returncode == 1
    assert "ANCHOR_INCLUSION_PROOF_INVALID" in result.stdout


def test_inclusion_proof_naming_a_different_checkpoint_fails(tmp_path):
    subprocess.run([sys.executable, str(GENERATOR), str(tmp_path)], check=True)
    packet_dir = tmp_path / "demo-packet-unanchored"
    receipt = json.loads((packet_dir / "receipt.json").read_text())
    _write_checkpoint(packet_dir, _compute_receipt_hash(receipt))

    proof = json.loads((packet_dir / "inclusion_proof.json").read_text())
    proof["sth_tree_size"] = proof["sth_tree_size"] + 1
    (packet_dir / "inclusion_proof.json").write_text(gen.canonical_dumps(proof), encoding="utf-8")

    result = _run_verify(packet_dir)
    assert result.returncode == 1
    assert "ANCHOR_CHECKPOINT_MISMATCH" in result.stdout
