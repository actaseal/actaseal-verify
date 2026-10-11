"""verify_receipt.py: the same key-binding hole verify.py had.

A single-receipt document carries its own receipt_public_key_hex. Before
this, re-signing the receipt with any fresh key and swapping that key in
printed PASS / SIGNATURE_VERIFIED, even though the signed receipt's own
signer_pubkey_hash still named the real signer. Now:

1. signer_pubkey_hash (sha256 of the public key bytes) must match the
   document's key -- RECEIPT_SIGNER_PUBKEY_HASH_MISMATCH otherwise.
2. --receipt-public-key HEX pins the operator's published key --
   RECEIPT_KEY_NOT_TRUSTED otherwise. Without it, PASS output says the key
   was not independently checked.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parent.parent
VERIFIER = ROOT / "verify_receipt.py"


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def _key():
    private_key = Ed25519PrivateKey.generate()
    return private_key, private_key.public_key().public_bytes_raw().hex()


def _signed(private_key, receipt):
    unsigned = {k: v for k, v in receipt.items() if k not in ("signature", "tsa_anchor")}
    signed = dict(unsigned)
    signed["signature"] = private_key.sign(_canonical(unsigned).encode("utf-8")).hex()
    return signed


def _base_receipt(signer_pubkey_hash):
    return {
        "receipt_id": "rcpt_key_binding_1",
        "decision": "ALLOW",
        "action_id": "act_1",
        "algorithm": "ed25519",
        "signer_pubkey_hash": signer_pubkey_hash,
    }


def _hash(pub_hex):
    return hashlib.sha256(bytes.fromhex(pub_hex)).hexdigest()


def _run(tmp_path, document, *flags):
    path = tmp_path / "receipt_document.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return subprocess.run(
        [sys.executable, str(VERIFIER), str(path), *flags], capture_output=True, text=True, timeout=30
    )


def _genuine():
    real_private, real_pub = _key()
    receipt = _signed(real_private, _base_receipt(_hash(real_pub)))
    return {"receipt": receipt, "receipt_public_key_hex": real_pub}, real_pub


def _resigned(document, *, rebind_hash):
    attacker_private, attacker_pub = _key()
    receipt = dict(document["receipt"])
    if rebind_hash:
        receipt["signer_pubkey_hash"] = _hash(attacker_pub)
    return {"receipt": _signed(attacker_private, receipt), "receipt_public_key_hex": attacker_pub}


def test_resigned_receipt_with_unrebound_signed_hash_fails(tmp_path):
    genuine, _ = _genuine()
    result = _run(tmp_path, _resigned(genuine, rebind_hash=False))
    assert result.returncode == 1, result.stdout
    assert result.stdout.startswith("FAIL"), result.stdout
    assert "RECEIPT_SIGNER_PUBKEY_HASH_MISMATCH" in result.stdout


def test_hash_mismatch_is_a_failed_signature_check_in_emitted_result(tmp_path):
    genuine, _ = _genuine()
    result = _run(tmp_path, _resigned(genuine, rebind_hash=False), "--emit-result")
    emitted = json.loads(result.stdout.strip().splitlines()[-1])
    assert emitted["verdict"] == "CRYPTOGRAPHICALLY_INVALID"
    assert emitted["outcome"] == "REJECTED"
    assert emitted["failed_checks"] == ["signature"]


def test_genuine_receipt_without_pin_says_key_was_not_independently_checked(tmp_path):
    genuine, real_pub = _genuine()
    result = _run(tmp_path, genuine)
    assert result.returncode == 0, result.stdout
    assert "SIGNATURE_VERIFIED" in result.stdout
    assert "receipt key NOT checked against an independent key" in result.stdout
    assert real_pub in result.stdout


def test_genuine_receipt_with_correct_pin_passes(tmp_path):
    genuine, real_pub = _genuine()
    result = _run(tmp_path, genuine, "--receipt-public-key", real_pub)
    assert result.returncode == 0, result.stdout
    assert "receipt key matches --receipt-public-key" in result.stdout
    assert "NOT checked against an independent key" not in result.stdout


def test_fully_consistent_forgery_passes_unpinned_but_fails_pinned(tmp_path):
    genuine, real_pub = _genuine()
    forged = _resigned(genuine, rebind_hash=True)
    unpinned = _run(tmp_path, forged)
    assert unpinned.returncode == 0, unpinned.stdout
    assert "NOT checked against an independent key" in unpinned.stdout
    pinned = _run(tmp_path, forged, "--receipt-public-key", real_pub)
    assert pinned.returncode == 1, pinned.stdout
    assert "RECEIPT_KEY_NOT_TRUSTED" in pinned.stdout


def test_pin_flag_requires_a_value(tmp_path):
    genuine, _ = _genuine()
    result = _run(tmp_path, genuine, "--receipt-public-key")
    assert result.returncode == 2, result.stdout
    assert "--receipt-public-key requires a value" in result.stdout
