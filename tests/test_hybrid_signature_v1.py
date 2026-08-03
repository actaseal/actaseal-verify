"""ONESHOT-MONEY T2 (ActaSeal private repo): the public verifier must
accept hybrid Ed25519+ML-DSA-65 receipts, or the private repo's
crypto-agility/longevity claim is hollow. Calls verify.py's
verify_receipt() directly (no full packet needed) against constructed
manifest/receipt dicts.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import verify as v  # noqa: E402


def canonical_dumps(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def canonical_hash(value):
    return hashlib.sha256(canonical_dumps(value).encode("utf-8")).hexdigest()


def _crypto():
    from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import load_der_public_key

    return {
        "ed25519_public_key_cls": Ed25519PublicKey,
        "invalid_signature_error": InvalidSignature,
        "unsupported_algorithm_error": UnsupportedAlgorithm,
        "load_der_public_key": load_der_public_key,
        "ecdsa_sha256": ec.ECDSA(hashes.SHA256()),
    }


def _oqs_available():
    try:
        import oqs  # noqa: F401
    except ImportError:
        return False
    return True


def _hybrid_receipt_and_key():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    import oqs

    ed_priv = Ed25519PrivateKey.generate()
    ed_pub_hex = ed_priv.public_key().public_bytes_raw().hex() if hasattr(
        ed_priv.public_key(), "public_bytes_raw"
    ) else ed_priv.public_key().public_bytes(
        __import__("cryptography.hazmat.primitives.serialization", fromlist=["Encoding"]).Encoding.Raw,
        __import__("cryptography.hazmat.primitives.serialization", fromlist=["PublicFormat"]).PublicFormat.Raw,
    ).hex()

    with oqs.Signature("ML-DSA-65") as pq_signer:
        pq_pub_hex = pq_signer.generate_keypair().hex()

        receipt = {
            "decision": "ALLOW",
            "reason_code": "OK",
            "action_hash": "a" * 64,
            "evidence_set_hash": "b" * 64,
            "ledger_entry_hash": "event-1",
            "timestamp": "2026-08-03T00:00:00+00:00",
            "algorithm": v.ALGORITHM_HYBRID_ED25519_ML_DSA_65,
            "signature": "",
        }
        unsigned = dict(receipt)
        unsigned.pop("signature")
        data = canonical_dumps(unsigned).encode("utf-8")

        ed_sig_hex = ed_priv.sign(data).hex()
        pq_sig_hex = pq_signer.sign(data).hex()
        dotted_sig = f"{ed_sig_hex}.{pq_sig_hex}"
        dotted_pub = f"{ed_pub_hex}.{pq_pub_hex}"
        receipt["signature"] = dotted_sig.encode("ascii").hex()
        public_key_hex = dotted_pub.encode("ascii").hex()

        event = {
            "event_hash": "event-1",
            "action_id": "action-1",
            "action_packet_hash": receipt["action_hash"],
        }
        manifest = {"action_id": "action-1", "receipt_public_key_hex": public_key_hex}
        return manifest, receipt, [event]


@pytest.mark.skipif(not _oqs_available(), reason="liboqs-python (oqs) not available in this environment")
def test_valid_hybrid_receipt_verifies():
    manifest, receipt, events = _hybrid_receipt_and_key()
    failures = []
    v.verify_receipt(manifest, receipt, events, failures, _crypto())
    assert failures == [], failures


@pytest.mark.skipif(not _oqs_available(), reason="liboqs-python (oqs) not available in this environment")
def test_hybrid_receipt_with_stripped_pq_half_fails_downgrade():
    manifest, receipt, events = _hybrid_receipt_and_key()
    dotted_sig = bytes.fromhex(receipt["signature"]).decode("ascii")
    ed_sig_hex = dotted_sig.split(v.HYBRID_PART_SEPARATOR)[0]
    receipt["signature"] = ed_sig_hex.encode("ascii").hex()
    failures = []
    v.verify_receipt(manifest, receipt, events, failures, _crypto())
    assert any("INVALID_HYBRID_FORMAT" in f for f in failures)


def test_hybrid_malformed_format_fails_closed_without_oqs_needed():
    """The format check runs before either half's crypto -- this must
    fail closed even without liboqs installed."""
    manifest = {"action_id": "action-1", "receipt_public_key_hex": "not-hex-dot-separated".encode("ascii").hex()}
    receipt = {
        "decision": "ALLOW",
        "action_hash": "a" * 64,
        "ledger_entry_hash": "event-1",
        "algorithm": v.ALGORITHM_HYBRID_ED25519_ML_DSA_65,
        "signature": "aa".encode("ascii").hex(),
    }
    events = [{"event_hash": "event-1", "action_id": "action-1", "action_packet_hash": receipt["action_hash"]}]
    failures = []
    v.verify_receipt(manifest, receipt, events, failures, _crypto())
    assert any("INVALID_HYBRID_FORMAT" in f for f in failures)
