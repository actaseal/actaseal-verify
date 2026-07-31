"""Conformance vectors for verify.py's additive RFC 3161 / SCITT-receipt
checks (verify_rfc3161_token, verify_scitt_receipt) -- a different
artifact type (AS 1215 archive attestations) from the dispute-packet
vectors in conformance/vectors/{valid,tampered_*,wrong_signature,
rotated_key_still_verifies}/, which test_conformance.py already covers.

Requires asn1crypto (`pip install actaseal[rfc3161]`) for the RFC 3161
vectors specifically; the SCITT-receipt vectors need only cryptography,
same as the rest of this repo's base install.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
VECTOR_DIR = Path(__file__).resolve().parent / "vectors" / "archive_attestation_v1"


def _load_verify_module():
    spec = importlib.util.spec_from_file_location("verify", REPO_ROOT / "verify.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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


@pytest.mark.parametrize(
    "name",
    ["rfc3161_token_pass.json", "rfc3161_token_fail_hash_mismatch.json", "rfc3161_token_fail_no_trusted_root.json"],
)
def test_rfc3161_vector(name):
    pytest.importorskip("asn1crypto")
    verify = _load_verify_module()
    vector = json.loads((VECTOR_DIR / name).read_text())
    ca_cert_paths = [str(REPO_ROOT / p) for p in vector["ca_cert_paths"]]
    ok, failures = verify.verify_rfc3161_token(vector["token_der_hex"], vector["hash_hex"], ca_cert_paths)
    assert ok == vector["expected_ok"], f"{name}: {failures}"
    if not vector["expected_ok"]:
        assert any(vector["expected_failure_substring"] in f for f in failures), failures


@pytest.mark.parametrize("name", ["scitt_receipt_pass.json", "scitt_receipt_fail_tampered_leaf.json"])
def test_scitt_receipt_vector(name):
    verify = _load_verify_module()
    vector = json.loads((VECTOR_DIR / name).read_text())
    ok, failures = verify.verify_scitt_receipt(
        vector["subject_hash_hex"], vector["receipt"], vector["sth_public_key_hex"], _crypto()
    )
    assert ok == vector["expected_ok"], f"{name}: {failures}"
    if not vector["expected_ok"]:
        assert any(vector["expected_failure_substring"] in f for f in failures), failures
