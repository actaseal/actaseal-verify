"""A receipt signed under a rotated-out key is genuine evidence; a forged
or tampered one is not. Before --receipt-keyring, a relying party pinning
the operator's current key got the same answer for both, so a customer's
real year-old receipt read as forged the day the key rotated.

With --receipt-keyring (the operator's /.well-known/actaseal-keys.json),
both standalone verifiers check the receipt against the key its own
key_id names, and report one of five distinct codes, always with that
key_id:

  RECEIPT_KEY_CURRENT       pass, signed under the active key
  RECEIPT_KEY_ROTATED_OUT   pass, signed under a retired (not revoked) key
  RECEIPT_KEY_UNKNOWN       fail, key_id not in the keyring (not evaluated)
  RECEIPT_SIGNATURE_INVALID fail, does not verify under that key_id's key
  RECEIPT_KEY_REVOKED       fail, verifies, but that key was revoked
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parent.parent
VERIFY = ROOT / "verify.py"
VERIFY_RECEIPT = ROOT / "verify_receipt.py"
DEMO = ROOT / "demo" / "demo-packet-unanchored"

KEY_CODES = {
    "RECEIPT_KEY_CURRENT",
    "RECEIPT_KEY_ROTATED_OUT",
    "RECEIPT_KEY_UNKNOWN",
    "RECEIPT_SIGNATURE_INVALID",
    "RECEIPT_KEY_REVOKED",
}

_spec = importlib.util.spec_from_file_location("_verify_mod", VERIFY)
_verify = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_verify)


def _codes(stdout):
    return {code for code in KEY_CODES if code in stdout}


def _entry(kid, pub_hex, *, active=False, revoked=False):
    return {
        "kid": kid,
        "public_key_hex": pub_hex,
        "created_at": "2026-01-01T00:00:00Z",
        "active": active,
        "revoked": revoked,
        "revoked_reason": "key compromise" if revoked else None,
        "revoked_at": "2026-06-01T00:00:00Z" if revoked else None,
    }


def _keyring(tmp_path, *entries):
    path = tmp_path / "actaseal-keys.json"
    path.write_text(json.dumps({"format": "actaseal-keys.v1", "keys": list(entries)}), encoding="utf-8")
    return path


def _other_pub():
    return Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()


# ---- verify.py (full packet) ----------------------------------------------

def _packet(tmp_path):
    dest = tmp_path / "packet"
    shutil.copytree(DEMO, dest)
    manifest = json.loads((dest / "manifest.json").read_text())
    receipt = json.loads((dest / "receipt.json").read_text())
    return dest, receipt["key_id"], manifest["receipt_public_key_hex"]


def _run_packet(packet, *flags):
    return subprocess.run(
        [sys.executable, str(VERIFY), str(packet), *flags], capture_output=True, text=True, timeout=30
    )


def _packet_cases(tmp_path):
    packet, kid, pub = _packet(tmp_path)
    cases = {}
    cases["current"] = (packet, _keyring(tmp_path / "c", _entry(kid, pub, active=True)))
    cases["rotated_out"] = (
        packet,
        _keyring(tmp_path / "r", _entry(kid, pub), _entry("key-2", _other_pub(), active=True)),
    )
    cases["unknown"] = (packet, _keyring(tmp_path / "u", _entry("key-2", _other_pub(), active=True)))
    tampered = tmp_path / "tampered"
    shutil.copytree(packet, tampered)
    receipt = json.loads((tampered / "receipt.json").read_text())
    receipt["reason_code"] = str(receipt.get("reason_code")) + "_EDITED"
    (tampered / "receipt.json").write_text(json.dumps(receipt))
    cases["tampered"] = (tampered, _keyring(tmp_path / "t", _entry(kid, pub, active=True)))
    cases["revoked"] = (packet, _keyring(tmp_path / "v", _entry(kid, pub, revoked=True)))
    return kid, cases


@pytest.fixture
def packet_cases(tmp_path):
    for sub in ("c", "r", "u", "t", "v"):
        (tmp_path / sub).mkdir()
    return _packet_cases(tmp_path)


EXPECTED = {
    "current": (0, "RECEIPT_KEY_CURRENT"),
    "rotated_out": (0, "RECEIPT_KEY_ROTATED_OUT"),
    "unknown": (1, "RECEIPT_KEY_UNKNOWN"),
    "tampered": (1, "RECEIPT_SIGNATURE_INVALID"),
    "revoked": (1, "RECEIPT_KEY_REVOKED"),
}


@pytest.mark.parametrize("case", sorted(EXPECTED))
def test_packet_verifier_keyring_outcome(packet_cases, case):
    kid, cases = packet_cases
    packet, keyring = cases[case]
    result = _run_packet(packet, "--receipt-keyring", str(keyring))
    exit_code, code = EXPECTED[case]
    assert result.returncode == exit_code, result.stdout
    assert _codes(result.stdout) == {code}, result.stdout
    assert kid in result.stdout, result.stdout


def test_packet_verifier_forgery_reusing_real_key_id_is_signature_invalid(tmp_path):
    packet, kid, pub = _packet(tmp_path)
    manifest = json.loads((packet / "manifest.json").read_text())
    receipt = json.loads((packet / "receipt.json").read_text())
    attacker = Ed25519PrivateKey.generate()
    attacker_pub = attacker.public_key().public_bytes_raw().hex()
    receipt["signer_pubkey_hash"] = hashlib.sha256(bytes.fromhex(attacker_pub)).hexdigest()
    auth = json.loads((packet / "authentication.json").read_text())
    auth["signer_pubkey_hash"] = receipt["signer_pubkey_hash"]
    (packet / "authentication.json").write_text(json.dumps(auth))
    unsigned = {k: v for k, v in receipt.items() if k not in ("signature", "tsa_anchor")}
    receipt["signature"] = attacker.sign(_verify.canonical_dumps(unsigned).encode("utf-8")).hex()
    manifest["receipt_public_key_hex"] = attacker_pub
    (packet / "manifest.json").write_text(json.dumps(manifest))
    (packet / "receipt.json").write_text(json.dumps(receipt))
    keyring = _keyring(tmp_path, _entry(kid, pub, active=True))
    result = _run_packet(packet, "--receipt-keyring", str(keyring))
    assert result.returncode == 1, result.stdout
    assert "RECEIPT_SIGNATURE_INVALID" in result.stdout


def test_packet_verifier_rejects_keyring_and_pin_together(tmp_path):
    packet, kid, pub = _packet(tmp_path)
    keyring = _keyring(tmp_path, _entry(kid, pub, active=True))
    result = _run_packet(packet, "--receipt-keyring", str(keyring), "--receipt-public-key", pub)
    assert result.returncode == 2, result.stdout


def test_packet_verifier_unreadable_keyring_is_unable_to_run(tmp_path):
    packet, _, _ = _packet(tmp_path)
    bad = tmp_path / "bad.json"
    bad.write_text("[1, 2]", encoding="utf-8")
    result = _run_packet(packet, "--receipt-keyring", str(bad))
    assert result.returncode == 2, result.stdout
    assert "UNABLE_TO_RUN" in result.stdout


# ---- verify_receipt.py (single receipt) ------------------------------------

def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def _receipt_document(kid="op-key-1"):
    private_key = Ed25519PrivateKey.generate()
    pub = private_key.public_key().public_bytes_raw().hex()
    receipt = {
        "receipt_id": "rcpt_keyring_1",
        "decision": "ALLOW",
        "action_id": "act_1",
        "algorithm": "ed25519",
        "key_id": kid,
        "signer_pubkey_hash": hashlib.sha256(bytes.fromhex(pub)).hexdigest(),
    }
    receipt["signature"] = private_key.sign(_canonical(receipt).encode("utf-8")).hex()
    return {"receipt": receipt, "receipt_public_key_hex": pub}, kid, pub


def _run_receipt(tmp_path, document, *flags):
    path = tmp_path / "receipt_document.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return subprocess.run(
        [sys.executable, str(VERIFY_RECEIPT), str(path), *flags], capture_output=True, text=True, timeout=30
    )


def _receipt_cases(tmp_path):
    document, kid, pub = _receipt_document()
    tampered = json.loads(json.dumps(document))
    tampered["receipt"]["decision"] = "DENY"
    return kid, {
        "current": (document, (_entry(kid, pub, active=True),)),
        "rotated_out": (document, (_entry(kid, pub), _entry("op-key-2", _other_pub(), active=True))),
        "unknown": (document, (_entry("op-key-2", _other_pub(), active=True),)),
        "tampered": (tampered, (_entry(kid, pub, active=True),)),
        "revoked": (document, (_entry(kid, pub, revoked=True),)),
    }


@pytest.mark.parametrize("case", sorted(EXPECTED))
def test_receipt_verifier_keyring_outcome(tmp_path, case):
    kid, cases = _receipt_cases(tmp_path)
    document, entries = cases[case]
    keyring = _keyring(tmp_path, *entries)
    result = _run_receipt(tmp_path, document, "--receipt-keyring", str(keyring))
    exit_code, code = EXPECTED[case]
    assert result.returncode == exit_code, result.stdout
    assert _codes(result.stdout) == {code}, result.stdout
    assert kid in result.stdout, result.stdout


EXPECTED_VERDICT = {
    "current": ("CRYPTOGRAPHICALLY_VALID", "ACCEPTED"),
    "rotated_out": ("CRYPTOGRAPHICALLY_VALID", "ACCEPTED"),
    "unknown": ("NOT_EVALUATED", "REJECTED"),
    "tampered": ("CRYPTOGRAPHICALLY_INVALID", "REJECTED"),
    "revoked": ("CRYPTOGRAPHICALLY_VALID", "REJECTED"),
}


@pytest.mark.parametrize("case", sorted(EXPECTED_VERDICT))
def test_receipt_verifier_emitted_result_names_key_and_keeps_verdicts_apart(tmp_path, case):
    kid, cases = _receipt_cases(tmp_path)
    document, entries = cases[case]
    keyring = _keyring(tmp_path, *entries)
    result = _run_receipt(tmp_path, document, "--receipt-keyring", str(keyring), "--emit-result")
    emitted = json.loads(result.stdout.strip().splitlines()[-1])
    verdict, outcome = EXPECTED_VERDICT[case]
    assert emitted["verdict"] == verdict, emitted
    assert emitted["outcome"] == outcome, emitted
    assert emitted["receipt_key"]["key_id"] == kid, emitted
    assert emitted["receipt_key"]["status"] == EXPECTED[case][1], emitted


def test_unknown_key_under_declared_complete_trust_is_policy_refusal(tmp_path):
    kid, cases = _receipt_cases(tmp_path)
    document, entries = cases["unknown"]
    keyring = _keyring(tmp_path, *entries)
    result = _run_receipt(
        tmp_path, document, "--receipt-keyring", str(keyring), "--trust-material-complete", "--emit-result"
    )
    emitted = json.loads(result.stdout.strip().splitlines()[-1])
    assert emitted["verdict"] == "NOT_EVALUATED"
    assert emitted["disposition"] == "REFUSED_BY_POLICY"


def test_receipt_verifier_rejects_keyring_and_pin_together(tmp_path):
    document, kid, pub = _receipt_document()
    keyring = _keyring(tmp_path, _entry(kid, pub, active=True))
    result = _run_receipt(tmp_path, document, "--receipt-keyring", str(keyring), "--receipt-public-key", pub)
    assert result.returncode == 2, result.stdout
