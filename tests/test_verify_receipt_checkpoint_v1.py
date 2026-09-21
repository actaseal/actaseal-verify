"""T5 port: keyless/hash-linked verification mode
(verify_receipt.py --checkpoint). A receipt can PASS on hash-linkage
alone, via an out-of-band trusted checkpoint hash, even when the signing
key is unknown or rotated -- reported as CHAIN_VERIFIED_KEY_UNKNOWN,
never conflated with a real SIGNATURE_VERIFIED PASS, and never conflated
with a generic FAIL either. Ported unchanged from the private repo's
actaseal/dispute/verify_receipt.py (a standalone, non-actaseal-importing
sibling of offline_verifier.py, not subject to that file's byte-pin).
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

ROOT = Path(__file__).resolve().parent.parent
VERIFIER = ROOT / "verify_receipt.py"

MODE_SIGNATURE_VERIFIED = "SIGNATURE_VERIFIED"
MODE_CHAIN_VERIFIED_KEY_UNKNOWN = "CHAIN_VERIFIED_KEY_UNKNOWN"


def canonical_dumps(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def _make_signer():
    private_key = Ed25519PrivateKey.generate()
    public_key_hex = private_key.public_key().public_bytes_raw().hex()
    return private_key, public_key_hex


def _sign(private_key, receipt_without_signature):
    data = canonical_dumps(receipt_without_signature).encode("utf-8")
    signature_hex = private_key.sign(data).hex()
    signed = dict(receipt_without_signature)
    signed["signature"] = signature_hex
    return signed


def _unsigned_receipt(**overrides):
    fields = dict(
        decision="ALLOW",
        reason_code="OK",
        action_hash="a" * 64,
        mandate_hash=None,
        evidence_set_hash="b" * 64,
        ledger_entry_hash="c" * 64,
        approval_event_hash=None,
        agent_id="agent-1",
        tool_name="issue_refund",
        args_hash="d" * 64,
        purpose=None,
        key_id=None,
        rail_anchors_hash=None,
        scope_conformance=None,
        timestamp="2026-07-17T00:00:00+00:00",
    )
    fields.update(overrides)
    return fields


def _chain(receipt, previous_event_hash="genesis"):
    event1 = {"event_hash": "e1", "previous_event_hash": previous_event_hash}
    event2 = {"event_hash": receipt["ledger_entry_hash"], "previous_event_hash": "e1"}
    return [event1, event2]


def _run_cli(tmp_path, document, extra_args=(), name="input.json"):
    path = tmp_path / name
    path.write_text(json.dumps(document))
    result = subprocess.run(
        [sys.executable, str(VERIFIER), str(path), *extra_args],
        capture_output=True,
        text=True,
    )
    return result


def test_rotated_key_receipt_passes_chain_mode_with_correct_verdict_label(tmp_path):
    original_signer, _ = _make_signer()
    receipt = _sign(original_signer, _unsigned_receipt())

    rotated_away_signer, rotated_away_public_key_hex = _make_signer()
    document = {
        "receipt": receipt,
        "receipt_public_key_hex": rotated_away_public_key_hex,
        "ledger_slice": _chain(receipt),
    }
    checkpoint_hash = receipt["ledger_entry_hash"]

    result = _run_cli(tmp_path, document, extra_args=["--checkpoint", checkpoint_hash])

    assert result.returncode == 0, result.stdout + result.stderr
    assert "PASS" in result.stdout
    assert MODE_CHAIN_VERIFIED_KEY_UNKNOWN in result.stdout
    assert MODE_SIGNATURE_VERIFIED not in result.stdout


def test_keyless_mode_with_no_key_at_all_passes_via_checkpoint(tmp_path):
    signer, _ = _make_signer()
    receipt = _sign(signer, _unsigned_receipt())
    document = {
        "receipt": receipt,
        "ledger_slice": _chain(receipt),
    }
    result = _run_cli(tmp_path, document, extra_args=["--checkpoint", receipt["ledger_entry_hash"]])

    assert result.returncode == 0, result.stdout + result.stderr
    assert MODE_CHAIN_VERIFIED_KEY_UNKNOWN in result.stdout


def test_valid_signature_still_wins_and_reports_signature_verified_even_with_checkpoint(tmp_path):
    signer, public_key_hex = _make_signer()
    receipt = _sign(signer, _unsigned_receipt())
    document = {
        "receipt": receipt,
        "receipt_public_key_hex": public_key_hex,
        "ledger_slice": _chain(receipt),
    }
    result = _run_cli(tmp_path, document, extra_args=["--checkpoint", receipt["ledger_entry_hash"]])

    assert result.returncode == 0
    assert MODE_SIGNATURE_VERIFIED in result.stdout
    assert MODE_CHAIN_VERIFIED_KEY_UNKNOWN not in result.stdout


def test_tampered_chain_fails_and_reports_neither_pass_mode(tmp_path):
    signer, _ = _make_signer()
    receipt = _sign(signer, _unsigned_receipt())
    tampered_chain = _chain(receipt)
    tampered_chain[1]["previous_event_hash"] = "not-e1"  # break the link

    unrelated_signer, unrelated_public_key_hex = _make_signer()
    document = {
        "receipt": receipt,
        "receipt_public_key_hex": unrelated_public_key_hex,
        "ledger_slice": tampered_chain,
    }
    result = _run_cli(
        tmp_path, document, extra_args=["--checkpoint", receipt["ledger_entry_hash"]], name="b.json"
    )

    assert result.returncode == 1
    assert "FAIL" in result.stdout
    assert "CHAIN_BROKEN" in result.stdout
    assert MODE_SIGNATURE_VERIFIED not in result.stdout
    assert MODE_CHAIN_VERIFIED_KEY_UNKNOWN not in result.stdout


def test_checkpoint_verdict_is_a_third_distinct_result_never_conflated():
    """Hard requirement: the key-unresolved case (CHAIN_VERIFIED_KEY_UNKNOWN)
    must never be reported as, or treated equal to, a genuine signature
    PASS (SIGNATURE_VERIFIED) or a generic tamper/fail result (FAIL). All
    three must be pairwise distinct string labels -- this is the
    regression the whole feature exists to prevent (a keyless PASS being
    silently upgraded, in a report or a downstream consumer's string
    comparison, into "the signature checked out")."""
    FAIL_LABEL = "FAIL"
    assert MODE_SIGNATURE_VERIFIED != MODE_CHAIN_VERIFIED_KEY_UNKNOWN
    assert MODE_SIGNATURE_VERIFIED != FAIL_LABEL
    assert MODE_CHAIN_VERIFIED_KEY_UNKNOWN != FAIL_LABEL
    labels = {MODE_SIGNATURE_VERIFIED, MODE_CHAIN_VERIFIED_KEY_UNKNOWN, FAIL_LABEL}
    assert len(labels) == 3


def test_checkpoint_hash_not_in_slice_fails_with_specific_reason(tmp_path):
    signer, _ = _make_signer()
    receipt = _sign(signer, _unsigned_receipt())
    document = {
        "receipt": receipt,
        "ledger_slice": _chain(receipt),
    }
    result = _run_cli(tmp_path, document, extra_args=["--checkpoint", "not-in-the-slice"])

    assert result.returncode == 1
    assert "CHECKPOINT_NOT_IN_SLICE" in result.stdout


def test_missing_checkpoint_value_is_malformed_input(tmp_path):
    signer, public_key_hex = _make_signer()
    receipt = _sign(signer, _unsigned_receipt())
    document = {"receipt": receipt, "receipt_public_key_hex": public_key_hex}
    result = _run_cli(tmp_path, document, extra_args=["--checkpoint"])

    assert result.returncode == 2
    assert "MALFORMED_INPUT" in result.stdout


def test_has_no_external_imports_beyond_cryptography_stdlib():
    """Same posture as verify.py: standalone, no actaseal imports."""
    source = VERIFIER.read_text(encoding="utf-8")
    assert "import actaseal" not in source
