"""Conformance test suite for verify_receipt.py's --emit-result structured
output (schema actaseal-verify-result.v1) and the --trust-material-complete
relying-party declaration -- the behavior IETF SCITT PR #463's completeness
requirements describe. Mirrors the four cases TKCollective pinned at
TKCollective/tanilo-receipt-verify@97e09e7's tests/test_jwks_is_complete.py:
  (a) default (not declared complete), unresolvable key -> NOT_EVALUATED/ACCEPTED
  (b) declared complete, same artifact/key material -> NOT_EVALUATED/REFUSED_BY_POLICY
  (c) empty declared-complete key set -> NOT_EVALUATED/REFUSED_BY_POLICY (not INVALID)
  (d) a real signature failure, under both declarations -> CRYPTOGRAPHICALLY_INVALID

Each vector directory under vectors/receipt_scitt_result/ carries
input.json (the document), meta.json (the CLI flags to invoke
verify_receipt.py with), and expected_result.json (the exit code and the
full --emit-result JSON object verify_receipt.py must reproduce exactly
-- captured from a real run by conformance/generate_vectors.py, not
hand-computed; see that file's _run_verify_receipt_emit_result).
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
VECTORS_DIR = Path(__file__).resolve().parent / "vectors" / "receipt_scitt_result"
VERIFY_RECEIPT_PY = REPO_ROOT / "verify_receipt.py"


def _vector_dirs() -> list[Path]:
    if not VECTORS_DIR.exists():
        return []
    return sorted(
        d for d in VECTORS_DIR.rglob("*")
        if d.is_dir() and (d / "input.json").exists() and (d / "meta.json").exists()
    )


def _vector_id(d: Path) -> str:
    return str(d.relative_to(VECTORS_DIR))


def _run(vector_dir: Path) -> subprocess.CompletedProcess:
    meta = json.loads((vector_dir / "meta.json").read_text(encoding="utf-8"))
    cmd = [sys.executable, str(VERIFY_RECEIPT_PY), str(vector_dir / "input.json"), "--emit-result"]
    if meta["checkpoint"] is not None:
        cmd += ["--checkpoint", meta["checkpoint"]]
    if meta["trust_material_complete"]:
        cmd.append("--trust-material-complete")
    return subprocess.run(cmd, capture_output=True, text=True)


@pytest.mark.parametrize("vector_dir", _vector_dirs(), ids=_vector_id)
def test_scitt_result_vector_matches_pinned_expected_result(vector_dir):
    expected = json.loads((vector_dir / "expected_result.json").read_text(encoding="utf-8"))
    completed = _run(vector_dir)

    assert completed.returncode == expected["exit_code"], (
        f"{_vector_id(vector_dir)}: expected exit {expected['exit_code']}, got {completed.returncode}\n"
        f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
    )
    result_line = next(
        (line for line in completed.stdout.splitlines() if line.startswith("{")), None,
    )
    assert result_line is not None, f"{_vector_id(vector_dir)}: no --emit-result JSON line in stdout:\n{completed.stdout}"
    actual_result = json.loads(result_line)
    assert actual_result == expected["result"], (
        f"{_vector_id(vector_dir)}: result mismatch\nexpected: {expected['result']}\nactual:   {actual_result}"
    )


def test_default_output_unchanged_without_emit_result_flag():
    """--emit-result is purely additive: running the same vector WITHOUT
    it must never print a JSON result line, and must still reach the
    same exit code as the pinned vector (exit_code in expected_result.json
    was itself captured WITH --emit-result; this test re-runs without it
    and checks only that nothing resembling the structured line leaks
    into default output and the exit code is unaffected by the flag)."""
    any_checked = False
    for vector_dir in _vector_dirs():
        meta = json.loads((vector_dir / "meta.json").read_text(encoding="utf-8"))
        expected = json.loads((vector_dir / "expected_result.json").read_text(encoding="utf-8"))
        cmd = [sys.executable, str(VERIFY_RECEIPT_PY), str(vector_dir / "input.json")]
        if meta["checkpoint"] is not None:
            cmd += ["--checkpoint", meta["checkpoint"]]
        if meta["trust_material_complete"]:
            cmd.append("--trust-material-complete")
        completed = subprocess.run(cmd, capture_output=True, text=True)
        assert completed.returncode == expected["exit_code"], _vector_id(vector_dir)
        assert not any(line.startswith("{") for line in completed.stdout.splitlines()), (
            f"{_vector_id(vector_dir)}: a JSON line leaked into default output without --emit-result"
        )
        any_checked = True
    assert any_checked, "no vectors found -- test would otherwise pass vacuously"


def test_four_cases_cover_the_expected_verdict_disposition_pairs():
    """Static check on the committed expected_result.json files: the
    four SCITT-PR-463 cases this corpus mirrors must each be present,
    independent of the subprocess runs above. (c)'s pair
    (NOT_EVALUATED, REFUSED_BY_POLICY) intentionally duplicates (b)'s --
    that's the point (same policy-refusal shape reached via an empty
    rather than merely-unresolved trust list) -- so this checks a
    multiset of required pairs are each present at least once, not a
    set of four distinct pairs."""
    required_pairs = [
        ("NOT_EVALUATED", "ACCEPTED"),             # (a)
        ("NOT_EVALUATED", "REFUSED_BY_POLICY"),    # (b)
        ("NOT_EVALUATED", "REFUSED_BY_POLICY"),    # (c) -- same shape as (b), not a bug
        ("CRYPTOGRAPHICALLY_INVALID", "ACCEPTED"), # (d), both flag values
        ("CRYPTOGRAPHICALLY_INVALID", "ACCEPTED"),
    ]
    actual_pairs = []
    for vector_dir in _vector_dirs():
        expected = json.loads((vector_dir / "expected_result.json").read_text(encoding="utf-8"))
        result = expected["result"]
        actual_pairs.append((result["verdict"], result["disposition"]))

    remaining = list(actual_pairs)
    for pair in required_pairs:
        assert pair in remaining, f"missing required (verdict, disposition) pair: {pair} in {actual_pairs}"
        remaining.remove(pair)


def test_schema_and_integrity_protection_always_present():
    for vector_dir in _vector_dirs():
        expected = json.loads((vector_dir / "expected_result.json").read_text(encoding="utf-8"))
        result = expected["result"]
        assert result["schema"] == "actaseal-verify-result.v1"
        assert result["integrity_protection"] == "none"
        assert isinstance(result["trust_material_complete"], bool)


def test_outcome_exit_code_failed_checks_always_present_and_consistent():
    """outcome/exit_code/failed_checks were added specifically because
    verdict alone is not safe to read as "should this be accepted" (see
    valid_signature_broken_chain/). Every vector's pinned result must
    carry all three, outcome must be the direct, only-two-values mapping
    from exit_code, and failed_checks must exactly match whichever
    `checks` entries (if any) have status "failed" -- except the
    malformed-input/archive-attestation-failure vectors, whose `checks`
    is always `[]` by design (nothing got far enough to run) but whose
    failed_checks still names the override identifier."""
    for vector_dir in _vector_dirs():
        expected = json.loads((vector_dir / "expected_result.json").read_text(encoding="utf-8"))
        result = expected["result"]
        assert "outcome" in result and "exit_code" in result and "failed_checks" in result, _vector_id(vector_dir)
        assert result["outcome"] in ("ACCEPTED", "REJECTED"), _vector_id(vector_dir)
        expected_outcome = "ACCEPTED" if result["exit_code"] == 0 else "REJECTED"
        assert result["outcome"] == expected_outcome, _vector_id(vector_dir)
        assert isinstance(result["failed_checks"], list), _vector_id(vector_dir)
        checks_failed = [c["check"] for c in result["checks"] if c["status"] == "failed"]
        if result["checks"]:
            assert result["failed_checks"] == checks_failed, _vector_id(vector_dir)


def test_worked_example_valid_signature_broken_chain():
    """The exact case that motivated outcome/exit_code/failed_checks: a
    verdict of CRYPTOGRAPHICALLY_VALID that is nonetheless REJECTED
    overall. Asserted directly against the live subprocess, not just
    the pinned file, so a future regression here is caught immediately."""
    vector_dir = VECTORS_DIR / "valid_signature_broken_chain"
    assert vector_dir.exists(), "valid_signature_broken_chain vector is missing"
    completed = _run(vector_dir)
    result_line = next(line for line in completed.stdout.splitlines() if line.startswith("{"))
    result = json.loads(result_line)
    assert completed.returncode == 1
    assert result["verdict"] == "CRYPTOGRAPHICALLY_VALID"
    assert result["outcome"] == "REJECTED"
    assert result["exit_code"] == 1
    assert "legacy_chain" in result["failed_checks"]
