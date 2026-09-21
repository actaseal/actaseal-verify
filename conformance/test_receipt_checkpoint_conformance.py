"""Conformance test suite for verify_receipt.py's T5 keyless/checkpoint
mode: feeds conformance/vectors/receipt_checkpoint/* through
verify_receipt.py as a subprocess (same shape as test_conformance.py's
packet-vector runner) and asserts the expected mode + exit code.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
VECTORS_DIR = Path(__file__).resolve().parent / "vectors" / "receipt_checkpoint"
VERIFY_RECEIPT_PY = REPO_ROOT / "verify_receipt.py"


def _vector_dirs() -> list[Path]:
    if not VECTORS_DIR.exists():
        return []
    return sorted(d for d in VECTORS_DIR.iterdir() if d.is_dir() and (d / "input.json").exists())


def _run_verify_receipt(input_path: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(VERIFY_RECEIPT_PY), str(input_path), "--checkpoint",
         json.loads(input_path.read_text(encoding="utf-8"))["receipt"]["ledger_entry_hash"]],
        capture_output=True,
        text=True,
    )


@pytest.mark.parametrize("vector_dir", _vector_dirs(), ids=lambda d: d.name)
def test_receipt_checkpoint_vector_matches_expected_verdict(vector_dir):
    expected = json.loads((vector_dir / "expected.json").read_text(encoding="utf-8"))
    result = _run_verify_receipt(vector_dir / "input.json")

    assert result.returncode == expected["exit_code"], (
        f"{vector_dir.name}: expected exit {expected['exit_code']}, got {result.returncode}\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    if expected["mode"] == "FAIL":
        assert result.stdout.startswith("FAIL"), result.stdout
    else:
        assert result.stdout.startswith("PASS"), result.stdout
        assert f"mode: {expected['mode']}" in result.stdout, result.stdout
    for substring in expected["must_include_substrings"]:
        assert substring in result.stdout, f"{vector_dir.name}: expected {substring!r} in {result.stdout}"


def test_all_three_vectors_produce_pairwise_distinct_modes():
    """Hard requirement, vector-level: the three receipt_checkpoint
    vectors' modes (SIGNATURE_VERIFIED, CHAIN_VERIFIED_KEY_UNKNOWN, FAIL)
    must be pairwise distinct -- this is a static check on the committed
    expected.json files, independent of the subprocess runs above."""
    modes = {json.loads((d / "expected.json").read_text())["mode"] for d in _vector_dirs()}
    assert modes == {"SIGNATURE_VERIFIED", "CHAIN_VERIFIED_KEY_UNKNOWN", "FAIL"}
