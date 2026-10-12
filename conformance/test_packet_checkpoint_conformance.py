"""Conformance vectors for `verify.py --checkpoint` (keyless packet check).

Each case under conformance/vectors/packet_checkpoint/ is a full packet
plus an expected.json that also carries the command-line arguments the
case is run with: the checkpoint is supplied out of band, never read
from the packet, so it cannot live in the packet's own files.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
GROUP = Path(__file__).resolve().parent / "vectors" / "packet_checkpoint"
CASES = sorted(d for d in GROUP.iterdir() if d.is_dir()) if GROUP.is_dir() else []


def test_the_group_exists_and_covers_pass_and_fail():
    names = {d.name for d in CASES}
    assert {
        "key_unknown_valid", "signature_valid_with_checkpoint", "checkpoint_not_in_slice",
        "checkpoint_before_receipt_entry", "key_unknown_receipt_altered",
    } <= names


@pytest.mark.parametrize("case", CASES, ids=lambda d: d.name)
def test_case_matches_expected(case):
    expected = json.loads((case / "expected.json").read_text(encoding="utf-8"))
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "verify.py"), str(case), *expected["args"]], capture_output=True, text=True
    )
    assert result.returncode == expected["exit_code"], f"{case.name}\n{result.stdout}\n{result.stderr}"
    assert result.stdout.startswith("VERIFIED" if expected["verified"] else "VERIFICATION FAILED"), result.stdout
    for substring in expected["must_include_output_substrings"]:
        assert substring in result.stdout, f"{case.name}: expected {substring!r} in\n{result.stdout}"
    for substring in expected.get("must_not_include_output_substrings", []):
        assert substring not in result.stdout, f"{case.name}: did not expect {substring!r} in\n{result.stdout}"
