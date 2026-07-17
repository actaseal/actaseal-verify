"""Conformance test suite: feeds each vector under conformance/vectors/
through this repo's own verify.py and asserts the expected verdict.

This is the same shape of thing Sigstore's conformance suite or the W3C
Certificate Transparency test vectors are: a fixed set of known-good and
known-bad inputs plus their expected verdicts, so a third-party
re-implementing the verifier (not just running ours) can check their
own implementation against the same vectors -- see conformance/README.md.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
VECTORS_DIR = Path(__file__).resolve().parent / "vectors"
PIN_FILE = Path(__file__).resolve().parent / "vectors.sha256"
VERIFY_PY = REPO_ROOT / "verify.py"


def _single_packet_vector_dirs() -> list[Path]:
    return sorted(
        d for d in VECTORS_DIR.iterdir() if d.is_dir() and (d / "manifest.json").exists()
    )


def _run_verify(packet_dir: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(VERIFY_PY), str(packet_dir)],
        capture_output=True,
        text=True,
    )


def test_vectors_pin_file_matches_committed_vectors():
    """Drift guard (same idea as ../offline_verifier.sha256): if a vector
    file was hand-edited without regenerating through generate_vectors.py
    and re-pinning, this fails -- forcing edits through the generator."""
    assert PIN_FILE.exists(), "run conformance/generate_vectors.py to create vectors.sha256"
    expected_lines = set(PIN_FILE.read_text(encoding="utf-8").splitlines())
    actual_lines = set()
    for path in VECTORS_DIR.rglob("*"):
        if path.is_file():
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            actual_lines.add(f"{digest}  {path.relative_to(VECTORS_DIR.parent).as_posix()}")
    missing = expected_lines - actual_lines
    extra = actual_lines - expected_lines
    assert not missing and not extra, (
        f"vectors.sha256 out of sync with conformance/vectors/ -- rerun "
        f"conformance/generate_vectors.py. missing={missing} extra={extra}"
    )


@pytest.mark.parametrize("packet_dir", _single_packet_vector_dirs(), ids=lambda d: d.name)
def test_single_packet_vector_matches_expected_verdict(packet_dir):
    expected = json.loads((packet_dir / "expected.json").read_text(encoding="utf-8"))
    result = _run_verify(packet_dir)
    assert result.returncode == expected["exit_code"], (
        f"{packet_dir.name}: expected exit {expected['exit_code']}, got {result.returncode}\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    if expected["verified"]:
        assert result.stdout.startswith("VERIFIED"), result.stdout
    else:
        assert result.stdout.startswith("VERIFICATION FAILED"), result.stdout
        for substring in expected["must_include_failure_substrings"]:
            assert substring in result.stdout, (
                f"{packet_dir.name}: expected failure output to mention {substring!r}\n{result.stdout}"
            )


def test_rotated_key_still_verifies_vector():
    directory = VECTORS_DIR / "rotated_key_still_verifies"
    expected = json.loads((directory / "expected.json").read_text(encoding="utf-8"))
    for sub_name in ("issued_before_rotation", "issued_after_rotation"):
        result = _run_verify(directory / sub_name)
        assert result.returncode == expected[sub_name]["exit_code"], (
            f"{sub_name}: {result.stdout}\n{result.stderr}"
        )
        assert result.stdout.startswith("VERIFIED"), result.stdout

    old_key = json.loads((directory / "issued_before_rotation" / "manifest.json").read_text())[
        "receipt_public_key_hex"
    ]
    new_key = json.loads((directory / "issued_after_rotation" / "manifest.json").read_text())[
        "receipt_public_key_hex"
    ]
    assert old_key != new_key, "vector no longer demonstrates two distinct signing keys"
