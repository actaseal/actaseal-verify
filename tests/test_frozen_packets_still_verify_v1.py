"""R4: packets made by earlier versions still verify (or still fail, for the tampered ones) with today's verifier.

The sets in conformance/frozen/ are copies of the conformance packets as earlier commits produced them
(scripts/freeze_vectors.py). A change that makes an old valid packet fail, or an old tampered one pass, breaks this test.
Not covered by design: the packets that pin the exact bytes of the verifier that shipped with them
(verifier_digest_*); those are checked against the shipped copy, not the working tree."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
FROZEN = ROOT / "conformance" / "frozen"
DOC = json.loads((FROZEN / "expectations.json").read_text())
CASES = [(label, name, exp) for label, entry in sorted(DOC.items()) for name, exp in sorted(entry["expect"].items())]


def test_there_are_at_least_four_generations_frozen():
    assert len(DOC) >= 4 and all((FROZEN / label).is_dir() for label in DOC)


@pytest.mark.parametrize("label,name,expected", CASES, ids=[f"{l}/{n}" for l, n, _ in CASES])
def test_frozen_packet(label, name, expected):
    r = subprocess.run([sys.executable, str(ROOT / "verify.py"), str(FROZEN / label / name)], capture_output=True, text=True)
    verdict, code = expected
    if verdict == "PASS":
        assert r.returncode == 0 and "VERIFIED" in r.stdout, r.stdout + r.stderr
    else:
        assert r.returncode == 1 and code in r.stdout, r.stdout + r.stderr
