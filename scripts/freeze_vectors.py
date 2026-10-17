#!/usr/bin/env python3
"""Keep a copy of the conformance packets as an earlier commit produced them.

    python scripts/freeze_vectors.py <commit> <label>

Copies the single-packet vectors (valid, tampered_chain, tampered_payload, wrong_signature) from that commit into
conformance/frozen/<label>/ and records what the verifier must say about each in conformance/frozen/expectations.json.
tests/test_frozen_packets_still_verify_v1.py then checks every frozen packet against the verifier in the working tree,
so a change that stops an old packet from verifying fails the build.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FROZEN = ROOT / "conformance" / "frozen"
EXPECT = {
    "valid": ["PASS", None],
    "tampered_chain": ["FAIL", "EVENT_ID_MISMATCH"],
    "tampered_payload": ["FAIL", "PAYLOAD_HASH_MISMATCH"],
    "wrong_signature": ["FAIL", "RECEIPT_SIGNATURE_INVALID"],
}


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__)
        return 2
    commit, label = argv
    target = FROZEN / label
    if target.exists():
        print(f"{label} is already frozen; frozen sets are never rewritten", file=sys.stderr)
        return 1
    with tempfile.TemporaryDirectory() as tmp:
        archive = subprocess.run(["git", "archive", commit, "conformance/vectors"], cwd=ROOT, capture_output=True, check=True).stdout
        subprocess.run(["tar", "-x", "-C", tmp], input=archive, check=True)
        src = Path(tmp) / "conformance" / "vectors"
        target.mkdir(parents=True)
        for name in EXPECT:
            shutil.copytree(src / name, target / name)
    path = FROZEN / "expectations.json"
    doc = json.loads(path.read_text()) if path.exists() else {}
    doc[label] = {"commit": commit, "expect": EXPECT}
    path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
    print(f"froze {commit} as {label}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
