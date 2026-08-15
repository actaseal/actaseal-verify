"""Drift guard for conformance/js_parity/parity_manifest.json: it is a
generated file (scripts/generate_js_parity_manifest.py), not hand-edited
-- same idea as conformance/vectors.sha256 guarding the vectors
directory. If verify.py or verify_min.js changes in a way that alters
which failure codes either one can produce, this fails until someone
reruns the generator and commits the result.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
GENERATOR = REPO_ROOT / "scripts" / "generate_js_parity_manifest.py"


def test_parity_manifest_matches_fresh_regeneration():
    result = subprocess.run(
        [sys.executable, str(GENERATOR), "--check"],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )
    assert result.returncode == 0, (
        "conformance/js_parity/parity_manifest.json is out of sync with "
        "verify.py / verify_min.js -- rerun scripts/generate_js_parity_manifest.py "
        f"and commit the result.\n{result.stdout}\n{result.stderr}"
    )
