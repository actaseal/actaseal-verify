"""Which of verify.py's failure codes verify_min.js can, in principle,
ever produce -- derived from conformance/js_parity/parity_manifest.json
(itself derived from source, see scripts/generate_js_parity_manifest.py),
not hand-written from scratch.

Used by tests/test_js_verify_conformance_parity.py to decide whether a
conformance vector's expected verify.py failure is something verify_min.js
was ever going to be able to detect (IN scope -> a real verdict comparison
is meaningful) or not (OUT of scope -> verify_min.js reporting VERIFIED on
this vector is UNSUPPORTED coverage, not a disagreement with verify.py).
"""
from __future__ import annotations

import json
from pathlib import Path

MANIFEST_PATH = Path(__file__).resolve().parent / "parity_manifest.json"


def in_scope_failure_code_prefixes() -> set[str]:
    """Every failure-code string verify_min.js's ported functions can
    emit, taken directly from the manifest's js_failure_codes lists."""
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    codes: set[str] = set()
    for entry in manifest["entries"]:
        codes.update(entry["js_failure_codes"])
    return codes


def failure_is_in_scope(failure_line: str, in_scope_codes: set[str]) -> bool:
    """A verify.py failure line looks like 'CODE' or 'CODE: extra detail'.
    In scope iff its CODE prefix is one verify_min.js's ported functions
    can produce."""
    code = failure_line.split(":", 1)[0].strip()
    return code in in_scope_codes
