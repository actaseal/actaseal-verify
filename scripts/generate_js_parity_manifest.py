#!/usr/bin/env python3
"""Derives conformance/js_parity/parity_manifest.json from the actual
source of verify.py and tamper_demo/verify_min.js -- not hand-written.

Method: parse verify.py with `ast`, find every top-level `verify_*`
function, and extract the FAILURE_CODE string literals its body can
append to `failures` (via a regex over that function's own source
segment, matching `"SOME_CODE` / `'SOME_CODE` at the start of a string
literal -- the same convention every failure code in this file follows).
Then check, for each such function, whether tamper_demo/verify_min.js
defines a same-named-in-spirit function (verify_events -> verifyEvents,
verify_receipt -> verifyReceipt) and if so extract ITS failure-code
literals the same way, from its own JS source text.

A function is "full" if a JS counterpart exists and emits the exact
same code set, "partial" if a JS counterpart exists but emits a proper
subset, "none" if no JS counterpart of the expected name exists at all.
The reasoning for *why* something is partial (rather than just *that*
it is) is not mechanically derivable from string literals alone --
those notes are marked "hand-asserted" in the output so a reader knows
which parts of this file are checked against real code and which are
a human's judgement call layered on top.

Usage: python scripts/generate_js_parity_manifest.py [--check]
--check exits 1 if the committed parity_manifest.json would differ
from what regenerating produces right now (the sync-drift guard).
"""
from __future__ import annotations

import ast
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
VERIFY_PY = REPO_ROOT / "verify.py"
VERIFY_MIN_JS = REPO_ROOT / "tamper_demo" / "verify_min.js"
OUTPUT = REPO_ROOT / "conformance" / "js_parity" / "parity_manifest.json"

CODE_LITERAL_RE = re.compile(r"""["'`]([A-Z][A-Z0-9_]{2,})""")

# verify.py function name -> (JS counterpart function name, hand-asserted
# note on scope difference). None as the JS name means "no counterpart
# exists in verify_min.js at all" -- this half of the mapping (which
# Python function corresponds to which JS function, if any) is a human
# judgement call about intent, not something string-matching can prove;
# marked accordingly below. The failure-CODE SETS on each side, by
# contrast, ARE mechanically extracted from the two files' own source.
PY_TO_JS_FUNCTION = {
    "verify_events": "verifyEvents",
    "verify_receipt": "verifyReceipt",
    "verify_offline_verifier_digest": None,
    "verify_ledger_root_version": None,
    "verify_continuity_checkpoint": None,
    "verify_authentication_docs": None,
    "verify_scope_conformance": None,
    "verify_approver_snapshot": None,
    "verify_approval_manifestation": None,
    "verify_ledger_head_anchor": None,
    "verify_settlement_anchor": None,
    "verify_rfc3161_token": None,
    "verify_scitt_receipt": None,
    "verify_archive_export_ledger_slice": None,
    "verify_archive_export": None,
}

HAND_ASSERTED_NOTES = {
    "verify_events": (
        "verifyEvents in verify_min.js ports this function's full code set."
    ),
    "verify_receipt": (
        "verifyReceipt in verify_min.js ports only the Ed25519 signing "
        "branch (ECDSA/ML-DSA/hybrid branches are not ported -- a non-"
        "ed25519 algorithm is reported as "
        "RECEIPT_SIGNATURE_ALGORITHM_UNSUPPORTED_IN_DEMO instead of being "
        "evaluated) and does not port the RECEIPT_ACTION_HASH_MISMATCH "
        "check (recorded_action_hash vs receipt.action_hash)."
    ),
    "verify_offline_verifier_digest": (
        "Not applicable to verify_min.js by construction: this check "
        "verifies verify.py's OWN running source hash against a pin in "
        "manifest.json. verify_min.js is a different file with no "
        "self-digest concept -- there is nothing to port."
    ),
    "verify_ledger_root_version": "Not ported. No JS counterpart exists.",
    "verify_continuity_checkpoint": (
        "Not ported (RFC 9162 Merkle inclusion/consistency proof "
        "checking). No JS counterpart exists."
    ),
    "verify_authentication_docs": "Not ported. No JS counterpart exists.",
    "verify_scope_conformance": "Not ported. No JS counterpart exists.",
    "verify_approver_snapshot": "Not ported. No JS counterpart exists.",
    "verify_approval_manifestation": "Not ported. No JS counterpart exists.",
    "verify_ledger_head_anchor": "Not ported. No JS counterpart exists.",
    "verify_settlement_anchor": "Not ported. No JS counterpart exists.",
    "verify_rfc3161_token": (
        "Not ported (RFC 3161 timestamp token checking, --archive-export "
        "mode only). No JS counterpart exists."
    ),
    "verify_scitt_receipt": (
        "Not ported (SCITT transparency receipt checking, --archive-export "
        "mode only). No JS counterpart exists."
    ),
    "verify_archive_export_ledger_slice": (
        "Not ported. verify_min.js has no --archive-export equivalent at "
        "all -- a structurally different manifest shape."
    ),
    "verify_archive_export": (
        "Not ported. verify_min.js has no --archive-export equivalent at "
        "all -- a structurally different manifest shape."
    ),
}

NON_CODE_UPPER_WORDS = {"VERIFIED", "OK", "IN_SCOPE"}


def _extract_codes(source_text: str) -> set[str]:
    codes = set()
    for match in CODE_LITERAL_RE.finditer(source_text):
        token = match.group(1)
        if token in NON_CODE_UPPER_WORDS:
            continue
        codes.add(token)
    return codes


def _py_function_codes() -> dict[str, set[str]]:
    tree = ast.parse(VERIFY_PY.read_text(encoding="utf-8"), filename=str(VERIFY_PY))
    result = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name in PY_TO_JS_FUNCTION:
            segment = ast.get_source_segment(VERIFY_PY.read_text(encoding="utf-8"), node)
            result[node.name] = _extract_codes(segment or "")
    return result


def _js_function_codes() -> dict[str, set[str]]:
    js_source = VERIFY_MIN_JS.read_text(encoding="utf-8")
    functions = {}
    # Each `async function <name>(...) { ... }` block, matched to its
    # closing brace by counting brace depth -- verify_min.js has no
    # nested function declarations, so this is exact for this file.
    for match in re.finditer(r"async function (\w+)\s*\([^)]*\)\s*\{", js_source):
        name = match.group(1)
        start = match.end()
        depth = 1
        i = start
        while depth > 0 and i < len(js_source):
            if js_source[i] == "{":
                depth += 1
            elif js_source[i] == "}":
                depth -= 1
            i += 1
        body = js_source[start:i]
        functions[name] = _extract_codes(body)
    return functions


def build_manifest() -> dict:
    py_codes = _py_function_codes()
    js_codes = _js_function_codes()
    entries = []
    for py_name in sorted(PY_TO_JS_FUNCTION):
        js_name = PY_TO_JS_FUNCTION[py_name]
        py_code_set = sorted(py_codes.get(py_name, set()))
        if js_name is None:
            status = "none"
            js_code_set = []
        else:
            js_code_set = sorted(js_codes.get(js_name, set()))
            if set(js_code_set) == set(py_code_set) and py_code_set:
                status = "full"
            elif set(js_code_set) < set(py_code_set):
                status = "partial"
            elif not js_code_set:
                status = "none"
            else:
                status = "partial"
        entries.append(
            {
                "verify_py_function": py_name,
                "verify_py_failure_codes": py_code_set,
                "js_function": js_name,
                "js_failure_codes": js_code_set,
                "status": status,
                "code_sets_derived_from": "static source inspection (ast for Python, brace-matched regex for JS)",
                "status_note": HAND_ASSERTED_NOTES.get(py_name, ""),
                "status_note_derived_from": "hand-asserted",
            }
        )
    return {
        "$schema_note": (
            "Machine-derived parity manifest between verify.py and "
            "tamper_demo/verify_min.js. Regenerate with "
            "scripts/generate_js_parity_manifest.py; do not hand-edit -- "
            "this file itself is a build artifact with a sync-drift guard "
            "(tests/test_js_parity_manifest_in_sync.py)."
        ),
        "verify_py_path": "verify.py",
        "verify_min_js_path": "tamper_demo/verify_min.js",
        "entries": entries,
        "summary": {
            "full": sum(1 for e in entries if e["status"] == "full"),
            "partial": sum(1 for e in entries if e["status"] == "partial"),
            "none": sum(1 for e in entries if e["status"] == "none"),
            "total": len(entries),
        },
    }


def main(argv: list[str]) -> int:
    manifest = build_manifest()
    rendered = json.dumps(manifest, indent=2, sort_keys=False) + "\n"
    if "--check" in argv:
        if not OUTPUT.exists() or OUTPUT.read_text(encoding="utf-8") != rendered:
            print(f"OUT OF SYNC: {OUTPUT} does not match a fresh regeneration.")
            print("Run: python scripts/generate_js_parity_manifest.py")
            return 1
        print("OK: parity_manifest.json is in sync.")
        return 0
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(rendered, encoding="utf-8")
    print(f"Wrote {OUTPUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
