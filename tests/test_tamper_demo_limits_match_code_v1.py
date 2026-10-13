"""The demo page's two lists -- what it checks, what it does not -- must
match the code, in both directions.

test_tamper_demo_html_states_its_limits.py already ties the "does NOT
check" list to the parity manifest. That only helps if the manifest
itself lists every check verify.py has, and nothing tied the "checks"
list to what verify_min.js really does. These tests close both.
"""
from __future__ import annotations

import ast
import json
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
INDEX_HTML = REPO_ROOT / "tamper_demo" / "index.html"
VERIFY_PY = REPO_ROOT / "verify.py"
PARITY_MANIFEST = REPO_ROOT / "conformance" / "js_parity" / "parity_manifest.json"

# Every failure the in-browser check can report -> words the page's
# "What this page checks" sentence must use for it.
CHECKED_KEYWORDS = {
    "MANIFEST_SCHEMA_MISMATCH": "schema version",
    "EVENT_COUNT_MISMATCH": "event count",
    "EMPTY_LEDGER_SLICE": "not empty",
    "CHAIN_START_MISMATCH": "first event",
    "PAYLOAD_HASH_MISMATCH": "payload hash",
    "EVENT_ID_MISMATCH": "event id",
    "EVENT_HASH_MISMATCH": "event hash",
    "CHAIN_BROKEN": "previous event",
    "MALFORMED_EVENT": "well-formed",
    "ACTION_NOT_IN_SLICE": "action appears",
    "RECEIPT_SIGNATURE_INVALID": "ed25519 signature",
    "RECEIPT_LEDGER_ENTRY_NOT_IN_SLICE": "ledger entry",
    "RECEIPT_BOUND_TO_DIFFERENT_ACTION": "same action",
}
# Reported when the page meets something it does not check at all; the
# "does NOT check" list covers it.
NOT_A_CHECK = {"RECEIPT_SIGNATURE_ALGORITHM_UNSUPPORTED_IN_DEMO"}

# Checks verify.py makes that the page does not, beyond the ones
# test_tamper_demo_html_states_its_limits.py already requires.
UNCHECKED_KEYWORDS = {
    "the receipt's action hash": "action hash",
    "whether the signing key is the operator's": "really the operator's",
    "--receipt-public-key pinning": "--receipt-public-key",
    "key rotation (--receipt-keyring)": "--receipt-keyring",
    "the --checkpoint mode": "--checkpoint",
}


def _page() -> str:
    return re.sub(r"\s+", " ", INDEX_HTML.read_text(encoding="utf-8").lower())


def _limits_box() -> tuple[str, str]:
    page = _page()
    start = page.index('id="limits-box"')
    box = page[start:page.index("</div>", start)]
    checks, _, does_not = box.partition("what it does not check")
    assert does_not, "the limits box must have a 'What it does NOT check' part"
    return checks, does_not


def test_manifest_lists_every_check_function_in_the_verifier():
    tree = ast.parse(VERIFY_PY.read_text(encoding="utf-8"))
    in_verifier = {
        node.name for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name.startswith("verify_")
    }
    manifest = json.loads(PARITY_MANIFEST.read_text(encoding="utf-8"))
    in_manifest = {entry["verify_py_function"] for entry in manifest["entries"]}
    assert in_verifier - in_manifest == set()
    assert in_manifest - in_verifier == set()


def test_checks_sentence_names_everything_the_page_code_can_report():
    manifest = json.loads(PARITY_MANIFEST.read_text(encoding="utf-8"))
    reported = {code for entry in manifest["entries"] for code in entry["js_failure_codes"]}
    assert reported, "expected the page's code to report at least one failure code"
    unmapped = reported - set(CHECKED_KEYWORDS) - NOT_A_CHECK
    assert unmapped == set(), "add the words the page uses for these to CHECKED_KEYWORDS"
    checks, _does_not = _limits_box()
    missing = {code: CHECKED_KEYWORDS[code] for code in reported - NOT_A_CHECK if CHECKED_KEYWORDS[code] not in checks}
    assert missing == {}


def test_checks_sentence_claims_nothing_the_page_code_does_not_report():
    manifest = json.loads(PARITY_MANIFEST.read_text(encoding="utf-8"))
    reported = {code for entry in manifest["entries"] for code in entry["js_failure_codes"]}
    stale = set(CHECKED_KEYWORDS) - reported
    assert stale == set(), "CHECKED_KEYWORDS names a failure the page's code no longer reports"


def test_does_not_check_list_names_the_remaining_gaps():
    _checks, does_not = _limits_box()
    missing = {what: words for what, words in UNCHECKED_KEYWORDS.items() if words not in does_not}
    assert missing == {}


def test_page_does_not_count_its_checks():
    assert "two of the checks" not in _page()
