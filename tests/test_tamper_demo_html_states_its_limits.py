"""tamper_demo/index.html must state its own limits on its face -- what
it checks, what it doesn't, and where to go for an authoritative check.
The exact wording is hand-written (English prose isn't mechanically
derivable), but this test cross-checks its claims against
conformance/js_parity/parity_manifest.json so the two can't silently
drift apart: every verify.py check the manifest marks anything other
than "full" must be nameable somewhere in the page's limits text, and
the page must never claim full parity with verify.py outright.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
INDEX_HTML = REPO_ROOT / "tamper_demo" / "index.html"
PARITY_MANIFEST = REPO_ROOT / "conformance" / "js_parity" / "parity_manifest.json"

# verify.py function -> a substring that must appear somewhere in the
# page's (lowercased) limits text if that function is not fully ported.
# Hand-asserted mapping (English prose isn't mechanically derivable from
# a Python identifier) -- cross-checked against the live manifest below
# so a newly-added non-full check can't silently go unmentioned.
CONCEPT_KEYWORDS = {
    "verify_offline_verifier_digest": "digest",
    "verify_ledger_root_version": "root version",
    "verify_continuity_checkpoint": "continuity checkpoint",
    "verify_authentication_docs": "authentication-document",
    "verify_scope_conformance": "scope conformance",
    "verify_approver_snapshot": "approver-snapshot",
    "verify_approval_manifestation": "approval-manifestation",
    "verify_ledger_head_anchor": "transparency anchoring",
    "verify_settlement_anchor": "settlement-anchor",
    "verify_rfc3161_token": "rfc 3161",
    "verify_scitt_receipt": "scitt",
    "verify_archive_export_ledger_slice": "archive-export",
    "verify_archive_export": "archive-export",
}


def test_page_links_to_the_parity_manifest():
    html = INDEX_HTML.read_text(encoding="utf-8")
    assert "js_parity/parity_manifest.json" in html


def test_page_does_not_claim_full_parity_with_verify_py():
    html = INDEX_HTML.read_text(encoding="utf-8")
    assert "the same checks" not in html.lower(), (
        "index.html must not claim to run 'the same checks' as verify.py -- "
        "it only ports a subset (see parity_manifest.json)."
    )


def test_page_names_every_unported_check_category():
    manifest = json.loads(PARITY_MANIFEST.read_text(encoding="utf-8"))
    # Collapse HTML source line-wrapping whitespace so a keyword split
    # across two lines by hand-wrapped prose still matches.
    html = re.sub(r"\s+", " ", INDEX_HTML.read_text(encoding="utf-8").lower())
    not_full = [e for e in manifest["entries"] if e["status"] != "full"]
    assert not_full, "expected at least one non-full entry to sanity-check this test itself"

    for entry in not_full:
        name = entry["verify_py_function"]
        if name == "verify_receipt":
            assert ("ecdsa" in html and "pq" in html) or "hybrid" in html, (
                "verify_receipt is only partially ported (Ed25519 only) -- the page must say so."
            )
            continue
        assert name in CONCEPT_KEYWORDS, (
            f"{name} (status={entry['status']}) is not in CONCEPT_KEYWORDS -- add a mapping "
            f"so this test can check the page mentions it."
        )
        keyword = CONCEPT_KEYWORDS[name]
        assert keyword in html, f"{name} (status={entry['status']}) has no mention in index.html's limits text"
