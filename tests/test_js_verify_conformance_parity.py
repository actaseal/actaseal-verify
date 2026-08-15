"""Runs tamper_demo/verify_min.js over every single-packet conformance
vector in conformance/vectors/ and compares its verdict to verify.py's
verdict on the same vector.

verify_min.js only ports a subset of verify.py's checks (see
conformance/js_parity/parity_manifest.json): chain integrity
(verify_events, full parity) and the Ed25519 branch of the receipt
signature check (verify_receipt, partial parity). So this harness does
NOT expect the two verdicts to always match outright -- a vector whose
only expected failures are outside what verify_min.js can ever detect
(e.g. VERIFIER_DIGEST_MISMATCH, which is a check on verify.py's own
running source and has no JS equivalent by construction) is classified
UNSUPPORTED, not a disagreement. Every vector whose expected failures
ARE within verify_min.js's covered check set is classified BOTH_AGREE
or DISAGREE by an honest comparison -- never tuned to force agreement.

A DISAGREE finding here is either a real bug in one of the two
implementations, or evidence of an ambiguity in SPEC.md; either way it
must be reported, never silently reconciled.

Skipped (not failed) when `node` isn't on PATH, same policy as
test_tamper_demo_js.py.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from conformance.js_parity.covered_checks import failure_is_in_scope, in_scope_failure_code_prefixes

REPO_ROOT = Path(__file__).resolve().parent.parent
VERIFY_PY = REPO_ROOT / "verify.py"
VERIFY_MIN_JS = REPO_ROOT / "tamper_demo" / "verify_min.js"
VECTORS_DIR = REPO_ROOT / "conformance" / "vectors"

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")


def _single_packet_vector_dirs() -> list[Path]:
    """Vector directories shaped like a single dispute packet (manifest.json
    directly inside) -- excludes archive_attestation_v1 (a different
    artifact type/manifest shape entirely, --archive-export mode, which
    verify_min.js has no equivalent for at all) and expands
    rotated_key_still_verifies/ into its two sub-packets."""
    dirs = []
    for d in sorted(VECTORS_DIR.iterdir()):
        if not d.is_dir():
            continue
        if (d / "manifest.json").exists():
            dirs.append(d)
        else:
            for sub in sorted(d.iterdir()):
                if sub.is_dir() and (sub / "manifest.json").exists():
                    dirs.append(sub)
    return dirs


def _run_verify_py(packet_dir: Path) -> list[str]:
    result = subprocess.run(
        [sys.executable, str(VERIFY_PY), str(packet_dir)],
        capture_output=True,
        text=True,
    )
    lines = [l.strip() for l in result.stdout.splitlines() if l.strip()]
    # First line is "VERIFIED: ..." or "VERIFICATION FAILED"; failure
    # codes are the indented lines under "VERIFICATION FAILED".
    if lines and lines[0].startswith("VERIFIED"):
        return []
    return lines[1:]


def _run_verify_min_js(packet_dir: Path) -> dict:
    manifest = json.loads((packet_dir / "manifest.json").read_text())
    receipt = json.loads((packet_dir / "receipt.json").read_text())
    events = [
        json.loads(line)
        for line in (packet_dir / "ledger_slice.ndjson").read_text().splitlines()
        if line.strip()
    ]
    script = f"""
const verify = require({json.dumps(str(VERIFY_MIN_JS))});
const manifest = {json.dumps(manifest)};
const receipt = {json.dumps(receipt)};
const events = {json.dumps(events)};
verify.verifyPacket(manifest, receipt, events).then((result) => {{
  console.log(JSON.stringify(result));
}});
"""
    result = subprocess.run(["node", "-e", script], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout.strip().splitlines()[-1])


def _classify(py_failures: list[str], js_result: dict, in_scope_codes: set[str]) -> str:
    in_scope_py_failures = [f for f in py_failures if failure_is_in_scope(f, in_scope_codes)]
    js_verified = js_result["verified"]

    if not in_scope_py_failures:
        # Nothing verify.py failed on is even in verify_min.js's covered
        # check set. verify_min.js reporting VERIFIED here is expected
        # and correct -- it structurally cannot see the other failures
        # (or there are none). This is coverage-limitation, not agreement
        # on a shared verdict, so it's its own category.
        return "UNSUPPORTED" if py_failures else "BOTH_AGREE"

    # At least one of verify.py's failures IS something verify_min.js's
    # ported checks should be able to catch. verify_min.js must also
    # report unverified for real agreement.
    if not js_verified:
        return "BOTH_AGREE"
    return "DISAGREE"


@pytest.mark.parametrize("packet_dir", _single_packet_vector_dirs(), ids=lambda d: str(d.relative_to(VECTORS_DIR)))
def test_conformance_vector_parity(packet_dir):
    in_scope_codes = in_scope_failure_code_prefixes()
    py_failures = _run_verify_py(packet_dir)
    js_result = _run_verify_min_js(packet_dir)
    verdict = _classify(py_failures, js_result, in_scope_codes)

    assert verdict in ("BOTH_AGREE", "UNSUPPORTED"), (
        f"{packet_dir.relative_to(VECTORS_DIR)}: DISAGREE between verify.py and verify_min.js.\n"
        f"verify.py failures: {py_failures}\n"
        f"verify_min.js result: {js_result}\n"
        f"in-scope codes: {sorted(in_scope_codes)}"
    )


def test_verifier_digest_tampered_vector_is_unsupported_not_a_false_pass():
    """The one vector in this set whose failure is entirely outside
    verify_min.js's coverage: VERIFIER_DIGEST_MISMATCH is a check on
    verify.py's own running source, which has no JS analogue. Pin the
    classification explicitly so a future change to verify_min.js's
    scope can't silently turn this into an unnoticed false pass."""
    packet_dir = VECTORS_DIR / "verifier_digest_tampered"
    in_scope_codes = in_scope_failure_code_prefixes()
    py_failures = _run_verify_py(packet_dir)
    js_result = _run_verify_min_js(packet_dir)
    assert any("VERIFIER_DIGEST_MISMATCH" in f for f in py_failures)
    assert _classify(py_failures, js_result, in_scope_codes) == "UNSUPPORTED"
    assert js_result["verified"] is True, (
        "verify_min.js has no concept of its own digest pin -- it is expected "
        "to report VERIFIED here, which is exactly why this vector is "
        "classified UNSUPPORTED rather than compared as a real verdict."
    )


class _FakeVerdict:
    """Unit-level proof the classifier itself can distinguish DISAGREE
    from UNSUPPORTED from BOTH_AGREE, independent of node/subprocess --
    the break/restore transcript for this harness's own logic."""


def test_classifier_flags_a_real_disagreement():
    in_scope_codes = in_scope_failure_code_prefixes()
    py_failures = ["CHAIN_BROKEN: event 1"]
    js_result_wrong = {"verified": True, "failures": []}  # verify_min.js wrongly says OK
    assert _classify(py_failures, js_result_wrong, in_scope_codes) == "DISAGREE"


def test_classifier_agrees_when_both_fail_on_in_scope_code():
    in_scope_codes = in_scope_failure_code_prefixes()
    py_failures = ["CHAIN_BROKEN: event 1"]
    js_result_right = {"verified": False, "failures": ["CHAIN_BROKEN: event 1"]}
    assert _classify(py_failures, js_result_right, in_scope_codes) == "BOTH_AGREE"


def test_classifier_marks_out_of_scope_failure_as_unsupported_not_agree():
    in_scope_codes = in_scope_failure_code_prefixes()
    py_failures = ["VERIFIER_DIGEST_MISMATCH: declared=x actual=y"]
    js_result = {"verified": True, "failures": []}
    assert _classify(py_failures, js_result, in_scope_codes) == "UNSUPPORTED"
