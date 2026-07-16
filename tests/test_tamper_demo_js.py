"""In-browser tamper-and-verify demo (tamper_demo/): verify_min.js is a
minimal JS port of verify.py's chain-integrity and Ed25519-receipt-
signature checks. Tested here via `node` (no browser needed) against
the real demo packet, both untampered (must verify) and tampered
(must fail, naming the same failure codes verify.py itself would name).

Skipped, not failed, when `node` isn't on PATH -- this is JS-only
functionality; its absence shouldn't fail the Python test suite in an
environment without Node installed.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
VERIFY_MIN_JS = ROOT / "tamper_demo" / "verify_min.js"
DEMO_ZIP = ROOT / "demo" / "demo-packet-unanchored.zip"

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")


def _load_packet(tmp_path: Path) -> tuple[dict, dict, list[dict]]:
    extract_dir = tmp_path / "packet"
    with zipfile.ZipFile(DEMO_ZIP) as archive:
        archive.extractall(extract_dir)
    manifest = json.loads((extract_dir / "manifest.json").read_text())
    receipt = json.loads((extract_dir / "receipt.json").read_text())
    events = [
        json.loads(line)
        for line in (extract_dir / "ledger_slice.ndjson").read_text().splitlines()
        if line.strip()
    ]
    return manifest, receipt, events


def _run_node_verify(manifest: dict, receipt: dict, events: list[dict]) -> dict:
    script = f"""
const verify = require({json.dumps(str(VERIFY_MIN_JS))});
const manifest = {json.dumps(manifest)};
const receipt = {json.dumps(receipt)};
const events = {json.dumps(events)};
verify.verifyPacket(manifest, receipt, events).then((result) => {{
  console.log(JSON.stringify(result));
}});
"""
    result = subprocess.run(
        ["node", "-e", script],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout.strip().splitlines()[-1])


def test_untampered_demo_packet_verifies_clean_in_js(tmp_path):
    manifest, receipt, events = _load_packet(tmp_path)
    result = _run_node_verify(manifest, receipt, events)
    assert result["verified"] is True
    assert result["failures"] == []


def test_tampered_receipt_decision_fails_signature_check_in_js(tmp_path):
    manifest, receipt, events = _load_packet(tmp_path)
    receipt = dict(receipt, decision="BLOCK")
    result = _run_node_verify(manifest, receipt, events)
    assert result["verified"] is False
    assert "RECEIPT_SIGNATURE_INVALID" in result["failures"]


def test_tampered_ledger_event_payload_fails_hash_check_in_js(tmp_path):
    manifest, receipt, events = _load_packet(tmp_path)
    events = [dict(e) for e in events]
    events[0] = dict(events[0], payload=dict(events[0]["payload"], action_packet_hash="tampered"))
    result = _run_node_verify(manifest, receipt, events)
    assert result["verified"] is False
    assert any("PAYLOAD_HASH_MISMATCH" in f for f in result["failures"])


def test_broken_chain_link_fails_in_js(tmp_path):
    manifest, receipt, events = _load_packet(tmp_path)
    events = [dict(e) for e in events]
    events[1] = dict(events[1], previous_event_hash="not-the-right-hash")
    result = _run_node_verify(manifest, receipt, events)
    assert result["verified"] is False
    assert any("CHAIN_BROKEN" in f or "EVENT_HASH_MISMATCH" in f for f in result["failures"])


def test_wrong_public_key_fails_signature_check_in_js(tmp_path):
    manifest, receipt, events = _load_packet(tmp_path)
    manifest = dict(manifest, receipt_public_key_hex="00" * 32)
    result = _run_node_verify(manifest, receipt, events)
    assert result["verified"] is False
    assert "RECEIPT_SIGNATURE_INVALID" in result["failures"]
