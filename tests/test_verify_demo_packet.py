from __future__ import annotations

import json
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VERIFY_PY = ROOT / "verify.py"
GENERATOR = ROOT / "generate_demo_packet.py"

sys.path.insert(0, str(ROOT))
import generate_demo_packet as gen  # noqa: E402  (needs ROOT on sys.path first)


def _run_verify(packet_dir: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(VERIFY_PY), str(packet_dir)],
        capture_output=True,
        text=True,
    )


def test_demo_packets_regenerate_and_verify_clean(tmp_path):
    subprocess.run([sys.executable, str(GENERATOR), str(tmp_path)], check=True)

    for name in ("demo-packet-unanchored", "demo-packet-anchored"):
        result = _run_verify(tmp_path / name)
        assert result.returncode == 0, result.stdout + result.stderr
        assert "VERIFIED" in result.stdout


def test_committed_demo_zips_verify_clean(tmp_path):
    for name in ("demo-packet-unanchored", "demo-packet-anchored"):
        zip_path = ROOT / "demo" / f"{name}.zip"
        extract_dir = tmp_path / name
        with zipfile.ZipFile(zip_path) as archive:
            archive.extractall(extract_dir)
        result = _run_verify(extract_dir)
        assert result.returncode == 0, result.stdout + result.stderr


def test_tampered_receipt_amount_fails_verification(tmp_path):
    subprocess.run([sys.executable, str(GENERATOR), str(tmp_path)], check=True)
    packet_dir = tmp_path / "demo-packet-unanchored"

    receipt_path = packet_dir / "receipt.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["decision"] = "BLOCK"  # tamper: flip the decision without re-signing
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")

    result = _run_verify(packet_dir)
    assert result.returncode == 1
    assert "RECEIPT_SIGNATURE_INVALID" in result.stdout


def test_broken_chain_fails_verification(tmp_path):
    subprocess.run([sys.executable, str(GENERATOR), str(tmp_path)], check=True)
    packet_dir = tmp_path / "demo-packet-unanchored"

    slice_path = packet_dir / "ledger_slice.ndjson"
    lines = [line for line in slice_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    events = [json.loads(line) for line in lines]
    events[1]["previous_event_hash"] = "0" * 64  # tamper: break the chain link
    slice_path.write_text("\n".join(json.dumps(e) for e in events) + "\n", encoding="utf-8")

    result = _run_verify(packet_dir)
    assert result.returncode == 1
    assert "CHAIN_BROKEN" in result.stdout


def test_foreign_action_scope_evaluated_event_does_not_leak_into_verdict(tmp_path):
    """Regression for a live bug (fixed in actaseal's private repo,
    ported here 2026-07-16): a dispute packet's ledger_slice.ndjson is
    documented to be the CONTIGUOUS span between an action's first and
    last event -- by design it can include a DIFFERENT action's events
    interleaved in between (e.g. this action getting a second event
    appended, such as a BREACH acknowledgement, after some unrelated
    action's own ScopeEvaluated landed in the ledger in between). A
    prior version of verify_scope_conformance took the LAST
    ScopeEvaluated event in the whole slice without checking which
    action it belonged to, so a foreign action's scope_hash/action_hash
    could get compared against this receipt's own scope_conformance and
    fail with SCOPE_HASH_MISMATCH on an otherwise-untampered packet.

    This appends one more, hash-correct ScopeEvaluated event for a
    DIFFERENT action_id, chained onto the end of an otherwise-valid
    packet, and asserts verify.py still passes -- the foreign event must
    be ignored, not compared against this receipt."""
    subprocess.run([sys.executable, str(GENERATOR), str(tmp_path)], check=True)
    packet_dir = tmp_path / "demo-packet-unanchored"

    manifest_path = packet_dir / "manifest.json"
    slice_path = packet_dir / "ledger_slice.ndjson"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    lines = [line for line in slice_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    events = [json.loads(line) for line in lines]

    foreign_intent_scope = {"tenant_id": "other-tenant", "action_types": ["payout"], "max_amount": "1.00"}
    foreign_executed_action = {"action_id": "other-action-999", "action_type": "payout", "amount": "999999.00"}
    foreign_event = gen._append_event(
        events,
        event_type="ScopeEvaluated",
        tenant_id="other-tenant",
        workspace_id="other-workspace",
        actor_id="gateway",
        action_id="other-action-999",
        action_type="payout",
        timestamp="2026-07-15T09:10:00+00:00",
        payload={
            "verdict": "BREACH",
            "breach_dimensions": ["amount"],
            "intent_scope": foreign_intent_scope,
            "executed_action": foreign_executed_action,
            "scope_hash": gen.canonical_hash(foreign_intent_scope),
            "action_hash": gen.canonical_hash(foreign_executed_action),
        },
        previous_event_hash=events[-1]["event_hash"],
    )
    assert foreign_event["action_id"] != manifest["action_id"]

    manifest["event_count"] = len(events)
    manifest_path.write_text(gen.canonical_dumps(manifest), encoding="utf-8")
    slice_path.write_text("\n".join(gen.canonical_dumps(e) for e in events) + "\n", encoding="utf-8")

    result = _run_verify(packet_dir)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "VERIFIED" in result.stdout


def test_verify_has_no_external_imports_beyond_cryptography():
    source = VERIFY_PY.read_text(encoding="utf-8")
    assert "import actaseal" not in source
    assert "from actaseal" not in source
    assert "requests" not in source
    assert "urllib" not in source
    assert "socket" not in source
