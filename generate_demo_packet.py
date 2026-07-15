#!/usr/bin/env python3
"""Builds a valid ActaSeal dispute packet from scratch, using only the
Python standard library plus 'cryptography'. Zero dependency on any
ActaSeal gateway/ledger/policy code -- this exists purely to give
verify.py something real to check, and to prove the packet format is
fully reproducible outside the private product.

Run: python generate_demo_packet.py [output_dir]
Produces two demo packets under output_dir:
  demo-packet-unanchored/  -- a plain approved refund, no on-chain settlement anchor
  demo-packet-anchored/    -- the same, but with a settlement rail anchor bound in

Each packet directory is also zipped (demo-packet-*.zip) so it matches
what a real ActaSeal deployment hands a counterparty.
"""
from __future__ import annotations

import hashlib
import json
import sys
import zipfile
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

SCHEMA_VERSION = "dispute_packet.v1"
EVENT_ID_BASIS = "ledger_event_id.v1"
EVENT_MATERIAL_FIELDS = (
    "event_type",
    "tenant_id",
    "workspace_id",
    "actor_id",
    "action_id",
    "action_type",
    "timestamp",
    "schema_version",
    "payload",
    "payload_hash",
    "previous_event_hash",
)

VERIFIER_SOURCE = (Path(__file__).resolve().parent / "verify.py")


def canonical_dumps(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def canonical_hash(value) -> str:
    return hashlib.sha256(canonical_dumps(value).encode("utf-8")).hexdigest()


def _append_event(events: list[dict], *, event_type, tenant_id, workspace_id, actor_id,
                   action_id, action_type, timestamp, payload, previous_event_hash):
    payload_hash = canonical_hash(payload)
    material = {
        "event_type": event_type,
        "tenant_id": tenant_id,
        "workspace_id": workspace_id,
        "actor_id": actor_id,
        "action_id": action_id,
        "action_type": action_type,
        "timestamp": timestamp,
        "schema_version": "ledger_event.v1",
        "payload": payload,
        "payload_hash": payload_hash,
        "previous_event_hash": previous_event_hash,
    }
    event_id = canonical_hash(dict(material, event_id_basis=EVENT_ID_BASIS))
    event_hash = canonical_hash(dict(material, event_id=event_id))
    event = dict(material, event_id=event_id, event_hash=event_hash)
    events.append(event)
    return event


def build_packet(*, anchored: bool) -> tuple[dict, dict, list[dict], dict, dict, dict]:
    private_key = Ed25519PrivateKey.generate()
    public_key_hex = private_key.public_key().public_bytes_raw().hex()

    tenant_id = "demo-tenant"
    workspace_id = "demo-workspace"
    action_id = "refund-demo-001"
    action_type = "refund_request"

    intent_scope = {"tenant_id": tenant_id, "action_types": ["refund_request"], "max_amount": "5000.00"}
    executed_action = {"action_id": action_id, "action_type": action_type, "amount": "1200.00"}
    scope_hash = canonical_hash(intent_scope)
    action_packet_hash = canonical_hash(executed_action)

    events: list[dict] = []
    _append_event(
        events,
        event_type="ActionSubmitted",
        tenant_id=tenant_id,
        workspace_id=workspace_id,
        actor_id="support-agent-1",
        action_id=action_id,
        action_type=action_type,
        timestamp="2026-07-15T09:00:00+00:00",
        payload={"action_packet_hash": action_packet_hash},
        previous_event_hash=None,
    )
    scope_event = _append_event(
        events,
        event_type="ScopeEvaluated",
        tenant_id=tenant_id,
        workspace_id=workspace_id,
        actor_id="gateway",
        action_id=action_id,
        action_type=action_type,
        timestamp="2026-07-15T09:00:01+00:00",
        payload={
            "verdict": "IN_SCOPE",
            "breach_dimensions": [],
            "intent_scope": intent_scope,
            "executed_action": executed_action,
            "scope_hash": scope_hash,
            "action_hash": action_packet_hash,
        },
        previous_event_hash=events[-1]["event_hash"],
    )
    final_event = _append_event(
        events,
        event_type="Finalized",
        tenant_id=tenant_id,
        workspace_id=workspace_id,
        actor_id="gateway",
        action_id=action_id,
        action_type=action_type,
        timestamp="2026-07-15T09:00:02+00:00",
        payload={"action_packet_hash": action_packet_hash, "decision": "ALLOW"},
        previous_event_hash=events[-1]["event_hash"],
    )

    key_id = "demo-key-1"
    signer_pubkey_hash = hashlib.sha256(bytes.fromhex(public_key_hex)).hexdigest()
    mandate_hash = canonical_hash({"mandate": "demo-ap2-mandate", "action_id": action_id})

    receipt_unsigned = {
        "decision": "ALLOW",
        "reason_code": "APPROVAL_GRANTED",
        "action_hash": action_packet_hash,
        "evidence_set_hash": canonical_hash({"evidence": "demo"}),
        "ledger_entry_hash": final_event["event_hash"],
        "timestamp": "2026-07-15T09:00:02+00:00",
        "algorithm": "ed25519",
        "key_id": key_id,
        "signer_pubkey_hash": signer_pubkey_hash,
        "mandate_hash": mandate_hash,
        "scope_conformance": {
            "verdict": "IN_SCOPE",
            "breaches": [],
            "scope_hash": scope_hash,
            "action_hash": action_packet_hash,
        },
    }
    signature = private_key.sign(canonical_dumps(receipt_unsigned).encode("utf-8")).hex()
    receipt = dict(receipt_unsigned, signature=signature)

    if anchored:
        anchor_content = {
            "rail": "ap2-demo-rail",
            "anchor_id": "anchor-demo-0001",
            "settled_at": "2026-07-15T09:05:00+00:00",
            "mandate_hash": mandate_hash,
        }
        settlement_anchor = {
            "status": "anchored",
            "anchor": anchor_content,
            "anchor_hash": canonical_hash(anchor_content),
        }
    else:
        settlement_anchor = {"status": "SETTLEMENT_UNANCHORED"}

    manifest = {
        "schema_version": SCHEMA_VERSION,
        "action_id": action_id,
        "receipt_public_key_hex": public_key_hex,
        "event_count": len(events),
        "chain_start_previous_event_hash": None,
        "scope_conformance_headline": "in_scope",
        "settlement_anchor": settlement_anchor,
    }

    acquisition = {
        "schema_version": "dispute_acquisition.v1",
        "acquired_by": "demo-generator",
        "acquired_at": "2026-07-15T09:10:00+00:00",
        "acquisition_method": "programmatic_export",
        "tool": {"name": "actaseal-verify-demo-generator", "version": "1.0.0"},
        "clock_source": "system_clock_ntp_synced",
        "source_ledger_path": "demo://in-memory-ledger",
        "ledger_root_hash": canonical_hash(events),
        "chain_of_custody": "generator -> zip archive -> counterparty",
        "external_anchor": {"log_id": "demo-transparency-log-0001"},
        "gaps": [],
    }
    custody = {
        "schema_version": "dispute_custody.v1",
        "action_id": action_id,
        "custody_events": [
            {"sequence": index + 1, "actor": "demo-generator", "action": "exported", "at": event["timestamp"],
             "ledger_event_hash": event["event_hash"]}
            for index, event in enumerate(events)
        ],
    }
    authentication = {
        "schema_version": "dispute_authentication.v1",
        "basis": "FRE 901(b)(9) / 902(13)-(14)",
        "hash_algorithm": "sha256",
        "canonicalization": "sorted-keys, compact separators, no NaN",
        "signer_key_id": key_id,
        "signer_pubkey_hash": signer_pubkey_hash,
        "external_anchor_log_id": acquisition["external_anchor"]["log_id"],
        "mandate_hash": mandate_hash,
        "statement": "This packet's ledger slice, receipt, and scope conformance are "
                     "independently re-derivable from their own recorded content; "
                     "see verify.py.",
    }

    return manifest, receipt, events, acquisition, custody, authentication


def write_packet(directory: Path, *, anchored: bool) -> None:
    manifest, receipt, events, acquisition, custody, authentication = build_packet(anchored=anchored)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "manifest.json").write_text(canonical_dumps(manifest), encoding="utf-8")
    (directory / "receipt.json").write_text(canonical_dumps(receipt), encoding="utf-8")
    (directory / "acquisition.json").write_text(canonical_dumps(acquisition), encoding="utf-8")
    (directory / "custody.json").write_text(canonical_dumps(custody), encoding="utf-8")
    (directory / "authentication.json").write_text(canonical_dumps(authentication), encoding="utf-8")
    (directory / "ledger_slice.ndjson").write_text(
        "\n".join(canonical_dumps(event) for event in events) + "\n", encoding="utf-8"
    )
    (directory / "verify.py").write_text(VERIFIER_SOURCE.read_text(encoding="utf-8"), encoding="utf-8")

    zip_path = directory.parent / f"{directory.name}.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as archive:
        for member in ("manifest.json", "receipt.json", "acquisition.json", "custody.json",
                        "authentication.json", "ledger_slice.ndjson", "verify.py"):
            archive.write(directory / member, arcname=member)


def main(argv: list[str]) -> int:
    output_dir = Path(argv[1]) if len(argv) > 1 else Path(__file__).resolve().parent / "demo"
    write_packet(output_dir / "demo-packet-unanchored", anchored=False)
    write_packet(output_dir / "demo-packet-anchored", anchored=True)
    print(f"Wrote demo packets to {output_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
