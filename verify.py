#!/usr/bin/env python3
"""Offline verifier for an ActaSeal dispute evidence packet.

Standalone by design: no actaseal imports, so a counterparty can re-check
the evidence without installing or trusting ActaSeal code. Requires only
the Python standard library plus the 'cryptography' package (Ed25519).

Checks, all of which must hold:
- every ledger event's payload_hash, event_id, and event_hash recompute
  from its own content (sha256 over canonical JSON: sorted keys, compact
  separators, no NaN);
- the slice is an unbroken hash chain (each previous_event_hash matches
  the prior event) anchored to the manifest's declared chain start;
- the manifest's action_id, event_count, and chain start match the slice;
- the receipt's Ed25519 signature verifies against the manifest's public
  key over the canonical JSON of the receipt minus its signature field;
- the receipt is bound into the slice: its ledger_entry_hash names an
  included event of the manifest's action, and that event's recorded
  action_packet_hash (when present) matches the receipt's action_hash;
- the FRE 901/902 authentication documents are present and consistent:
  acquisition.json names its tool, clock source, and custodian;
  custody.json's events are time-ordered and each bound to a ledger
  event hash that exists in the slice; authentication.json's declared
  hash algorithm, signer key_id, pubkey hash, and mandate_hash match
  the receipt, and its anchor log id matches the acquisition report.
  A missing or inconsistent document fails, naming that document.
- the manifest's scope_conformance_headline is present and consistent
  with the receipt's scope_conformance and the ScopeEvaluated ledger
  event (verdict, breach dimensions, recorded scope/action hashes);
  missing or mismatched fails naming SCOPE_*.

Trust root: receipt_public_key_hex in manifest.json. Compare it out of
band against the gateway operator's published key -- a packet re-signed
end to end with a different key is internally consistent.

Usage: python verify.py [packet_dir]   (defaults to this script's directory)
Exit codes: 0 verified, 1 verification failed or packet unreadable,
2 unable to run (missing 'cryptography').
"""
import hashlib
import json
import sys
from pathlib import Path

# Receipt signature algorithms this verifier knows how to check. Must stay
# in lock-step with actaseal.signing.ALGORITHM_*. Both branches use only
# the 'cryptography' package this script already requires (see module
# docstring) -- adding an algorithm here must never add a new dependency.
ALGORITHM_ED25519 = "ed25519"
ALGORITHM_ECDSA_P256_SHA256 = "ecdsa-p256-sha256"

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


def canonical_dumps(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def canonical_hash(value):
    return hashlib.sha256(canonical_dumps(value).encode("utf-8")).hexdigest()


def load_packet(base):
    manifest = json.loads((base / "manifest.json").read_text(encoding="utf-8"))
    receipt = json.loads((base / "receipt.json").read_text(encoding="utf-8"))
    events = []
    for line in (base / "ledger_slice.ndjson").read_text(encoding="utf-8").splitlines():
        if line.strip():
            events.append(json.loads(line))
    return manifest, receipt, events


def verify_events(manifest, events, failures):
    if manifest.get("schema_version") != SCHEMA_VERSION:
        failures.append("MANIFEST_SCHEMA_MISMATCH")
    if manifest.get("event_count") != len(events):
        failures.append("EVENT_COUNT_MISMATCH: manifest=%r slice=%d" % (manifest.get("event_count"), len(events)))
    if not events:
        failures.append("EMPTY_LEDGER_SLICE")
        return
    if events[0].get("previous_event_hash") != manifest.get("chain_start_previous_event_hash"):
        failures.append("CHAIN_START_MISMATCH")
    previous_hash = None
    for index, event in enumerate(events):
        try:
            material = {field: event[field] for field in EVENT_MATERIAL_FIELDS}
            if canonical_hash(event["payload"]) != event["payload_hash"]:
                failures.append("PAYLOAD_HASH_MISMATCH: event %d" % index)
            expected_id = canonical_hash(dict(material, event_id_basis=EVENT_ID_BASIS))
            if expected_id != event["event_id"]:
                failures.append("EVENT_ID_MISMATCH: event %d" % index)
            expected_hash = canonical_hash(dict(material, event_id=event["event_id"]))
            if expected_hash != event["event_hash"]:
                failures.append("EVENT_HASH_MISMATCH: event %d" % index)
            if index > 0 and event["previous_event_hash"] != previous_hash:
                failures.append("CHAIN_BROKEN: event %d" % index)
            previous_hash = event["event_hash"]
        except Exception as exc:
            failures.append("MALFORMED_EVENT: event %d: %s" % (index, exc))
            return
    action_id = manifest.get("action_id")
    if not any(event.get("action_id") == action_id for event in events):
        failures.append("ACTION_NOT_IN_SLICE: %r" % action_id)


def verify_receipt(manifest, receipt, events, failures, crypto):
    unsigned = dict(receipt)
    signature = unsigned.pop("signature", "")
    algorithm = receipt.get("algorithm") or ALGORITHM_ED25519
    try:
        data = canonical_dumps(unsigned).encode("utf-8")
        signature_bytes = bytes.fromhex(signature)
        public_key_hex = manifest["receipt_public_key_hex"]
        if algorithm == ALGORITHM_ED25519:
            public_key = crypto["ed25519_public_key_cls"].from_public_bytes(bytes.fromhex(public_key_hex))
            public_key.verify(signature_bytes, data)
        elif algorithm == ALGORITHM_ECDSA_P256_SHA256:
            ecdsa_public_key = crypto["load_der_public_key"](bytes.fromhex(public_key_hex))
            ecdsa_public_key.verify(signature_bytes, data, crypto["ecdsa_sha256"])
        else:
            failures.append("RECEIPT_SIGNATURE_ALGORITHM_UNKNOWN: %r" % algorithm)
            return
    except (crypto["invalid_signature_error"], crypto["unsupported_algorithm_error"], ValueError, KeyError, TypeError):
        failures.append("RECEIPT_SIGNATURE_INVALID")

    bound_event = next(
        (event for event in events if event.get("event_hash") == receipt.get("ledger_entry_hash")), None
    )
    if bound_event is None:
        failures.append("RECEIPT_LEDGER_ENTRY_NOT_IN_SLICE")
        return
    if bound_event.get("action_id") != manifest.get("action_id"):
        failures.append("RECEIPT_BOUND_TO_DIFFERENT_ACTION")
    recorded_action_hash = bound_event.get("payload", {}).get("action_packet_hash")
    if recorded_action_hash is not None and recorded_action_hash != receipt.get("action_hash"):
        failures.append("RECEIPT_ACTION_HASH_MISMATCH")


def _load_doc(base, name, missing_code, failures):
    path = base / name
    if not path.exists():
        failures.append(missing_code)
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        failures.append("%s: unreadable %s: %s" % (missing_code, name, exc))
        return None


def verify_authentication_docs(receipt, events, base, failures):
    """FRE 901(b)(9) / 902(13)-(14) posture: the acquisition report,
    chain-of-custody doc, and authentication statement must be present
    and internally consistent with the ledger slice and receipt."""
    acquisition = _load_doc(base, "acquisition.json", "ACQUISITION_REPORT_MISSING", failures)
    custody = _load_doc(base, "custody.json", "CUSTODY_DOC_MISSING", failures)
    authentication = _load_doc(
        base, "authentication.json", "AUTHENTICATION_STATEMENT_MISSING", failures
    )
    slice_hashes = set(event.get("event_hash") for event in events)

    if acquisition is not None:
        tool = acquisition.get("tool") or {}
        if not tool.get("name") or not tool.get("version"):
            failures.append("ACQUISITION_TOOL_UNDECLARED: acquisition.json lacks tool name+version")
        if not acquisition.get("clock_source"):
            failures.append("ACQUISITION_CLOCK_SOURCE_UNDECLARED: acquisition.json")
        if not acquisition.get("acquired_at"):
            failures.append("ACQUISITION_TIME_UNDECLARED: acquisition.json")

    if custody is not None:
        custody_events = custody.get("custody_events") or []
        if not custody_events:
            failures.append("CUSTODY_EMPTY: custody.json records no custody events")
        timestamps = [str(event.get("at") or "") for event in custody_events]
        if timestamps != sorted(timestamps):
            failures.append("CUSTODY_ORDER_INVALID: custody.json events are not time-ordered")
        for index, event in enumerate(custody_events):
            if event.get("ledger_event_hash") not in slice_hashes:
                failures.append(
                    "CUSTODY_EVENT_UNBOUND: custody.json event %d is not bound to a "
                    "ledger event hash in the slice" % index
                )

    if authentication is not None:
        if authentication.get("hash_algorithm") != "sha256":
            failures.append("AUTHENTICATION_HASH_ALGO_MISMATCH: authentication.json")
        for doc_field, receipt_field in (
            ("signer_key_id", "key_id"),
            ("signer_pubkey_hash", "signer_pubkey_hash"),
            ("mandate_hash", "mandate_hash"),
        ):
            if authentication.get(doc_field) != receipt.get(receipt_field):
                failures.append(
                    "AUTHENTICATION_%s_MISMATCH: authentication.json diverges from receipt"
                    % doc_field.upper()
                )
        if acquisition is not None:
            anchor = acquisition.get("external_anchor") or {}
            if authentication.get("external_anchor_log_id") != anchor.get("log_id"):
                failures.append(
                    "AUTHENTICATION_ANCHOR_LOG_MISMATCH: authentication.json vs acquisition.json"
                )


def _scope_headline(scope_conformance):
    # must stay in lock-step with actaseal.dispute.packet.scope_headline
    if scope_conformance is None:
        return "not_evaluated"
    if scope_conformance.get("verdict") == "IN_SCOPE":
        return "in_scope"
    dims = ",".join(
        str(breach.get("dimension")) for breach in (scope_conformance.get("breaches") or [])
    )
    return "BREACH:%s" % dims


def verify_scope_conformance(manifest, receipt, events, failures):
    """The headline scope verdict must be present and consistent all the
    way down: manifest headline == receipt scope_conformance == the
    ScopeEvaluated ledger event (verdict, breach dimensions, and the
    recorded scope/action hashes recomputed from the recorded inputs)."""
    if "scope_conformance_headline" not in manifest:
        failures.append("SCOPE_HEADLINE_MISSING: manifest.json")
    else:
        expected = _scope_headline(receipt.get("scope_conformance"))
        if manifest["scope_conformance_headline"] != expected:
            failures.append(
                "SCOPE_HEADLINE_MISMATCH: manifest.json says %r, receipt derives %r"
                % (manifest["scope_conformance_headline"], expected)
            )

    scope_events = [event for event in events if event.get("event_type") == "ScopeEvaluated"]
    result = receipt.get("scope_conformance")
    if result is not None and not scope_events:
        failures.append(
            "SCOPE_EVENT_MISSING: receipt.json claims a scope conformance the "
            "ledger_slice.ndjson never witnessed (no ScopeEvaluated event)"
        )
    if result is None and scope_events:
        failures.append(
            "SCOPE_RESULT_MISSING: receipt.json carries no scope_conformance but "
            "ledger_slice.ndjson records a ScopeEvaluated event"
        )
    if result is not None and scope_events:
        payload = scope_events[-1].get("payload", {})
        if payload.get("verdict") != result.get("verdict"):
            failures.append("SCOPE_VERDICT_MISMATCH: receipt.json vs ledger_slice.ndjson")
        event_dims = [str(dim) for dim in (payload.get("breach_dimensions") or [])]
        receipt_dims = [
            str(breach.get("dimension")) for breach in (result.get("breaches") or [])
        ]
        if event_dims != receipt_dims:
            failures.append(
                "SCOPE_DIMENSIONS_MISMATCH: receipt.json breaches %r vs ledger %r"
                % (receipt_dims, event_dims)
            )
        for hash_field, source_field in (("scope_hash", "intent_scope"), ("action_hash", "executed_action")):
            source = payload.get(source_field)
            if source is None or payload.get(hash_field) != canonical_hash(source):
                failures.append(
                    "SCOPE_HASH_MISMATCH: ScopeEvaluated %s does not recompute from its recorded %s"
                    % (hash_field, source_field)
                )
            elif result.get(hash_field) != payload.get(hash_field):
                failures.append(
                    "SCOPE_HASH_MISMATCH: receipt.json %s diverges from ledger" % hash_field
                )


def verify_settlement_anchor(manifest, failures):
    """The settlement anchor block must be present -- absence of a
    settlement is itself stated as SETTLEMENT_UNANCHORED, never silent --
    and an anchored block's anchor_hash must recompute from its content."""
    block = manifest.get("settlement_anchor")
    if block is None:
        failures.append(
            "SETTLEMENT_FIELD_MISSING: manifest.json carries no settlement_anchor "
            "block (even an unanchored packet must state SETTLEMENT_UNANCHORED)"
        )
        return
    status = block.get("status")
    if status == "SETTLEMENT_UNANCHORED":
        if set(block) != {"status"}:
            failures.append(
                "SETTLEMENT_ANCHOR_INVALID: unanchored block carries extra fields %r"
                % sorted(set(block) - {"status"})
            )
        return
    if status != "anchored":
        failures.append("SETTLEMENT_ANCHOR_INVALID: unknown status %r" % status)
        return
    anchor = block.get("anchor")
    if not isinstance(anchor, dict):
        failures.append("SETTLEMENT_ANCHOR_INVALID: anchored block has no anchor content")
        return
    if block.get("anchor_hash") != canonical_hash(anchor):
        failures.append(
            "SETTLEMENT_ANCHOR_HASH_MISMATCH: anchor_hash does not recompute from "
            "the anchor content in manifest.json"
        )


def main(argv):
    try:
        from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.hazmat.primitives.serialization import load_der_public_key
    except ImportError:
        print("UNABLE_TO_RUN: the 'cryptography' package is required (pip install cryptography)")
        return 2
    crypto = {
        "ed25519_public_key_cls": Ed25519PublicKey,
        "invalid_signature_error": InvalidSignature,
        "unsupported_algorithm_error": UnsupportedAlgorithm,
        "load_der_public_key": load_der_public_key,
        "ecdsa_sha256": ec.ECDSA(hashes.SHA256()),
    }

    base = Path(argv[1]) if len(argv) > 1 else Path(__file__).resolve().parent
    failures = []
    try:
        manifest, receipt, events = load_packet(base)
    except Exception as exc:
        print("VERIFICATION FAILED")
        print("  UNREADABLE_PACKET: %s" % exc)
        return 1

    verify_events(manifest, events, failures)
    verify_receipt(manifest, receipt, events, failures, crypto)
    verify_authentication_docs(receipt, events, base, failures)
    verify_scope_conformance(manifest, receipt, events, failures)
    verify_settlement_anchor(manifest, failures)

    if failures:
        print("VERIFICATION FAILED")
        for failure in failures:
            print("  " + failure)
        return 1
    print("VERIFIED: %d ledger events, receipt signature valid, chain intact" % len(events))
    print("  action_id: %s" % manifest.get("action_id"))
    print("  decision: %s (%s)" % (receipt.get("decision"), receipt.get("reason_code")))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
