#!/usr/bin/env python3
"""Offline verifier for an ActaSeal dispute evidence packet.

Standalone by design: no actaseal imports, so a counterparty can re-check
the evidence without installing or trusting ActaSeal code. Requires only
the Python standard library plus the 'cryptography' package (Ed25519).

Dual-version ledger_root support: this verifier declares which
ledger_root_hash algorithm versions it can check via
VERIFIER_SUPPORTS_ROOT_VERSIONS below. actaseal/dispute/verifier_gate.py
in the private actaseal repo reads this exact marker to decide whether a
v2 root may be emitted into a third-party-verified artifact at all --
keep both sides of this in sync (see VERIFIER_SYNC.md).

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

Usage: python verify.py [packet_dir] [--anchors PATH]
  packet_dir defaults to this script's directory. --anchors is optional:
  when given, also confirms this packet's ledger_root_hash was witnessed
  by a successful entry in the named anchor log (a jsonl file of
  transparency-anchor records, see actaseal.ledger_anchor /
  scripts/publish_anchor.py in the private ActaSeal repo).
Exit codes: 0 verified, 1 verification failed or packet unreadable,
2 unable to run (missing 'cryptography').
"""
import hashlib
import json
import sys
from pathlib import Path

# Receipt signature algorithms this verifier knows how to check. Must stay
# in lock-step with actaseal.signing.ALGORITHM_*. The Ed25519/ECDSA
# branches use only the 'cryptography' package this script already
# requires (see module docstring). The ML-DSA / hybrid branches below
# need the optional 'oqs' package (liboqs-python) -- lazily imported only
# when a receipt actually names one of those algorithms, so a packet
# signed classically still verifies on a machine without liboqs
# installed, and this script's baseline dependency claim stays true.
ALGORITHM_ED25519 = "ed25519"
ALGORITHM_ECDSA_P256_SHA256 = "ecdsa-p256-sha256"
ALGORITHM_ML_DSA_65 = "ml-dsa-65"
ALGORITHM_ML_DSA_87 = "ml-dsa-87"
# Hybrid classical+PQ (ONESHOT-MONEY T2, ActaSeal private repo): signature
# and public_key_hex are each this verifier's own raw-bytes hex, one layer
# outside a "<ed25519_hex>.<ml_dsa_65_hex>" ASCII-encoded pair -- PASS
# requires BOTH halves to verify independently. Stripping the PQ half to
# present a bare Ed25519 signature under this algorithm tag must fail the
# format check before either half's crypto is even touched (downgrade
# resistance is the whole point of a hybrid mode).
ALGORITHM_HYBRID_ED25519_ML_DSA_65 = "hybrid-ed25519-ml-dsa-65"
HYBRID_PART_SEPARATOR = "."

# Continuity-checkpoint failure codes (T8, ONESHOT-4 batch 3). Must stay
# in lock-step with actaseal.anchoring's constants of the same names.
ANCHOR_INCLUSION_PROOF_INVALID = "ANCHOR_INCLUSION_PROOF_INVALID"
ANCHOR_CONSISTENCY_PROOF_INVALID = "ANCHOR_CONSISTENCY_PROOF_INVALID"
ANCHOR_CHECKPOINT_MISMATCH = "ANCHOR_CHECKPOINT_MISMATCH"
STH_SIGNATURE_INVALID = "STH_SIGNATURE_INVALID"

# ATTESTATION-LIVE Task 4: RFC 3161 token + SCITT (RFC 9943) receipt
# verification, additive to this file's existing dispute-packet checks
# above -- neither of these two functions is wired into main()'s
# dispute-packet flow (a different artifact type: an AS 1215 archive
# inspection pack, not a money-action dispute packet), so no existing
# conformance vector's behavior changes. Both are plain, importable
# functions a caller (or a future archive-inspection-pack CLI mode)
# invokes directly.
TSA_TOKEN_HASH_MISMATCH = "TSA_TOKEN_HASH_MISMATCH"
TSA_TOKEN_INVALID = "TSA_TOKEN_INVALID"
TSA_TOKEN_NO_TRUSTED_ROOT = "TSA_TOKEN_NO_TRUSTED_ROOT"

# RCA1 (ledger-root v1->v2 migration): versions this verifier can check.
# A packet declaring a version NOT in this tuple fails loudly
# (LEDGER_ROOT_VERSION_UNKNOWN) -- never silently treated as v1 or
# silently passed through. v1 keeps its exact byte-level meaning
# forever; a packet with NO ledger_root_version field at all predates
# this field and means v1 (old packets must keep verifying exactly as
# they always did).
VERIFIER_SUPPORTS_ROOT_VERSIONS = ("v1", "v2")
LEDGER_ROOT_VERSION_V1 = "v1"
LEDGER_ROOT_VERSION_UNKNOWN = "LEDGER_ROOT_VERSION_UNKNOWN"

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
    if not isinstance(manifest, dict):
        raise ValueError("manifest.json must be a JSON object, got %s" % type(manifest).__name__)
    if not isinstance(receipt, dict):
        raise ValueError("receipt.json must be a JSON object, got %s" % type(receipt).__name__)
    events = []
    for line in (base / "ledger_slice.ndjson").read_text(encoding="utf-8").splitlines():
        if line.strip():
            event = json.loads(line)
            if not isinstance(event, dict):
                raise ValueError("each ledger_slice.ndjson line must be a JSON object, got %s" % type(event).__name__)
            events.append(event)
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
    # tsa_anchor is stapled onto a receipt AFTER signing -- the signature
    # covers the receipt's signing bytes, which exclude it -- so it must
    # be excluded here too, the same way "signature" itself is.
    unsigned.pop("tsa_anchor", None)
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
        elif algorithm in (ALGORITHM_ML_DSA_65, ALGORITHM_ML_DSA_87):
            try:
                import oqs
            except ImportError:
                failures.append(
                    "ALGORITHM_UNSUPPORTED: %s requires the optional 'oqs' package "
                    "(pip install liboqs-python), which is not installed in this environment" % algorithm
                )
                return
            oqs_name = "ML-DSA-65" if algorithm == ALGORITHM_ML_DSA_65 else "ML-DSA-87"
            try:
                with oqs.Signature(oqs_name) as verifier:
                    if not verifier.verify(data, signature_bytes, bytes.fromhex(public_key_hex)):
                        failures.append("RECEIPT_SIGNATURE_INVALID")
            except Exception:
                failures.append("RECEIPT_SIGNATURE_INVALID")
        elif algorithm == ALGORITHM_HYBRID_ED25519_ML_DSA_65:
            try:
                dotted_signature = signature_bytes.decode("ascii")
                dotted_public_key = bytes.fromhex(public_key_hex).decode("ascii")
                ed_sig_hex, pq_sig_hex = dotted_signature.split(HYBRID_PART_SEPARATOR)
                ed_pub_hex, pq_pub_hex = dotted_public_key.split(HYBRID_PART_SEPARATOR)
                if not ed_sig_hex.strip() or not pq_sig_hex.strip() or not ed_pub_hex.strip() or not pq_pub_hex.strip():
                    raise ValueError("empty hybrid part")
            except (ValueError, UnicodeDecodeError):
                failures.append(
                    "INVALID_HYBRID_FORMAT: expected '<ed25519_hex>.<ml_dsa_65_hex>' for both "
                    "signature and public_key"
                )
                return
            try:
                ed_public_key = crypto["ed25519_public_key_cls"].from_public_bytes(bytes.fromhex(ed_pub_hex))
                ed_public_key.verify(bytes.fromhex(ed_sig_hex), data)
            except (crypto["invalid_signature_error"], ValueError):
                failures.append("RECEIPT_SIGNATURE_INVALID")
                return
            try:
                import oqs
            except ImportError:
                failures.append(
                    "ALGORITHM_UNSUPPORTED: hybrid-ed25519-ml-dsa-65's PQ half requires the "
                    "optional 'oqs' package (pip install liboqs-python), which is not installed "
                    "in this environment"
                )
                return
            try:
                with oqs.Signature("ML-DSA-65") as verifier:
                    if not verifier.verify(data, bytes.fromhex(pq_sig_hex), bytes.fromhex(pq_pub_hex)):
                        failures.append("RECEIPT_SIGNATURE_INVALID")
            except Exception:
                failures.append("RECEIPT_SIGNATURE_INVALID")
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


def _leaf_hash(data):
    return hashlib.sha256(b"\x00" + data).digest()


def _node_hash(left, right):
    return hashlib.sha256(b"\x01" + left + right).digest()


def _root_from_audit_path(leaf, index, tree_size, path):
    """RFC 9162 section 2.1.3.2 inclusion-proof verification. Must stay
    in lock-step with actaseal.anchoring._root_from_audit_path."""
    if index < 0 or index >= tree_size:
        raise ValueError("leaf index outside claimed tree size")
    fn, sn = index, tree_size - 1
    node = leaf
    for sibling in path:
        if sn == 0:
            raise ValueError("audit path longer than the claimed tree allows")
        if fn % 2 == 1 or fn == sn:
            node = _node_hash(sibling, node)
            if fn % 2 == 0:
                while fn % 2 == 0 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            node = _node_hash(node, sibling)
        fn >>= 1
        sn >>= 1
    if sn != 0:
        raise ValueError("audit path shorter than the claimed tree requires")
    return node


def _largest_pow2_lt(n):
    split = 1
    while split * 2 < n:
        split *= 2
    return split


def _verify_consistency_nodes(m, n, proof):
    """Must stay in lock-step with actaseal.anchoring._verify_consistency_nodes."""
    if m == n:
        h = proof[0]
        return h, h
    k = _largest_pow2_lt(n)
    if m <= k:
        old_h, new_h_left = _verify_consistency_nodes(m, k, proof[:-1])
        new_h = _node_hash(new_h_left, proof[-1])
    else:
        old_h_right, new_h_right = _verify_consistency_nodes(m - k, n - k, proof[:-1])
        old_h = _node_hash(proof[-1], old_h_right)
        new_h = _node_hash(proof[-1], new_h_right)
    return old_h, new_h


def _sth_signing_bytes(sth):
    return canonical_dumps(
        {
            "log_id": sth.get("log_id"),
            "tree_size": sth.get("tree_size"),
            "root_hash": sth.get("root_hash"),
            "timestamp": sth.get("timestamp"),
        }
    ).encode("utf-8")


def _verify_sth_signature(sth, public_key_hex, crypto):
    """Must stay in lock-step with actaseal.anchoring.verify_tree_head /
    actaseal.receipt.verify_signature_bytes's Ed25519/ECDSA branches."""
    algorithm = sth.get("algorithm") or ALGORITHM_ED25519
    try:
        data = _sth_signing_bytes(sth)
        signature_bytes = bytes.fromhex(sth.get("signature", ""))
        if algorithm == ALGORITHM_ED25519:
            public_key = crypto["ed25519_public_key_cls"].from_public_bytes(bytes.fromhex(public_key_hex))
            public_key.verify(signature_bytes, data)
        elif algorithm == ALGORITHM_ECDSA_P256_SHA256:
            ecdsa_public_key = crypto["load_der_public_key"](bytes.fromhex(public_key_hex))
            ecdsa_public_key.verify(signature_bytes, data, crypto["ecdsa_sha256"])
        else:
            return False
    except (
        crypto["invalid_signature_error"],
        crypto["unsupported_algorithm_error"],
        ValueError,
        KeyError,
        TypeError,
    ):
        return False
    return True


def _compute_receipt_hash(receipt):
    """Must stay in lock-step with actaseal.receipt.receipt_hash /
    signing_bytes: sha256 over the canonical receipt payload minus
    signature and tsa_anchor (the latter is stapled AFTER signing)."""
    unsigned = dict(receipt)
    unsigned.pop("signature", None)
    unsigned.pop("tsa_anchor", None)
    return hashlib.sha256(canonical_dumps(unsigned).encode("utf-8")).hexdigest()


def verify_continuity_checkpoint(base, receipt, failures, crypto):
    """T8 (ONESHOT-4 batch 3): optional, additive check -- silent no-op
    when checkpoint.json is absent, same posture as --anchors. When a
    continuity-export bundle includes checkpoint.json (a signed
    SignedTreeHead) and inclusion_proof.json, confirms: the checkpoint's
    own signature verifies against the public key it ships alongside;
    this receipt's hash is included under that checkpoint's root (RFC
    6962 audit-path math); and the inclusion proof's claimed
    root/tree_size actually match the signed checkpoint, not some other
    one. When consistency_proof.json is also present (bridging to an
    older trusted checkpoint), its own math is checked too."""
    checkpoint_path = base / "checkpoint.json"
    if not checkpoint_path.exists():
        return
    checkpoint = _load_doc(base, "checkpoint.json", "CHECKPOINT_DOC_MISSING", failures)
    if checkpoint is None:
        return
    sth = checkpoint.get("sth")
    sth_public_key_hex = checkpoint.get("sth_public_key_hex")
    if not isinstance(sth, dict) or not sth_public_key_hex:
        failures.append("CHECKPOINT_DOC_MALFORMED: checkpoint.json is missing sth or sth_public_key_hex")
        return
    if not _verify_sth_signature(sth, sth_public_key_hex, crypto):
        failures.append(
            "%s:checkpoint.json's signed tree head does not verify against its own public key" % STH_SIGNATURE_INVALID
        )

    proof = _load_doc(base, "inclusion_proof.json", "INCLUSION_PROOF_MISSING", failures)
    if proof is None:
        return

    receipt_hash_value = _compute_receipt_hash(receipt)
    expected_leaf = _leaf_hash(receipt_hash_value.encode("utf-8")).hex()
    if proof.get("leaf_hash") != expected_leaf:
        failures.append(
            "%s:inclusion_proof.leaf_hash does not commit to this receipt's hash" % ANCHOR_INCLUSION_PROOF_INVALID
        )
    else:
        try:
            computed = _root_from_audit_path(
                bytes.fromhex(proof["leaf_hash"]),
                int(proof["entry_id"]),
                int(proof["sth_tree_size"]),
                [bytes.fromhex(node) for node in proof["audit_path"]],
            )
            if computed.hex() != proof.get("sth_root"):
                failures.append(
                    "%s:inclusion_proof audit path does not reproduce sth_root" % ANCHOR_INCLUSION_PROOF_INVALID
                )
        except (ValueError, TypeError, KeyError) as exc:
            failures.append("%s:inclusion_proof is malformed: %s" % (ANCHOR_INCLUSION_PROOF_INVALID, exc))

    if proof.get("sth_root") != sth.get("root_hash") or proof.get("sth_tree_size") != sth.get("tree_size"):
        failures.append(
            "%s:inclusion_proof's checkpoint (root=%r, tree_size=%r) does not match "
            "checkpoint.json's signed tree head (root=%r, tree_size=%r)"
            % (
                ANCHOR_CHECKPOINT_MISMATCH,
                proof.get("sth_root"),
                proof.get("sth_tree_size"),
                sth.get("root_hash"),
                sth.get("tree_size"),
            )
        )

    consistency_path = base / "consistency_proof.json"
    if not consistency_path.exists():
        return
    cproof = _load_doc(base, "consistency_proof.json", "CONSISTENCY_PROOF_MISSING", failures)
    if cproof is None:
        return
    m, n = cproof.get("old_tree_size"), cproof.get("new_tree_size")
    try:
        m, n = int(m), int(n)
    except (TypeError, ValueError):
        failures.append("%s:consistency_proof has non-integer tree sizes" % ANCHOR_CONSISTENCY_PROOF_INVALID)
        return
    if m < 0 or n < 0 or m > n:
        failures.append("%s:consistency_proof has an invalid tree-size relationship" % ANCHOR_CONSISTENCY_PROOF_INVALID)
        return
    if m == 0:
        if cproof.get("proof"):
            failures.append(
                "%s:consistency_proof with old_tree_size=0 must carry no proof nodes"
                % ANCHOR_CONSISTENCY_PROOF_INVALID
            )
        return
    if m == n:
        if cproof.get("proof") or cproof.get("old_root") != cproof.get("new_root"):
            failures.append(
                "%s:consistency_proof for equal tree sizes must have no proof nodes and matching roots"
                % ANCHOR_CONSISTENCY_PROOF_INVALID
            )
        return
    if not cproof.get("proof"):
        failures.append("%s:consistency_proof is missing required proof nodes" % ANCHOR_CONSISTENCY_PROOF_INVALID)
        return
    try:
        nodes = [bytes.fromhex(node) for node in cproof["proof"]]
        old_hash, new_hash = _verify_consistency_nodes(m, n, nodes)
    except (ValueError, TypeError, IndexError, KeyError):
        failures.append("%s:consistency_proof is malformed" % ANCHOR_CONSISTENCY_PROOF_INVALID)
        return
    if old_hash.hex() != cproof.get("old_root"):
        failures.append("%s:consistency_proof does not reproduce old_root" % ANCHOR_CONSISTENCY_PROOF_INVALID)
    if new_hash.hex() != cproof.get("new_root"):
        failures.append("%s:consistency_proof does not reproduce new_root" % ANCHOR_CONSISTENCY_PROOF_INVALID)


def verify_ledger_root_version(base, failures):
    """Reads acquisition.json's ledger_root_version (the field name
    actaseal's packet.py/inspection_pack.py/control_export.py all
    write). Returns the effective version string ("v1"/"v2") for
    callers that need it (e.g. verify_ledger_head_anchor), or None if
    this packet declares an unrecognized version -- in which case a
    LEDGER_ROOT_VERSION_UNKNOWN failure is appended and the caller must
    not proceed as if a known version were in effect.

    Missing entirely (no acquisition.json, or acquisition.json without
    the key) means v1: this field did not exist before RCA1, so every
    packet built before it defaults to the version they always were --
    never a silent behavior change for old packets."""
    acquisition = _load_doc(base, "acquisition.json", "ACQUISITION_REPORT_MISSING", [])
    if acquisition is None:
        return LEDGER_ROOT_VERSION_V1
    version = acquisition.get("ledger_root_version")
    if version is None:
        return LEDGER_ROOT_VERSION_V1
    if version not in VERIFIER_SUPPORTS_ROOT_VERSIONS:
        failures.append("%s: %r" % (LEDGER_ROOT_VERSION_UNKNOWN, version))
        return None
    return version


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

    # ledger_slice.ndjson is the CONTIGUOUS span between this action's
    # first and last event (see actaseal.dispute.packet.
    # extract_ledger_slice) -- by design, that span can include OTHER
    # actions' events interleaved in between (e.g. a BREACH acknowledged
    # after a different action scope-evaluated in between). Scoping by
    # action_id here is required so a foreign ScopeEvaluated event never
    # gets compared against this receipt's own scope_conformance.
    action_id = manifest.get("action_id")
    scope_events = [
        event
        for event in events
        if event.get("event_type") == "ScopeEvaluated" and event.get("action_id") == action_id
    ]
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


def verify_approver_snapshot(manifest, receipt, events, failures):
    """When present, the receipt's approver_snapshot_hash must recompute
    from an ApproverSnapshotCaptured ledger event for this action --
    additive: a receipt that predates this field (approver_snapshot_hash
    is None) is not checked at all, and stays valid either way. This is
    the frozen record of exactly what the human approver saw (scope-vs-
    action comparison, TTL remaining, request state) at decision time."""
    snapshot_hash = receipt.get("approver_snapshot_hash")
    if snapshot_hash is None:
        return

    action_id = manifest.get("action_id")
    snapshot_events = [
        event
        for event in events
        if event.get("event_type") == "ApproverSnapshotCaptured" and event.get("action_id") == action_id
    ]
    if not snapshot_events:
        failures.append(
            "APPROVER_SNAPSHOT_EVENT_MISSING: receipt.json claims an approver_snapshot_hash "
            "the ledger_slice.ndjson never witnessed (no ApproverSnapshotCaptured event)"
        )
        return
    payload = snapshot_events[-1].get("payload", {})
    if canonical_hash(payload) != snapshot_hash:
        failures.append(
            "APPROVER_SNAPSHOT_HASH_MISMATCH: ApproverSnapshotCaptured payload does not "
            "recompute to receipt.json's approver_snapshot_hash"
        )


def verify_ledger_head_anchor(base, failures, anchors_path):
    """Given an external anchor log (a jsonl file of {root_hash,
    anchored_at, status, ...} records -- see
    actaseal.ledger_anchor.FileAnchorBackend / scripts/publish_anchor.py),
    confirms this packet's ledger_root_hash (acquisition.json) was
    witnessed by some successful anchor entry. Optional: only runs when
    --anchors PATH is passed on the command line -- a packet does not
    ship its own anchor log, since anchoring is a separate, periodic
    operator workflow, not part of packet capture. Silent no-op when
    --anchors is not given, same posture as every other optional check
    in this verifier."""
    if anchors_path is None:
        return
    acquisition = _load_doc(base, "acquisition.json", "ACQUISITION_REPORT_MISSING", [])
    root_hash = acquisition.get("ledger_root_hash") if acquisition else None
    # Dual-version aware: an anchor entry written for a v2 root must
    # not be matched against a v1 root_hash that happens to differ
    # only because it's a different algorithm's value, and vice versa.
    # Absent on either side defaults to v1, same convention as
    # verify_ledger_root_version above and AnchorRecord.root_version's
    # own default on the actaseal side.
    root_version = (acquisition.get("ledger_root_version") if acquisition else None) or LEDGER_ROOT_VERSION_V1
    if not root_hash:
        failures.append(
            "ANCHOR_CHECK_NO_LEDGER_ROOT_HASH: acquisition.json carries no ledger_root_hash to check "
            "against the supplied anchor log"
        )
        return
    try:
        lines = Path(anchors_path).read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        failures.append("ANCHOR_LOG_UNREADABLE: %s" % exc)
        return
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        entry_root_version = entry.get("root_version") or LEDGER_ROOT_VERSION_V1
        if (
            entry.get("root_hash") == root_hash
            and entry_root_version == root_version
            and entry.get("status") == "OK"
        ):
            return
    failures.append(
        "ANCHOR_ENTRY_NOT_FOUND: no successful anchor entry in %s witnesses this packet's "
        "ledger_root_hash %r (root_version %r)" % (anchors_path, root_hash, root_version)
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


def verify_rfc3161_token(token_der_hex, hash_hex, ca_cert_paths):
    """ATTESTATION-LIVE Task 4: offline-verify an RFC 3161 (+ RFC 5816
    structure) TimeStampToken against a HASH the caller supplies (never
    trusted from inside the token) and a CONFIGURABLE, multi-member root
    bundle -- a buyer's own qualified TSA, freetsa.org's, or several at
    once. Succeeds if the token validates against ANY certificate in
    `ca_cert_paths` (tried in order); this is the "multi-TSA root
    bundle" the task asks for -- not full PKIX path validation (see the
    limitations list below, faithfully carried over unchanged).

    Faithful, standalone port of actaseal.anchor.tsa.verify_tsa_token --
    must stay in lock-step with it; this is not a second, divergent
    implementation, it is the SAME checks (messageImprint match, CMS
    SignedData signature over signedAttrs, signedAttrs messageDigest
    binding to TSTInfo, signer cert chains to a pinned CA) reproduced
    here because this file ships with zero actaseal imports (any
    third party can run it standalone) and the private repo's version
    imports actaseal.airgap/actaseal.crypto_agility this file cannot.

    Requires 'asn1crypto' in addition to 'cryptography' -- a real, new
    dependency for THIS specific optional check (CMS/ASN.1 parsing is
    unavoidable for RFC 3161 token verification), not for the base
    dispute-packet verification flow, which still requires nothing
    beyond the stdlib + 'cryptography'. Documented here rather than
    silently added: if asn1crypto is unavailable, this function raises
    ImportError with a clear message, same "can't run, say so" posture
    as main()'s own missing-cryptography check.

    Returns (ok, failures)."""
    try:
        from asn1crypto import cms, tsp  # noqa: F401 -- importing tsp registers the TSTInfo content-type OID
    except ImportError as exc:
        raise ImportError(
            "verify_rfc3161_token requires the 'asn1crypto' package (pip install asn1crypto) "
            "for RFC 3161 CMS/ASN.1 parsing"
        ) from exc
    from cryptography import x509 as cx509
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

    failures = []
    hash_bytes = bytes.fromhex(hash_hex)
    try:
        token_der = bytes.fromhex(token_der_hex)
        ci = cms.ContentInfo.load(token_der)
        sd = ci["content"]
        tst_info = sd["encap_content_info"]["content"].parsed
        message_imprint = tst_info["message_imprint"]["hashed_message"].native
        if message_imprint != hash_bytes:
            failures.append(TSA_TOKEN_HASH_MISMATCH)
            return False, failures

        signer_infos = sd["signer_infos"]
        if len(signer_infos) != 1:
            failures.append("%s: unexpected signer count" % TSA_TOKEN_INVALID)
            return False, failures
        signer_info = signer_infos[0]

        certs = sd["certificates"]
        if len(certs) < 1:
            failures.append("%s: no signer certificate in token" % TSA_TOKEN_INVALID)
            return False, failures
        signer_cert_der = certs[0].chosen.dump()
        signer_cert = cx509.load_der_x509_certificate(signer_cert_der, default_backend())

        signed_attrs = signer_info["signed_attrs"]
        # RFC 5652: the signature covers the SET OF encoding (tag 0x31)
        # of signed_attrs, not its context-specific [0] IMPLICIT encoding.
        signed_attrs_der = b"\x31" + signed_attrs.dump()[1:]
        signature = signer_info["signature"].native
        digest_algo = signer_info["digest_algorithm"]["algorithm"].native
        hash_map = {"sha256": hashes.SHA256, "sha384": hashes.SHA384, "sha512": hashes.SHA512}
        hash_cls = hash_map.get(digest_algo)
        if hash_cls is None:
            failures.append("%s: unsupported digest algorithm %r" % (TSA_TOKEN_INVALID, digest_algo))
            return False, failures

        signer_public_key = signer_cert.public_key()
        try:
            if isinstance(signer_public_key, rsa.RSAPublicKey):
                signer_public_key.verify(signature, signed_attrs_der, padding.PKCS1v15(), hash_cls())
            else:
                signer_public_key.verify(signature, signed_attrs_der, ec.ECDSA(hash_cls()))
        except InvalidSignature:
            failures.append("%s: signature over signed attributes does not verify" % TSA_TOKEN_INVALID)

        message_digest_attr = None
        for attr in signed_attrs:
            if attr["type"].native == "message_digest":
                message_digest_attr = attr["values"][0].native
        content_bytes = bytes(sd["encap_content_info"]["content"])
        digest_ctor = {"sha256": hashlib.sha256, "sha384": hashlib.sha384, "sha512": hashlib.sha512}[digest_algo]
        actual_digest = digest_ctor(content_bytes).digest()
        if message_digest_attr != actual_digest:
            failures.append("%s: signedAttrs messageDigest does not match TSTInfo content" % TSA_TOKEN_INVALID)
        if failures:
            return False, failures

        # Multi-TSA root bundle: succeed against ANY configured CA.
        chain_failures = []
        for ca_cert_path in ca_cert_paths:
            ca_path = Path(ca_cert_path)
            if not ca_path.is_file():
                chain_failures.append("%s: CA cert unavailable" % ca_cert_path)
                continue
            try:
                ca_cert = cx509.load_pem_x509_certificate(ca_path.read_bytes(), default_backend())
                ca_public_key = ca_cert.public_key()
                if isinstance(ca_public_key, rsa.RSAPublicKey):
                    ca_public_key.verify(
                        signer_cert.signature, signer_cert.tbs_certificate_bytes,
                        padding.PKCS1v15(), signer_cert.signature_hash_algorithm,
                    )
                else:
                    ca_public_key.verify(
                        signer_cert.signature, signer_cert.tbs_certificate_bytes,
                        ec.ECDSA(signer_cert.signature_hash_algorithm),
                    )
                return True, []  # matched this root -- done, do not evaluate the rest of the bundle
            except InvalidSignature:
                chain_failures.append("%s: does not chain to this root" % ca_cert_path)
                continue
        failures.append(
            "%s: signer certificate did not chain to any of %d configured root(s): %s"
            % (TSA_TOKEN_NO_TRUSTED_ROOT, len(ca_cert_paths), "; ".join(chain_failures))
        )
    except Exception as exc:  # noqa: BLE001 -- any parse failure is a verify failure, not a crash
        failures.append("%s: malformed token: %s: %s" % (TSA_TOKEN_INVALID, type(exc).__name__, exc))
        return False, failures
    return (not failures), failures


def verify_scitt_receipt(subject_hash_hex, receipt, sth_public_key_hex, crypto):
    """ATTESTATION-LIVE Task 4: offline-verify a SCITT (RFC 9943) Receipt
    -- {registration_id, inclusion_proof, signed_tree_head, ...}, the
    shape actaseal.archive.transparency_service.Receipt.to_dict() emits
    -- against PUBLISHED ledger state (the caller fetches the current
    SignedTreeHead + public key from GET /trust/archive-transparency-
    sth.json, or trusts the sth embedded in the receipt itself and only
    checks its signature -- both are supported: this function takes
    whichever SignedTreeHead the caller wants checked against).

    Reuses this file's own _leaf_hash/_root_from_audit_path/
    _verify_sth_signature (the SAME functions verify_continuity_
    checkpoint above already uses for the dispute-packet's own inclusion
    proof) -- no second Merkle or signature implementation. `receipt`
    is a dict with `inclusion_proof` (log_id, entry_id, leaf_hash,
    audit_path, sth_root, sth_tree_size) and `signed_tree_head` (log_id,
    tree_size, root_hash, timestamp, key_id, algorithm, signature) sub-
    dicts, mirroring actaseal.anchoring.InclusionProof/SignedTreeHead's
    own to_dict() shape unchanged.

    Returns (ok, failures)."""
    failures = []
    proof = receipt.get("inclusion_proof") or {}
    sth = receipt.get("signed_tree_head") or {}

    if not _verify_sth_signature(sth, sth_public_key_hex, crypto):
        failures.append("%s: signed_tree_head does not verify against the given public key" % STH_SIGNATURE_INVALID)

    expected_leaf = _leaf_hash(subject_hash_hex.encode("utf-8")).hex()
    if proof.get("leaf_hash") != expected_leaf:
        failures.append(
            "%s:inclusion_proof.leaf_hash does not commit to this subject hash" % ANCHOR_INCLUSION_PROOF_INVALID
        )
    else:
        try:
            computed = _root_from_audit_path(
                bytes.fromhex(proof["leaf_hash"]), int(proof["entry_id"]), int(proof["sth_tree_size"]),
                [bytes.fromhex(node) for node in proof["audit_path"]],
            )
            if computed.hex() != proof.get("sth_root"):
                failures.append(
                    "%s:inclusion_proof audit path does not reproduce sth_root" % ANCHOR_INCLUSION_PROOF_INVALID
                )
        except (ValueError, TypeError, KeyError) as exc:
            failures.append("%s:inclusion_proof is malformed: %s" % (ANCHOR_INCLUSION_PROOF_INVALID, exc))

    if proof.get("sth_root") != sth.get("root_hash") or proof.get("sth_tree_size") != sth.get("tree_size"):
        failures.append(
            "%s:inclusion_proof's checkpoint (root=%r, tree_size=%r) does not match the given "
            "signed tree head (root=%r, tree_size=%r)"
            % (
                ANCHOR_CHECKPOINT_MISMATCH, proof.get("sth_root"), proof.get("sth_tree_size"),
                sth.get("root_hash"), sth.get("tree_size"),
            )
        )
    return (not failures), failures


# READINESS-AND-SHIP Task 1: verifies an AS 1215 archive engagement
# export (actaseal.archive.inspection_pack.build_inspection_pack's
# output -- an "inspection pack" zip is exactly this export; there is
# no separate export format to build) standalone, with no ActaSeal
# import, no network, and the server stopped. That export already
# contains everything a seven-year retention holder needs: the
# engagement's own ledger_slice.ndjson (records), archive_attestation.
# json (the RFC 3161 token AND the SCITT transparency receipt, both
# embedded inside its two evidence-record chains -- see
# actaseal.archive.attestation.issue_archive_attestation), and
# workpaper_index.json (the hash manifest). See docs/EXPORT.md.
ARCHIVE_EXPORT_SCHEMA_VERSION = "inspection_pack.v1"

ARCHIVE_EXPORT_MANIFEST_SCHEMA_MISMATCH = "ARCHIVE_EXPORT_MANIFEST_SCHEMA_MISMATCH"
ARCHIVE_EXPORT_EVENT_COUNT_MISMATCH = "ARCHIVE_EXPORT_EVENT_COUNT_MISMATCH"
ARCHIVE_EXPORT_EMPTY_LEDGER_SLICE = "ARCHIVE_EXPORT_EMPTY_LEDGER_SLICE"
ARCHIVE_EXPORT_CHAIN_START_MISMATCH = "ARCHIVE_EXPORT_CHAIN_START_MISMATCH"
ARCHIVE_EXPORT_CHAIN_BROKEN = "ARCHIVE_EXPORT_CHAIN_BROKEN"
ARCHIVE_EXPORT_MALFORMED_EVENT = "ARCHIVE_EXPORT_MALFORMED_EVENT"
ARCHIVE_EXPORT_WORKPAPER_SET_TAMPERED = "ARCHIVE_EXPORT_WORKPAPER_SET_TAMPERED"


def load_archive_export(base):
    """`base` is a directory holding the four files an inspection pack
    zip contains once extracted (manifest.json, workpaper_index.json,
    archive_attestation.json, ledger_slice.ndjson) -- extract the zip
    first (this function does not open zips itself, matching
    load_packet's own directory-only contract above)."""
    manifest = json.loads((base / "manifest.json").read_text(encoding="utf-8"))
    workpaper_index = json.loads((base / "workpaper_index.json").read_text(encoding="utf-8"))
    attestation = json.loads((base / "archive_attestation.json").read_text(encoding="utf-8"))
    events = []
    for line in (base / "ledger_slice.ndjson").read_text(encoding="utf-8").splitlines():
        if line.strip():
            event = json.loads(line)
            if not isinstance(event, dict):
                raise ValueError("each ledger_slice.ndjson line must be a JSON object, got %s" % type(event).__name__)
            events.append(event)
    return manifest, workpaper_index, attestation, events


def verify_archive_export_ledger_slice(manifest, events, failures):
    """Same per-event recomputation as verify_events above (payload_hash/
    event_id/event_hash/chain contiguity, via the same canonical_hash/
    EVENT_MATERIAL_FIELDS/EVENT_ID_BASIS) -- a separate function, not a
    call into verify_events, because an inspection-pack manifest has no
    action_id to bind a single receipt to (an engagement's slice
    legitimately spans several action_ids -- its own, plus one per
    workpaper) and a different schema_version. Must stay in lock-step
    with actaseal.archive.inspection_pack._verify_slice_hash_chain."""
    if manifest.get("schema_version") != ARCHIVE_EXPORT_SCHEMA_VERSION:
        failures.append(ARCHIVE_EXPORT_MANIFEST_SCHEMA_MISMATCH)
    if manifest.get("event_count") != len(events):
        failures.append(
            "%s: manifest=%r slice=%d" % (ARCHIVE_EXPORT_EVENT_COUNT_MISMATCH, manifest.get("event_count"), len(events))
        )
    if not events:
        failures.append(ARCHIVE_EXPORT_EMPTY_LEDGER_SLICE)
        return
    if events[0].get("previous_event_hash") != manifest.get("chain_start_previous_event_hash"):
        failures.append(ARCHIVE_EXPORT_CHAIN_START_MISMATCH)
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
                failures.append("%s: event %d" % (ARCHIVE_EXPORT_CHAIN_BROKEN, index))
            previous_hash = event["event_hash"]
        except Exception as exc:
            failures.append("%s: event %d: %s" % (ARCHIVE_EXPORT_MALFORMED_EVENT, index, exc))
            return


def _merkle_root_from_leaves(leaves):
    """Must stay in lock-step with actaseal.anchoring._merkle_root (the
    Merkle Tree Hash per RFC 9162 section 2, domain-separated leaf/node
    hashing -- _leaf_hash/_node_hash above are already that same
    construction, reused unchanged)."""
    if not leaves:
        return hashlib.sha256(b"").digest()
    if len(leaves) == 1:
        return leaves[0]
    split = 1
    while split * 2 < len(leaves):
        split *= 2
    return _node_hash(_merkle_root_from_leaves(leaves[:split]), _merkle_root_from_leaves(leaves[split:]))


def _compute_workpaper_set_hashes(workpaper_hashes):
    """Must stay in lock-step with actaseal.archive.attestation.
    compute_workpaper_set_hashes -- the subject an ArchiveAttestation's
    two evidence-record chains actually commit to: a Merkle root over
    the engagement's SORTED workpaper content hashes, itself hashed
    under sha256 (the root value itself) and sha3-256 (of the root's
    raw bytes)."""
    leaves = [_leaf_hash(bytes.fromhex(h)) for h in sorted(workpaper_hashes)]
    root_hex = _merkle_root_from_leaves(leaves).hex()
    return {"sha256": root_hex, "sha3-256": hashlib.sha3_256(bytes.fromhex(root_hex)).hexdigest()}


def verify_archive_export(base, *, tsa_ca_cert_paths=None, sth_public_key_hex=None, crypto=None):
    """Full, standalone verification of an extracted inspection-pack
    export directory -- everything a third party needs, with no
    ActaSeal import, no network, and (if the caller omits
    tsa_ca_cert_paths/sth_public_key_hex) no external trust root
    required for the parts that don't need one. Returns (ok, failures).

    `tsa_ca_cert_paths`, if given, additionally verifies the embedded
    RFC 3161 token against that root bundle (requires asn1crypto -- see
    verify_rfc3161_token). `sth_public_key_hex`, if given, additionally
    verifies the embedded SCITT receipt's signed checkpoint against that
    public key (see verify_scitt_receipt) -- both optional because a
    reader may only have one of the two trust roots in hand, and the
    hash-chain + workpaper-set checks below are unconditional and need
    neither."""
    failures = []
    try:
        manifest, workpaper_index, attestation, events = load_archive_export(base)
    except Exception as exc:
        return False, ["UNREADABLE_ARCHIVE_EXPORT: %s" % exc]

    verify_archive_export_ledger_slice(manifest, events, failures)

    workpapers = workpaper_index.get("workpapers") or []
    current_hashes = [w["content_hash"] for w in workpapers if w.get("content_hash")]
    chains = (attestation.get("evidence_record") or {}).get("chains") or []
    subject_hashes = (attestation.get("evidence_record") or {}).get("subject_hashes") or {}
    current_subject_hashes = _compute_workpaper_set_hashes(current_hashes) if current_hashes else {}
    if current_subject_hashes != subject_hashes:
        failures.append(ARCHIVE_EXPORT_WORKPAPER_SET_TAMPERED)

    if tsa_ca_cert_paths:
        tsa_chain = next((c for c in chains if c.get("anchor_type") == "rfc3161_tsa"), None)
        if tsa_chain is None:
            failures.append("ARCHIVE_EXPORT_NO_TSA_CHAIN: archive_attestation.json carries no rfc3161_tsa chain")
        else:
            ok, tsa_failures = verify_rfc3161_token(
                tsa_chain["anchor"]["token_der_hex"], subject_hashes.get("sha256", ""), tsa_ca_cert_paths,
            )
            if not ok:
                failures.extend("ARCHIVE_EXPORT_TSA_CHAIN: %s" % f for f in tsa_failures)

    if sth_public_key_hex:
        scitt_chain = next((c for c in chains if c.get("anchor_type") == "sth_inclusion"), None)
        if scitt_chain is None:
            failures.append("ARCHIVE_EXPORT_NO_SCITT_CHAIN: archive_attestation.json carries no sth_inclusion chain")
        else:
            receipt_shape = {
                "inclusion_proof": scitt_chain["anchor"]["inclusion_proof"],
                "signed_tree_head": scitt_chain["anchor"]["sth"],
            }
            ok, scitt_failures = verify_scitt_receipt(
                subject_hashes.get("sha3-256", ""), receipt_shape, sth_public_key_hex, crypto or {},
            )
            if not ok:
                failures.extend("ARCHIVE_EXPORT_SCITT_CHAIN: %s" % f for f in scitt_failures)

    return (not failures), failures


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

    # --anchors PATH, --archive-export, --tsa-ca-cert PATH (repeatable),
    # --sth-public-key HEX are optional flags, stripped out before the
    # positional packet_dir argument is resolved -- any can appear
    # anywhere in argv.
    positional = []
    anchors_path = None
    archive_export_mode = False
    tsa_ca_cert_paths = []
    sth_public_key_hex = None
    args = list(argv[1:])
    while args:
        arg = args.pop(0)
        if arg == "--anchors":
            if not args:
                print("UNABLE_TO_RUN: --anchors requires a path argument")
                return 2
            anchors_path = args.pop(0)
        elif arg == "--archive-export":
            archive_export_mode = True
        elif arg == "--tsa-ca-cert":
            if not args:
                print("UNABLE_TO_RUN: --tsa-ca-cert requires a path argument")
                return 2
            tsa_ca_cert_paths.append(args.pop(0))
        elif arg == "--sth-public-key":
            if not args:
                print("UNABLE_TO_RUN: --sth-public-key requires a hex-encoded public key argument")
                return 2
            sth_public_key_hex = args.pop(0)
        else:
            positional.append(arg)

    base = Path(positional[0]) if positional else Path(__file__).resolve().parent

    if archive_export_mode:
        # A different artifact type (an AS 1215 archive engagement
        # export -- see docs/EXPORT.md), not a money-action dispute
        # packet: a separate verification path, not folded into the
        # flow below, since the two share no manifest shape.
        ok, export_failures = verify_archive_export(
            base, tsa_ca_cert_paths=tsa_ca_cert_paths or None, sth_public_key_hex=sth_public_key_hex, crypto=crypto,
        )
        if not ok:
            print("VERIFICATION FAILED")
            for failure in export_failures:
                print("  " + failure)
            return 1
        print("VERIFIED (archive export): ledger chain intact, workpaper set matches attestation")
        if tsa_ca_cert_paths:
            print("  RFC 3161 timestamp verified against the supplied CA bundle")
        if sth_public_key_hex:
            print("  SCITT transparency receipt verified against the supplied public key")
        return 0
    failures = []
    try:
        manifest, receipt, events = load_packet(base)
    except Exception as exc:
        print("VERIFICATION FAILED")
        print("  UNREADABLE_PACKET: %s" % exc)
        return 1

    verify_ledger_root_version(base, failures)
    verify_events(manifest, events, failures)
    verify_receipt(manifest, receipt, events, failures, crypto)
    verify_continuity_checkpoint(base, receipt, failures, crypto)
    verify_authentication_docs(receipt, events, base, failures)
    verify_scope_conformance(manifest, receipt, events, failures)
    verify_approver_snapshot(manifest, receipt, events, failures)
    verify_ledger_head_anchor(base, failures, anchors_path)
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
