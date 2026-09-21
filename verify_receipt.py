#!/usr/bin/env python3
"""Standalone verifier for a single ActaSeal receipt JSON.

Lighter-weight sibling of offline_verifier.py: that script verifies a full
dispute EVIDENCE PACKET (manifest.json + receipt.json + ledger_slice.ndjson
+ FRE 901/902 authentication docs, as a directory). This script verifies
just a RECEIPT -- no packet, no manifest, no authentication docs required.
Useful when a counterparty has nothing but a receipt JSON (e.g. pasted from
an email, attached to a chargeback response) and wants to check it is
genuinely signed by the claimed key, without needing the full dispute
packet machinery.

Standalone by design, same posture as offline_verifier.py: no actaseal
imports, so this file can be copied to the public actaseal-verify repo
unchanged. Requires only the Python standard library plus the
'cryptography' package (Ed25519 + ECDSA P-256/SHA-256).

Input JSON shape (one object, read from a file path argument or stdin):
    {
      "receipt": { ... PolicyDecisionReceipt.to_dict() shape ... },
      "receipt_public_key_hex": "<hex>",
      "ledger_slice": [ { ...ledger event... }, ... ]   # optional
    }
"receipt_public_key_hex" is a top-level sibling of "receipt" (not embedded
inside it) -- same convention as offline_verifier.py's manifest.json
carrying receipt_public_key_hex alongside receipt.json rather than inside
it. Compare it out of band against the gateway operator's published key: a
receipt re-signed end to end with a different key is internally
consistent and will still PASS this check alone.

"ledger_slice" is optional. When present, it is a list of ledger event
dicts in the same shape as offline_verifier.py's ledger_slice.ndjson
events (each carrying event_hash / previous_event_hash / event_id /
payload / payload_hash). When present, this script additionally checks
the slice is an unbroken hash chain and that the receipt's
ledger_entry_hash names an event_hash present in the slice. When absent,
this check is skipped entirely -- a bare receipt with no chain data still
gets a full PASS on signature alone.

T5: keyless / hash-linked verification mode. `--checkpoint <hex>`
supplies a trusted checkpoint hash OUT OF BAND (a CLI flag, never read
from the document itself -- a checkpoint embedded in the same JSON a
tamperer controls would prove nothing). When given, a receipt can PASS
purely on hash-linkage even with an unknown or rotated signing key: if
`ledger_slice` is present, forms an unbroken chain, contains the
receipt's `ledger_entry_hash`, AND the supplied checkpoint hash names
an `event_hash` actually present in that chain, the receipt PASSes with
verdict mode CHAIN_VERIFIED_KEY_UNKNOWN -- distinct from, and never
conflated with, a genuine signature check. `receipt_public_key_hex`
becomes optional in the input document when `--checkpoint` is supplied
(a caller in keyless mode may not have a key at all); if it is present
anyway and the signature independently verifies, the stronger verdict
mode SIGNATURE_VERIFIED wins and is reported instead. Without
`--checkpoint`, behavior is unchanged from before this mode existed:
`receipt_public_key_hex` is required, and `ledger_slice` (if present)
is checked as before.

The "trusted checkpoint" here is intentionally a bare hash, not a full
transparency-log inclusion proof (e.g. a Merkle audit path against a
published tree head) -- see actaseal.anchoring / actaseal.ledger_anchor
for ActaSeal's actual chain-head anchoring mechanism, which is the real
source of a checkpoint hash a caller would treat as trusted. This
script only checks the checkpoint names a hash present in the supplied
slice; it does not itself fetch or validate any transparency log.

Usage: python verify_receipt.py [receipt_file.json] [--checkpoint <hex>]
  receipt_file.json defaults to stdin when omitted.
Exit codes: 0 PASS, 1 FAIL (signature and/or chain check failed),
2 malformed input (unreadable JSON, missing required fields, missing
'cryptography' package).
"""
from __future__ import annotations

import hashlib
import json
import sys

# Must stay in lock-step with actaseal.signing.ALGORITHM_* and
# offline_verifier.py's copy of the same constants.
ALGORITHM_ED25519 = "ed25519"
ALGORITHM_ECDSA_P256_SHA256 = "ecdsa-p256-sha256"
# T6: recognized but OPTIONAL -- verifying this algorithm needs the
# 'oqs' package (liboqs-python), which this standalone script does NOT
# hard-depend on (its own docstring promises stdlib + 'cryptography'
# only). A receipt naming this algorithm is a recognized, well-formed
# case -- distinct from a genuinely unknown algorithm string -- that
# fails closed with ALGORITHM_UNSUPPORTED when 'oqs' isn't importable
# here, rather than the generic RECEIPT_SIGNATURE_ALGORITHM_UNKNOWN.
ALGORITHM_ML_DSA_65 = "ml-dsa-65"
# P7 (ONESHOT-PERMA): CNSA 2.0 profile, same optional-'oqs' posture as
# ALGORITHM_ML_DSA_65 immediately below.
ALGORITHM_ML_DSA_87 = "ml-dsa-87"
# ONESHOT-MONEY T2: hybrid classical+PQ. Signature and public key are both
# "<ed25519_hex>.<ml_dsa_65_hex>" -- PASS requires BOTH halves to verify
# independently (stripping the PQ half to present a bare Ed25519 signature
# must not verify as hybrid -- see actaseal.crypto.hybrid_signer, which
# this mirrors without importing actaseal, matching this script's own
# stdlib+cryptography(+optional oqs)-only dependency posture).
ALGORITHM_HYBRID_ED25519_ML_DSA_65 = "hybrid-ed25519-ml-dsa-65"
HYBRID_PART_SEPARATOR = "."

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


def verify_signature(receipt, public_key_hex, failures, crypto):
    unsigned = dict(receipt)
    signature = unsigned.pop("signature", "")
    # tsa_anchor (T1) is stapled onto a receipt AFTER signing -- the
    # signature covers signing_bytes(), which excludes it -- so it must
    # be excluded here too, the same way "signature" itself is. Must
    # stay in lock-step with actaseal.receipt._receipt_payload.
    unsigned.pop("tsa_anchor", None)
    algorithm = receipt.get("algorithm") or ALGORITHM_ED25519
    try:
        data = canonical_dumps(unsigned).encode("utf-8")
        signature_bytes = bytes.fromhex(signature)
        if algorithm == ALGORITHM_ED25519:
            public_key = crypto["ed25519_public_key_cls"].from_public_bytes(bytes.fromhex(public_key_hex))
            public_key.verify(signature_bytes, data)
        elif algorithm == ALGORITHM_ECDSA_P256_SHA256:
            ecdsa_public_key = crypto["load_der_public_key"](bytes.fromhex(public_key_hex))
            ecdsa_public_key.verify(signature_bytes, data, crypto["ecdsa_sha256"])
        elif algorithm == ALGORITHM_ML_DSA_65:
            try:
                import oqs
            except ImportError:
                failures.append(
                    "ALGORITHM_UNSUPPORTED: ml-dsa-65 requires the optional 'oqs' package "
                    "(pip install liboqs-python), which is not installed in this environment"
                )
                return
            try:
                with oqs.Signature("ML-DSA-65") as verifier:
                    if not verifier.verify(data, signature_bytes, bytes.fromhex(public_key_hex)):
                        failures.append("RECEIPT_SIGNATURE_INVALID")
            except Exception:
                failures.append("RECEIPT_SIGNATURE_INVALID")
        elif algorithm == ALGORITHM_ML_DSA_87:
            try:
                import oqs
            except ImportError:
                failures.append(
                    "ALGORITHM_UNSUPPORTED: ml-dsa-87 requires the optional 'oqs' package "
                    "(pip install liboqs-python), which is not installed in this environment"
                )
                return
            try:
                with oqs.Signature("ML-DSA-87") as verifier:
                    if not verifier.verify(data, signature_bytes, bytes.fromhex(public_key_hex)):
                        failures.append("RECEIPT_SIGNATURE_INVALID")
            except Exception:
                failures.append("RECEIPT_SIGNATURE_INVALID")
        elif algorithm == ALGORITHM_HYBRID_ED25519_ML_DSA_65:
            # signature/public_key_hex are this script's own raw-bytes
            # hex convention; the hybrid signer's "<ed>.<pq>" hex-pair
            # format lives one layer inside that, as plain ASCII bytes
            # (must stay in lock-step with actaseal.receipt's own
            # ALGORITHM_HYBRID_ED25519_ML_DSA_65 branch).
            try:
                dotted_signature = bytes.fromhex(signature).decode("ascii")
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
    except (
        crypto["invalid_signature_error"],
        crypto["unsupported_algorithm_error"],
        ValueError,
        KeyError,
        TypeError,
    ):
        failures.append("RECEIPT_SIGNATURE_INVALID")


def _chain_hashes(ledger_slice, failures):
    """Shared chain-linkage walk used by both verify_chain (legacy,
    non-checkpoint path) and verify_checkpoint_chain (T5). Returns the
    set of event_hash values in the slice, or None if the slice itself
    is malformed (failures already populated in that case)."""
    if not ledger_slice:
        failures.append("EMPTY_LEDGER_SLICE")
        return None
    previous_hash = None
    for index, event in enumerate(ledger_slice):
        try:
            if index > 0 and event.get("previous_event_hash") != previous_hash:
                failures.append("CHAIN_BROKEN: event %d" % index)
            previous_hash = event.get("event_hash")
        except (AttributeError, TypeError) as exc:
            failures.append("MALFORMED_LEDGER_EVENT: event %d: %s" % (index, exc))
            return None
    return set(event.get("event_hash") for event in ledger_slice)


def verify_chain(receipt, ledger_slice, failures):
    """Optional check: only runs when ledger_slice is present. Verifies
    the slice is an unbroken hash chain (each event's previous_event_hash
    matches the prior event's event_hash) and that the receipt's
    ledger_entry_hash names an event_hash present in the slice."""
    slice_hashes = _chain_hashes(ledger_slice, failures)
    if slice_hashes is None:
        return
    if receipt.get("ledger_entry_hash") not in slice_hashes:
        failures.append("RECEIPT_LEDGER_ENTRY_NOT_IN_SLICE")


def verify_checkpoint_chain(receipt, ledger_slice, checkpoint_hash, failures):
    """T5: keyless/hash-linked verification. Like verify_chain, but also
    requires the out-of-band-supplied `checkpoint_hash` to name an
    event_hash actually present in the (unbroken) slice -- the trusted
    anchor that lets this PASS stand in for a signature check. Appends
    to `failures` (never raises) so callers can combine this with a
    parallel signature-check attempt and report every reason a keyless
    PASS was not reached."""
    slice_hashes = _chain_hashes(ledger_slice, failures)
    if slice_hashes is None:
        return
    if receipt.get("ledger_entry_hash") not in slice_hashes:
        failures.append("RECEIPT_LEDGER_ENTRY_NOT_IN_SLICE")
    if checkpoint_hash not in slice_hashes:
        failures.append("CHECKPOINT_NOT_IN_SLICE")


VALIDATION_MATERIAL_MISSING = "VALIDATION_MATERIAL_MISSING"


def check_validation_material(document, warnings, failures):
    """P3 (ONESHOT-PERMA, LTA-style embedded validation material): a
    packet built by actaseal.dispute.packet.build_dispute_packet may
    carry a top-level "validation_material" object (signing-key/chain
    refs, key-registry snapshot, anchor certs, algorithm identifiers)
    so it verifies decades later with zero external lookups. Its
    absence is only a hard failure when the document explicitly marks
    itself as requiring it (`validation_material_required: true`,
    the posture new packets should set); older packets that predate
    this field get a warning, never a failure -- see docs/archive/
    lta_validation_material.md for the offline_verifier.py (pinned,
    unmodified) gap this leaves."""
    present = document.get("validation_material") is not None
    if present:
        return
    required = bool(document.get("validation_material_required"))
    message = (
        "%s: no embedded validation_material -- this packet cannot be "
        "re-verified offline decades from now without external lookups" % VALIDATION_MATERIAL_MISSING
    )
    if required:
        failures.append(message)
    else:
        warnings.append(message)


# ONESHOT-AUDIT Task B: ARCHIVE_ATTESTATION structural verification.
#
# Same Merkle Tree Hash per RFC 9162 §2 (hash construction unchanged
# from RFC 6962) domain-separated leaf/node hashing as
# actaseal.anchoring._merkle_root -- duplicated here rather than
# imported, same standalone-script posture as everything else in this
# file (and as offline_verifier.py's own local copy of the same
# primitives, see its _leaf_hash/_node_hash).
def _leaf_hash(data):
    return hashlib.sha256(b"\x00" + data).digest()


def _node_hash(left, right):
    return hashlib.sha256(b"\x01" + left + right).digest()


def _merkle_root(leaves):
    if not leaves:
        return hashlib.sha256(b"").digest()
    if len(leaves) == 1:
        return leaves[0]
    split = 1
    while split * 2 < len(leaves):
        split *= 2
    return _node_hash(_merkle_root(leaves[:split]), _merkle_root(leaves[split:]))


def _workpaper_set_subject_hashes(workpaper_hashes):
    leaves = [_leaf_hash(bytes.fromhex(value)) for value in sorted(workpaper_hashes)]
    sha256_root_hex = _merkle_root(leaves).hex()
    sha3_256_hex = hashlib.sha3_256(bytes.fromhex(sha256_root_hex)).hexdigest()
    return {"sha256": sha256_root_hex, "sha3-256": sha3_256_hex}


def verify_archive_attestation_document(document, failures):
    """Structural check ONLY: recomputes the workpaper-set subject hash
    from `current_workpaper_hashes` and confirms at least one chain in
    the attested EvidenceRecord still names that subject as its root --
    the same "did the workpaper set change since archival" question
    actaseal.archive.attestation.verify_archive_attestation answers,
    reimplemented standalone.

    Deliberately NOT a full cryptographic re-verification of the TSA
    token or the STH/inclusion-proof signature -- that requires this
    repo's actaseal.anchor.tsa / actaseal.anchoring machinery (CA
    cert-chain parsing, transparency-log signature checks), which this
    lighter-weight script does not carry. A structural match here means
    "the workpaper set is unchanged from what was attested"; it does
    NOT independently confirm the attestation's own anchors are
    genuine. For a full cryptographic check, use
    actaseal.archive.attestation.verify_archive_attestation (or a
    deployment's own console/API), not this script.
    """
    attestation = document.get("archive_attestation")
    current_workpaper_hashes = document.get("current_workpaper_hashes")
    if not isinstance(attestation, dict):
        failures.append("MALFORMED_INPUT: missing or non-object 'archive_attestation' field")
        return False
    if not isinstance(current_workpaper_hashes, list) or not current_workpaper_hashes:
        failures.append("MALFORMED_INPUT: missing or empty 'current_workpaper_hashes' field")
        return False
    try:
        evidence_record = attestation["evidence_record"]
        chains = evidence_record["chains"]
    except (KeyError, TypeError):
        failures.append("MALFORMED_INPUT: archive_attestation missing evidence_record.chains")
        return False

    current_subject_hashes = _workpaper_set_subject_hashes(current_workpaper_hashes)
    any_root_matches = False
    for chain in chains:
        algorithm = chain.get("hash_algorithm")
        reduced_hashtree = chain.get("reduced_hashtree") or []
        root = reduced_hashtree[-1] if reduced_hashtree else None
        expected = current_subject_hashes.get(algorithm)
        if root is not None and expected is not None and root == expected:
            any_root_matches = True

    if not any_root_matches:
        failures.append("WORKPAPER_SET_CHANGED: no attested chain's root matches the current workpaper set")
        return False
    return True


def load_input(source):
    text = source.read_text(encoding="utf-8") if hasattr(source, "read_text") else source.read()
    return json.loads(text)


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

    args = list(argv[1:])
    checkpoint_hash = None
    if "--checkpoint" in args:
        flag_index = args.index("--checkpoint")
        try:
            checkpoint_hash = args[flag_index + 1]
        except IndexError:
            print("FAIL")
            print("  MALFORMED_INPUT: --checkpoint requires a value")
            return 2
        args = args[:flag_index] + args[flag_index + 2 :]

    try:
        if args:
            from pathlib import Path

            document = json.loads(Path(args[0]).read_text(encoding="utf-8"))
        else:
            document = json.loads(sys.stdin.read())
    except (OSError, ValueError) as exc:
        print("FAIL")
        print("  MALFORMED_INPUT: unreadable or invalid JSON: %s" % exc)
        return 2

    if not isinstance(document, dict):
        print("FAIL")
        print("  MALFORMED_INPUT: top-level JSON must be an object")
        return 2

    # ONESHOT-AUDIT Task B: a document carrying "archive_attestation" is
    # a different document shape entirely (no receipt, no signature) --
    # branch out to its own verdict before the receipt-required checks
    # below, which do not apply here.
    if "archive_attestation" in document:
        attestation_failures = []
        if verify_archive_attestation_document(document, attestation_failures):
            print("PASS")
            print("  verdict: ARCHIVE_ATTESTATION_VERIFIED")
            print("  NOTE: structural check only -- workpaper set matches the attested subject. "
                  "Anchor cryptography (TSA/STH) not independently re-verified by this script; "
                  "use actaseal.archive.attestation.verify_archive_attestation for that.")
            return 0
        print("FAIL")
        print("  verdict: ARCHIVE_ATTESTATION_FAILED")
        for failure in attestation_failures:
            print("  " + failure)
        return 1

    receipt = document.get("receipt")
    public_key_hex = document.get("receipt_public_key_hex")
    if not isinstance(receipt, dict):
        print("FAIL")
        print("  MALFORMED_INPUT: missing or non-object 'receipt' field")
        return 2
    # T5: receipt_public_key_hex is required UNLESS a --checkpoint was
    # supplied -- keyless mode may have no key at all to offer.
    have_key = bool(public_key_hex) and isinstance(public_key_hex, str)
    if not have_key and checkpoint_hash is None:
        print("FAIL")
        print("  MALFORMED_INPUT: missing 'receipt_public_key_hex' field")
        return 2

    ledger_slice = document.get("ledger_slice")

    signature_failures = []
    signature_attempted = have_key
    if have_key:
        verify_signature(receipt, public_key_hex, signature_failures, crypto)
    signature_verified = signature_attempted and not signature_failures

    checkpoint_failures = []
    checkpoint_attempted = checkpoint_hash is not None
    if checkpoint_attempted:
        verify_checkpoint_chain(receipt, ledger_slice, checkpoint_hash, checkpoint_failures)
    checkpoint_verified = checkpoint_attempted and not checkpoint_failures

    # Legacy (no --checkpoint) chain check: ledger_slice, if present, is
    # still validated as an unbroken chain containing the receipt's
    # ledger_entry_hash -- unchanged from before T5 -- but only when
    # checkpoint mode isn't already covering that same slice (avoids
    # double-reporting the same chain walk under two different failure
    # lists).
    legacy_chain_failures = []
    if not checkpoint_attempted and ledger_slice is not None:
        verify_chain(receipt, ledger_slice, legacy_chain_failures)

    # A signature-only PASS must still respect the legacy (non-checkpoint)
    # chain check, exactly as before T5 existed: a valid signature over a
    # receipt whose supplied ledger_slice is broken is still a FAIL.
    if signature_verified and legacy_chain_failures:
        signature_verified = False

    material_warnings = []
    material_failures = []
    check_validation_material(document, material_warnings, material_failures)
    if material_failures:
        signature_verified = False
        checkpoint_verified = False

    if signature_verified:
        # Strongest available verdict: a real signature check passed.
        # Reported regardless of whether --checkpoint was also supplied.
        print("PASS")
        print("  verdict: %s" % receipt.get("decision"))
        print("  mode: SIGNATURE_VERIFIED")
        for warning in material_warnings:
            print("  WARNING: " + warning)
        return 0

    if checkpoint_verified:
        # Keyless/hash-linked PASS: chain-of-custody proven against a
        # trusted, out-of-band checkpoint even though the signing key is
        # unknown or rotated (have_key may be False, or the signature
        # check above may have failed). Never reported as
        # SIGNATURE_VERIFIED -- these are deliberately distinct verdicts.
        print("PASS")
        print("  verdict: %s" % receipt.get("decision"))
        print("  mode: CHAIN_VERIFIED_KEY_UNKNOWN")
        for warning in material_warnings:
            print("  WARNING: " + warning)
        return 0

    print("FAIL")
    print("  verdict: %s" % receipt.get("decision"))
    for failure in signature_failures:
        print("  " + failure)
    for failure in checkpoint_failures:
        print("  " + failure)
    for failure in legacy_chain_failures:
        print("  " + failure)
    for failure in material_failures:
        print("  " + failure)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
