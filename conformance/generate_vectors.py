#!/usr/bin/env python3
"""Regenerates conformance/vectors/ and its integrity pin
(conformance/vectors.sha256).

Every vector is built from generate_demo_packet.build_packet() -- the
same self-contained, dependency-free packet builder the top-level demo
packets come from (no import of any private ActaSeal code, no reuse of
real signing keys). Tampered vectors take a freshly built valid packet
and mutate exactly one field with plain JSON/string edits -- never by
calling into signing code -- so this script proves nothing that
generate_demo_packet.py + verify.py didn't already independently prove;
it only recombines them into the specific bad-input shapes a
third-party implementer's own verifier should also reject.

Run: python conformance/generate_vectors.py
Then review the diff under conformance/vectors/ before committing --
vectors.sha256 is a content pin (like the verifier_sha256 pin inside
every packet): it catches hand-edited vector files that were
never regenerated through this script.

Deterministic: every signing key this script uses is a fixed,
PUBLISHED TEST KEY (see _fixed_ed25519_key below), not a freshly minted
one -- regenerating with no underlying content change now produces
byte-identical output. This matters specifically because this repo is
PUBLIC and this exact corpus is what third-party implementers pin: a
fresh random key on every run used to churn every single vector file on
every regeneration (confirmed directly -- 593c2e0 touched 23+ files, two
lines each, purely because the embedded verifier's own self-digest
changed), which made a genuinely hand-edited vector and a routine,
no-op regeneration produce IDENTICAL-LOOKING diffs, defeating the "review
the diff before committing" review this docstring itself asks for, and
meant every regeneration was a false breakage for whoever pins this
corpus. generate_demo_packet.build_packet() keeps its own default
behavior unchanged (a fresh random key on every call, unless this script
passes signing_key= explicitly) -- see that function's own docstring.

One known, real exception, checked rather than assumed: none. This
corpus contains no PQ/ML-DSA signing at all (grepped: neither
generate_demo_packet.py nor this file import liboqs/oqs or reference
ML-DSA) and no ECDSA either (Ed25519 only, throughout) -- so there is no
hedged-signature caveat to document here.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from generate_demo_packet import build_packet, canonical_dumps  # noqa: E402

VECTORS_DIR = Path(__file__).resolve().parent / "vectors"


def _fixed_ed25519_key(label: str) -> Ed25519PrivateKey:
    """PUBLISHED TEST KEY -- NOT A REAL CREDENTIAL, NOT A SECRET.
    Deterministically derives an Ed25519 private key from a fixed,
    hardcoded, PUBLIC label string below. Anyone can recompute this
    exact key from the label alone by reading this function -- there is
    nothing to protect and nothing resembling real key material. Used
    only to make this PUBLIC conformance corpus reproducible across
    regenerations (see this module's own docstring); never reuse this
    key, or this derivation scheme, for anything that needs to be
    trusted or kept secret, in this repo or any other."""
    seed = hashlib.sha256(("actaseal-verify-conformance-PUBLISHED-TEST-KEY:" + label).encode("utf-8")).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)
PIN_FILE = Path(__file__).resolve().parent / "vectors.sha256"

PACKET_FILES = (
    "manifest.json",
    "receipt.json",
    "acquisition.json",
    "custody.json",
    "authentication.json",
    "ledger_slice.ndjson",
)


def _write_packet(directory: Path, manifest, receipt, events, acquisition, custody, authentication) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "manifest.json").write_text(canonical_dumps(manifest), encoding="utf-8")
    (directory / "receipt.json").write_text(canonical_dumps(receipt), encoding="utf-8")
    (directory / "acquisition.json").write_text(canonical_dumps(acquisition), encoding="utf-8")
    (directory / "custody.json").write_text(canonical_dumps(custody), encoding="utf-8")
    (directory / "authentication.json").write_text(canonical_dumps(authentication), encoding="utf-8")
    (directory / "ledger_slice.ndjson").write_text(
        "\n".join(canonical_dumps(event) for event in events) + "\n", encoding="utf-8"
    )


def _write_expected(directory: Path, *, verified: bool, must_include: list[str], proves: str) -> None:
    (directory / "expected.json").write_text(
        json.dumps(
            {
                "verified": verified,
                "exit_code": 0 if verified else 1,
                "must_include_failure_substrings": must_include,
                "proves": proves,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def _load_events(directory: Path) -> list[dict]:
    lines = (directory / "ledger_slice.ndjson").read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines if line.strip()]


def _write_events(directory: Path, events: list[dict]) -> None:
    (directory / "ledger_slice.ndjson").write_text(
        "\n".join(canonical_dumps(event) for event in events) + "\n", encoding="utf-8"
    )


def build_valid_vector() -> None:
    manifest, receipt, events, acquisition, custody, authentication = build_packet(
        anchored=True, signing_key=_fixed_ed25519_key("valid")
    )
    directory = VECTORS_DIR / "valid"
    _write_packet(directory, manifest, receipt, events, acquisition, custody, authentication)
    _write_expected(
        directory,
        verified=True,
        must_include=[],
        proves="A well-formed packet, produced with no tampering, verifies cleanly end to end "
        "(hash chain, receipt signature, authentication docs, scope conformance, settlement anchor).",
    )


def build_tampered_payload_vector() -> None:
    manifest, receipt, events, acquisition, custody, authentication = build_packet(
        anchored=True, signing_key=_fixed_ed25519_key("tampered_payload")
    )
    directory = VECTORS_DIR / "tampered_payload"
    _write_packet(directory, manifest, receipt, events, acquisition, custody, authentication)

    events = _load_events(directory)
    # Mutate one event's payload in place without recomputing payload_hash
    # / event_id / event_hash -- exactly what an attacker editing a stored
    # ledger record (not re-deriving it) would produce.
    events[1]["payload"] = dict(events[1]["payload"], tampered="true")
    _write_events(directory, events)
    _write_expected(
        directory,
        verified=False,
        must_include=["PAYLOAD_HASH_MISMATCH", "EVENT_ID_MISMATCH", "EVENT_HASH_MISMATCH"],
        proves="A ledger event whose payload was edited after the fact fails payload_hash "
        "recomputation, which cascades into event_id and event_hash for that event.",
    )


def build_tampered_chain_vector() -> None:
    manifest, receipt, events, acquisition, custody, authentication = build_packet(
        anchored=True, signing_key=_fixed_ed25519_key("tampered_chain")
    )
    directory = VECTORS_DIR / "tampered_chain"
    _write_packet(directory, manifest, receipt, events, acquisition, custody, authentication)

    events = _load_events(directory)
    # Rewrite the middle event's previous_event_hash to point somewhere
    # else -- payload/event_hash of every event stays internally
    # self-consistent; only the link between events is severed.
    events[1]["previous_event_hash"] = "0" * 64
    _write_events(directory, events)
    _write_expected(
        directory,
        verified=False,
        must_include=["CHAIN_BROKEN"],
        proves="A ledger slice where one event's previous_event_hash no longer matches the "
        "prior event's event_hash fails chain-continuity verification, even though every "
        "individual event is internally self-consistent.",
    )


def build_wrong_signature_vector() -> None:
    manifest, receipt, events, acquisition, custody, authentication = build_packet(
        anchored=True, signing_key=_fixed_ed25519_key("wrong_signature")
    )
    directory = VECTORS_DIR / "wrong_signature"
    _write_packet(directory, manifest, receipt, events, acquisition, custody, authentication)

    receipt_path = directory / "receipt.json"
    receipt_on_disk = json.loads(receipt_path.read_text(encoding="utf-8"))
    good_sig = receipt_on_disk["signature"]
    # Flip one hex nibble -- still valid hex, still the right length, just
    # not a signature that verifies against this manifest's public key.
    flipped_char = "0" if good_sig[0] != "0" else "1"
    receipt_on_disk["signature"] = flipped_char + good_sig[1:]
    receipt_path.write_text(canonical_dumps(receipt_on_disk), encoding="utf-8")
    _write_expected(
        directory,
        verified=False,
        must_include=["RECEIPT_SIGNATURE_INVALID"],
        proves="A receipt whose signature bytes were altered fails Ed25519 verification against "
        "the manifest's pinned public key, even though every other field is untouched.",
    )


def build_rotated_key_still_verifies_vector() -> None:
    # Two independently-keyed packets (two distinct fixed test keys, see
    # _fixed_ed25519_key) both verify on their own terms -- the property
    # this demonstrates is that verify.py's trust root is the
    # *manifest's own* receipt_public_key_hex, not a single hardcoded key, so
    # rotating the operator's signing key never invalidates packets issued
    # under the old key: each packet keeps carrying (and gets checked
    # against) the key that actually signed it.
    directory = VECTORS_DIR / "rotated_key_still_verifies"
    directory.mkdir(parents=True, exist_ok=True)

    manifest_old, receipt_old, events_old, acq_old, cust_old, auth_old = build_packet(
        anchored=False, signing_key=_fixed_ed25519_key("rotated_key_still_verifies:before")
    )
    manifest_new, receipt_new, events_new, acq_new, cust_new, auth_new = build_packet(
        anchored=True, signing_key=_fixed_ed25519_key("rotated_key_still_verifies:after")
    )
    assert manifest_old["receipt_public_key_hex"] != manifest_new["receipt_public_key_hex"], (
        "expected two independently generated packets to carry different signing keys"
    )

    old_dir = directory / "issued_before_rotation"
    new_dir = directory / "issued_after_rotation"
    _write_packet(old_dir, manifest_old, receipt_old, events_old, acq_old, cust_old, auth_old)
    _write_packet(new_dir, manifest_new, receipt_new, events_new, acq_new, cust_new, auth_new)

    (directory / "expected.json").write_text(
        json.dumps(
            {
                "issued_before_rotation": {"verified": True, "exit_code": 0},
                "issued_after_rotation": {"verified": True, "exit_code": 0},
                "proves": "Each packet's manifest.json pins the public key that actually signed "
                "its receipt. Verifying issued_before_rotation/ and issued_after_rotation/ -- "
                "signed under two different keys -- both succeed, because verify.py's trust "
                "root is per-packet, not a single hardcoded key: rotating the operator's live "
                "signing key does not retroactively invalidate receipts issued under the key "
                "that was live when they were signed.",
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def build_verifier_digest_valid_vector() -> None:
    """manifest.json's
    "verifier_sha256" pin, registered as a real conformance vector --
    the previous pass added the field and the self-check in verify.py
    but never a vector proving a correctly-pinned packet verifies. The
    digest is computed the SAME way verify.py's own
    verifier_body_sha256 does (strips leading '#' lines), over the
    REAL verify.py this conformance suite's subprocess actually runs."""
    from verify import verifier_body_sha256

    manifest, receipt, events, acquisition, custody, authentication = build_packet(
        anchored=True, signing_key=_fixed_ed25519_key("verifier_digest_valid")
    )
    manifest = dict(manifest, verifier_sha256=verifier_body_sha256((REPO_ROOT / "verify.py").read_bytes()))
    directory = VECTORS_DIR / "verifier_digest_valid"
    _write_packet(directory, manifest, receipt, events, acquisition, custody, authentication)
    _write_expected(
        directory,
        verified=True,
        must_include=[],
        proves="A packet whose manifest.json declares the correct verifier_sha256 (the digest "
        "pin) verifies cleanly -- the running verify.py's own body hash matches the pin.",
    )


def build_verifier_digest_tampered_vector() -> None:
    manifest, receipt, events, acquisition, custody, authentication = build_packet(
        anchored=True, signing_key=_fixed_ed25519_key("verifier_digest_tampered")
    )
    # Well-formed 64-char hex, deliberately wrong -- distinct from
    # VERIFIER_DIGEST_MALFORMED (a not-hex-shaped value), which this
    # vector set deliberately does NOT also cover: MALFORMED is a
    # format check covered by the producer's own tests, not duplicated
    # here.
    manifest = dict(manifest, verifier_sha256="0" * 64)
    directory = VECTORS_DIR / "verifier_digest_tampered"
    _write_packet(directory, manifest, receipt, events, acquisition, custody, authentication)
    _write_expected(
        directory,
        verified=False,
        must_include=["VERIFIER_DIGEST_MISMATCH"],
        proves="A packet whose manifest.json declares a verifier_sha256 that does not match the "
        "running verify.py's own body hash fails closed -- catches a swapped-out verify.py "
        "before any of its other checks are trusted.",
    )


def _canonical_receipt_dumps(value):
    return canonical_dumps(value)


def _sign_receipt_fields(private_key, receipt_without_signature):
    data = _canonical_receipt_dumps(receipt_without_signature).encode("utf-8")
    signed = dict(receipt_without_signature)
    signed["signature"] = private_key.sign(data).hex()
    return signed


def _unsigned_checkpoint_receipt():
    return dict(
        decision="ALLOW",
        reason_code="OK",
        action_hash="a" * 64,
        mandate_hash=None,
        evidence_set_hash="b" * 64,
        ledger_entry_hash="c" * 64,
        approval_event_hash=None,
        agent_id="agent-1",
        tool_name="issue_refund",
        args_hash="d" * 64,
        purpose=None,
        key_id=None,
        rail_anchors_hash=None,
        scope_conformance=None,
        timestamp="2026-07-17T00:00:00+00:00",
    )


def _checkpoint_chain(receipt, previous_event_hash="genesis"):
    return [
        {"event_hash": "e1", "previous_event_hash": previous_event_hash},
        {"event_hash": receipt["ledger_entry_hash"], "previous_event_hash": "e1"},
    ]


def _write_receipt_vector(directory: Path, document: dict, *, mode: str, exit_code: int, proves: str,
                           must_include: list[str] | None = None) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "input.json").write_text(_canonical_receipt_dumps(document), encoding="utf-8")
    (directory / "expected.json").write_text(
        json.dumps(
            {
                "exit_code": exit_code,
                "mode": mode,
                "must_include_substrings": must_include or [],
                "proves": proves,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def build_receipt_checkpoint_signature_verified_vector() -> None:
    """verify_receipt.py's T5 checkpoint mode: a key that DOES resolve
    independently of the checkpoint wins outright -- SIGNATURE_VERIFIED,
    the strongest verdict, reported even though --checkpoint was also
    supplied and would independently pass on its own."""
    private_key = _fixed_ed25519_key("receipt_checkpoint:signature_verified")
    public_key_hex = private_key.public_key().public_bytes_raw().hex()
    receipt = _sign_receipt_fields(private_key, _unsigned_checkpoint_receipt())
    document = {
        "receipt": receipt,
        "receipt_public_key_hex": public_key_hex,
        "ledger_slice": _checkpoint_chain(receipt),
    }
    directory = VECTORS_DIR / "receipt_checkpoint" / "signature_verified"
    _write_receipt_vector(
        directory,
        document,
        mode="SIGNATURE_VERIFIED",
        exit_code=0,
        proves="A receipt whose signing key resolves and independently verifies passes as "
        "SIGNATURE_VERIFIED -- the strongest verdict -- even when a --checkpoint hash that "
        "would also independently pass is supplied alongside it.",
    )


def build_receipt_checkpoint_key_unknown_vector() -> None:
    """The signing key is NOT independently resolvable (a different,
    unrelated key is presented, simulating rotation) but the ledger
    slice forms an unbroken chain containing both the receipt's
    ledger_entry_hash and the supplied --checkpoint hash -- PASSes on
    hash-linkage alone, reported as the distinct CHAIN_VERIFIED_KEY_UNKNOWN
    verdict, never as SIGNATURE_VERIFIED."""
    signing_key = _fixed_ed25519_key("receipt_checkpoint:key_unknown:signing")
    receipt = _sign_receipt_fields(signing_key, _unsigned_checkpoint_receipt())

    unrelated_key = _fixed_ed25519_key("receipt_checkpoint:key_unknown:unrelated")
    unrelated_public_key_hex = unrelated_key.public_key().public_bytes_raw().hex()
    document = {
        "receipt": receipt,
        "receipt_public_key_hex": unrelated_public_key_hex,
        "ledger_slice": _checkpoint_chain(receipt),
    }
    directory = VECTORS_DIR / "receipt_checkpoint" / "key_unknown"
    _write_receipt_vector(
        directory,
        document,
        mode="CHAIN_VERIFIED_KEY_UNKNOWN",
        exit_code=0,
        proves="A receipt presented with an unresolvable/rotated-away signing key still PASSes "
        "when its ledger_entry_hash is bound into an unbroken chain that also contains the "
        "out-of-band --checkpoint hash -- reported as CHAIN_VERIFIED_KEY_UNKNOWN, a third "
        "verdict distinct from SIGNATURE_VERIFIED and never conflated with it.",
    )


def build_receipt_checkpoint_tampered_vector() -> None:
    """Tampering the chain (breaking previous_event_hash) defeats BOTH
    the legacy chain check and checkpoint mode -- neither PASS verdict
    is reachable, the generic FAIL applies, distinct from both PASS
    modes."""
    signing_key = _fixed_ed25519_key("receipt_checkpoint:tampered:signing")
    receipt = _sign_receipt_fields(signing_key, _unsigned_checkpoint_receipt())

    unrelated_key = _fixed_ed25519_key("receipt_checkpoint:tampered:unrelated")
    unrelated_public_key_hex = unrelated_key.public_key().public_bytes_raw().hex()
    tampered_chain = _checkpoint_chain(receipt)
    tampered_chain[1]["previous_event_hash"] = "not-e1"
    document = {
        "receipt": receipt,
        "receipt_public_key_hex": unrelated_public_key_hex,
        "ledger_slice": tampered_chain,
    }
    directory = VECTORS_DIR / "receipt_checkpoint" / "tampered"
    _write_receipt_vector(
        directory,
        document,
        mode="FAIL",
        exit_code=1,
        must_include=["CHAIN_BROKEN"],
        proves="A tampered ledger slice (broken previous_event_hash link) combined with an "
        "unresolvable signing key fails outright -- neither SIGNATURE_VERIFIED nor "
        "CHAIN_VERIFIED_KEY_UNKNOWN is reachable.",
    )


def write_pin() -> None:
    entries = []
    for path in sorted(VECTORS_DIR.rglob("*")):
        if path.is_file():
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            entries.append(f"{digest}  {path.relative_to(VECTORS_DIR.parent).as_posix()}")
    PIN_FILE.write_text("\n".join(entries) + "\n", encoding="utf-8")


DISPUTE_PACKET_VECTOR_NAMES = (
    "valid",
    "tampered_payload",
    "tampered_chain",
    "wrong_signature",
    "rotated_key_still_verifies",
    "verifier_digest_valid",
    "verifier_digest_tampered",
)


def main() -> int:
    # Only remove the dispute-packet vectors THIS script actually
    # regenerates (DISPUTE_PACKET_VECTOR_NAMES) -- a bare
    # shutil.rmtree(VECTORS_DIR) here would also delete
    # archive_attestation_v1/ (the separate RFC 3161 / SCITT-receipt
    # vector set test_archive_attestation_conformance.py owns) and
    # file_seal_v1/ (seals written by ActaSeal itself, which
    # tests/test_verify_seal_v1.py owns), which this script has no logic
    # to rebuild. Both are still pinned by write_pin().
    if VECTORS_DIR.exists():
        import shutil

        for name in DISPUTE_PACKET_VECTOR_NAMES:
            child = VECTORS_DIR / name
            if child.exists():
                shutil.rmtree(child)
        receipt_checkpoint_dir = VECTORS_DIR / "receipt_checkpoint"
        if receipt_checkpoint_dir.exists():
            shutil.rmtree(receipt_checkpoint_dir)
    build_valid_vector()
    build_tampered_payload_vector()
    build_tampered_chain_vector()
    build_wrong_signature_vector()
    build_rotated_key_still_verifies_vector()
    build_verifier_digest_valid_vector()
    build_verifier_digest_tampered_vector()
    build_receipt_checkpoint_signature_verified_vector()
    build_receipt_checkpoint_key_unknown_vector()
    build_receipt_checkpoint_tampered_vector()
    write_pin()
    print(f"Wrote vectors to {VECTORS_DIR}")
    print(f"Pinned {PIN_FILE}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
