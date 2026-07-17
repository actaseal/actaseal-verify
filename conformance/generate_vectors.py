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
vectors.sha256 is a content pin (like ../offline_verifier.sha256 pins
the synced verifier): it catches hand-edited vector files that were
never regenerated through this script, it does not claim byte-for-byte
reproducibility across runs (each run mints a fresh Ed25519 key, same
as generate_demo_packet.py itself).
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from generate_demo_packet import build_packet, canonical_dumps  # noqa: E402

VECTORS_DIR = Path(__file__).resolve().parent / "vectors"
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
    manifest, receipt, events, acquisition, custody, authentication = build_packet(anchored=True)
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
    manifest, receipt, events, acquisition, custody, authentication = build_packet(anchored=True)
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
    manifest, receipt, events, acquisition, custody, authentication = build_packet(anchored=True)
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
    manifest, receipt, events, acquisition, custody, authentication = build_packet(anchored=True)
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
    # Two independently-keyed packets (each generate_demo_packet.build_packet()
    # call mints its own fresh Ed25519 key) both verify on their own terms --
    # the property this demonstrates is that verify.py's trust root is the
    # *manifest's own* receipt_public_key_hex, not a single hardcoded key, so
    # rotating the operator's signing key never invalidates packets issued
    # under the old key: each packet keeps carrying (and gets checked
    # against) the key that actually signed it.
    directory = VECTORS_DIR / "rotated_key_still_verifies"
    directory.mkdir(parents=True, exist_ok=True)

    manifest_old, receipt_old, events_old, acq_old, cust_old, auth_old = build_packet(anchored=False)
    manifest_new, receipt_new, events_new, acq_new, cust_new, auth_new = build_packet(anchored=True)
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


def write_pin() -> None:
    entries = []
    for path in sorted(VECTORS_DIR.rglob("*")):
        if path.is_file():
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            entries.append(f"{digest}  {path.relative_to(VECTORS_DIR.parent).as_posix()}")
    PIN_FILE.write_text("\n".join(entries) + "\n", encoding="utf-8")


def main() -> int:
    if VECTORS_DIR.exists():
        import shutil

        shutil.rmtree(VECTORS_DIR)
    build_valid_vector()
    build_tampered_payload_vector()
    build_tampered_chain_vector()
    build_wrong_signature_vector()
    build_rotated_key_still_verifies_vector()
    write_pin()
    print(f"Wrote vectors to {VECTORS_DIR}")
    print(f"Pinned {PIN_FILE}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
