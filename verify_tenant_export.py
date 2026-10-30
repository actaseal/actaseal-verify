#!/usr/bin/env python3
"""Check a tenant export archive offline (backlog B12). Imports no ActaSeal
code: it needs only Python 3 and the `cryptography` package, so a tenant that
has left can check what it was given without installing or trusting anything.

    python verify_tenant_export.py <archive.zip> [--public-key HEX]

Without --public-key the archive's own seal key is used, which only shows the
archive is internally consistent; pin the operator's published key to also
show who sealed it. Exit 0 = every check passed.
"""

import hashlib
import json
import sys
import zipfile

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
SCHEMA = "tenant_export.v1"
SEAL_SCHEMA = "tenant_export_seal.v1"


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )


def chash(value):
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def leaf(data):
    return hashlib.sha256(b"\x00" + data).digest()


def node(left, right):
    return hashlib.sha256(b"\x01" + left + right).digest()


def root_from_path(leaf_hash, index, tree_size, path):
    if index < 0 or index >= tree_size:
        raise ValueError("leaf index outside the tree")
    fn, sn, current = index, tree_size - 1, leaf_hash
    for sibling in path:
        if sn == 0:
            raise ValueError("audit path too long")
        if fn % 2 == 1 or fn == sn:
            current = node(sibling, current)
            if fn % 2 == 0:
                while fn % 2 == 0 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            current = node(current, sibling)
        fn >>= 1
        sn >>= 1
    if sn != 0:
        raise ValueError("audit path too short")
    return current


def verify_signature(algorithm, signature_hex, data, public_key_hex):
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        signature = bytes.fromhex(signature_hex)
        key = bytes.fromhex(public_key_hex)
        if algorithm in (None, "ed25519"):
            Ed25519PublicKey.from_public_bytes(key).verify(signature, data)
        elif algorithm == "ecdsa-p256-sha256":
            serialization.load_der_public_key(key).verify(
                signature, data, ec.ECDSA(hashes.SHA256())
            )
        elif algorithm in ("ml-dsa-65", "ml-dsa-87"):
            return _ml_dsa_verify(
                "ML-DSA-65" if algorithm == "ml-dsa-65" else "ML-DSA-87", signature, data, key
            )
        elif algorithm == "hybrid-ed25519-ml-dsa-65":
            # "<ed25519_hex>.<ml_dsa_65_hex>" for the signature and the key, as verify.py reads it.
            ed_sig, pq_sig = signature.decode("ascii").split(".")
            ed_pub, pq_pub = key.decode("ascii").split(".")
            if not all((ed_sig, pq_sig, ed_pub, pq_pub)):
                return False
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(ed_pub)).verify(
                bytes.fromhex(ed_sig), data
            )
            return _ml_dsa_verify("ML-DSA-65", bytes.fromhex(pq_sig), data, bytes.fromhex(pq_pub))
        else:
            return None  # an algorithm this script cannot check: reported, never passed
        return True
    except (InvalidSignature, ValueError, TypeError, UnicodeDecodeError):
        return False


def _ml_dsa_verify(name, signature, data, public_key):
    """True or False with the optional `oqs` package; None (reported, never passed) without it."""
    try:
        import oqs  # noqa: PLC0415 -- optional, only for post-quantum receipts
    except ImportError:
        return None
    if oqs is None:
        return None
    try:
        with oqs.Signature(name) as verifier:
            return bool(verifier.verify(data, signature, public_key))
    except Exception:
        return False


def _scope_failures(manifest, events):
    """A pack built for one action (a receipt share pack) must hold that action's events only."""
    action_id = manifest.get("action_id")
    if action_id is None:
        return []
    return [
        f"EVENT_FROM_ANOTHER_ACTION: event {position}"
        for position, row in enumerate(events)
        if not isinstance(row, dict) or (row.get("event") or {}).get("action_id") != action_id
    ]


def verify_archive(path, pinned_public_key_hex=None):
    """Returns {"verified": bool, "failures": [...], "counts": {...}}."""
    failures = []
    try:
        with zipfile.ZipFile(path) as archive:
            names = set(archive.namelist())
            for required in (
                "manifest.json",
                "seal.json",
                "events.ndjson",
                "receipts.ndjson",
                "keys.json",
            ):
                if required not in names:
                    return {
                        "verified": False,
                        "failures": ["MISSING_FILE: " + required],
                        "counts": {},
                    }
            raw = {
                name: archive.read(name)
                for name in (
                    "manifest.json",
                    "seal.json",
                    "events.ndjson",
                    "receipts.ndjson",
                    "keys.json",
                )
            }
        manifest = json.loads(raw["manifest.json"])
        seal = json.loads(raw["seal.json"])
        events = [
            json.loads(line)
            for line in raw["events.ndjson"].decode("utf-8").splitlines()
            if line.strip()
        ]
        receipts = [
            json.loads(line)
            for line in raw["receipts.ndjson"].decode("utf-8").splitlines()
            if line.strip()
        ]
        keys = json.loads(raw["keys.json"])
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        return {"verified": False, "failures": ["UNREADABLE_ARCHIVE: %s" % exc], "counts": {}}

    payload = seal.get("payload", {})
    if manifest.get("schema_version") != SCHEMA or payload.get("schema") != SEAL_SCHEMA:
        failures.append("SCHEMA_MISMATCH")
    seal_key = seal.get("signer_public_key_hex", "")
    if (
        pinned_public_key_hex is not None
        and pinned_public_key_hex.strip().lower() != seal_key.strip().lower()
    ):
        failures.append("SEAL_KEY_NOT_TRUSTED")
    ok = verify_signature(
        seal.get("signer_algorithm"),
        seal.get("signature_hex", ""),
        canonical(payload).encode("utf-8"),
        seal_key,
    )
    if ok is None:
        failures.append("SEAL_ALGORITHM_UNSUPPORTED: %r" % seal.get("signer_algorithm"))
    elif not ok:
        failures.append("SEAL_SIGNATURE_INVALID")

    for name in ("events.ndjson", "receipts.ndjson", "keys.json"):
        if hashlib.sha256(raw[name]).hexdigest() != payload.get(name.replace(".", "_") + "_sha256"):
            failures.append("FILE_DIGEST_MISMATCH: " + name)
    if hashlib.sha256(canonical(manifest).encode("utf-8")).hexdigest() != payload.get(
        "manifest_sha256"
    ):
        failures.append("MANIFEST_DIGEST_MISMATCH")

    tenant, tree_size, root = (
        manifest.get("tenant_id"),
        payload.get("tree_size"),
        payload.get("root"),
    )
    if (
        payload.get("tenant_id") != tenant
        or payload.get("event_count") != len(events)
        or payload.get("action_id") != manifest.get("action_id")
    ):
        failures.append("SEAL_MANIFEST_MISMATCH")
    failures.extend(_scope_failures(manifest, events))

    event_hashes = set()
    for position, row in enumerate(events):
        try:
            event, index, path = (
                row["event"],
                row["leaf_index"],
                [bytes.fromhex(h) for h in row["audit_path"]],
            )
            material = {field: event[field] for field in EVENT_MATERIAL_FIELDS}
            if chash(event["payload"]) != event["payload_hash"]:
                failures.append("PAYLOAD_HASH_MISMATCH: event %d" % position)
            if chash(dict(material, event_id_basis=EVENT_ID_BASIS)) != event["event_id"]:
                failures.append("EVENT_ID_MISMATCH: event %d" % position)
            if chash(dict(material, event_id=event["event_id"])) != event["event_hash"]:
                failures.append("EVENT_HASH_MISMATCH: event %d" % position)
            if event["tenant_id"] != tenant:
                failures.append("EVENT_FROM_ANOTHER_TENANT: event %d" % position)
            if (
                root_from_path(
                    leaf(event["event_hash"].encode("utf-8")), index, tree_size, path
                ).hex()
                != root
            ):
                failures.append("NOT_IN_SEALED_LEDGER: event %d" % position)
            event_hashes.add(event["event_hash"])
        except (KeyError, ValueError, TypeError) as exc:
            failures.append("MALFORMED_EVENT: event %d: %s" % (position, exc))

    for position, receipt in enumerate(receipts):
        unsigned = {k: v for k, v in receipt.items() if k not in ("signature", "tsa_anchor")}
        key = keys.get(receipt.get("key_id") or "")
        if key is None:
            failures.append("RECEIPT_KEY_UNKNOWN: receipt %d" % position)
            continue
        ok = verify_signature(
            receipt.get("algorithm"),
            receipt.get("signature", ""),
            canonical(unsigned).encode("utf-8"),
            key["public_key_hex"],
        )
        if ok is None:
            failures.append(
                "RECEIPT_ALGORITHM_UNSUPPORTED: receipt %d (%r)"
                % (position, receipt.get("algorithm"))
            )
        elif not ok:
            failures.append("RECEIPT_SIGNATURE_INVALID: receipt %d" % position)
        if receipt.get("ledger_entry_hash") not in event_hashes:
            failures.append("RECEIPT_NOT_BOUND_TO_AN_EXPORTED_EVENT: receipt %d" % position)

    return {
        "verified": not failures,
        "failures": failures,
        "counts": {"events": len(events), "receipts": len(receipts), "keys": len(keys)},
    }


def main(argv):
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 2
    pinned = argv[argv.index("--public-key") + 1] if "--public-key" in argv else None
    result = verify_archive(argv[0], pinned)
    print(json.dumps(result, indent=2))
    return 0 if result["verified"] else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
