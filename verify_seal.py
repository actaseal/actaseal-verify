#!/usr/bin/env python3
"""verify_seal.py -- verify an ActaSeal file seal yourself, offline.

A file seal (format actaseal.file-seal.v1, written by `actaseal seal`) covers a
set of files -- logs, an evidence pack, an audit submission. This script checks,
without ActaSeal and without a network call:

  * every sealed file is byte-for-byte unchanged (SHA-256);
  * the seal document itself was not edited (its canonical-JSON hash);
  * the Ed25519 signature, and that it is by the key you expect (--public-key);
  * the chain: the seal links to the previous day's seal (--previous);
  * the RFC 3161 timestamp over the seal hash, against a TSA CA you trust.

Usage:
  python verify_seal.py SEAL.json --base DIR [--previous PREV.json]
                        [--public-key HEX] [--tsa-ca PEM ...]
                        [--require-timestamp | --skip-timestamp] [--json]

Exit codes: 0 verified, 1 a check failed, 2 could not run (unreadable input,
missing dependency).

Dependencies: `cryptography`; plus `asn1crypto` to check the RFC 3161 timestamp
(pip install asn1crypto, or pass --skip-timestamp). The timestamp check is
verify.py's verify_rfc3161_token.

Trust: without --public-key a valid signature only shows the seal is
self-consistent (anyone can re-seal changed files with their own key). The TSA
certificate must chain to a CA you pass with --tsa-ca, or to freeTSA's root
(embedded below, SHA-256 pinned) for seals timestamped by freeTSA -- never to a
CA path recorded inside the seal. Only the files a seal lists are checked.

Must give the same results as ActaSeal's own verifier (actaseal.file_seal);
conformance/vectors/file_seal_v1 holds seals ActaSeal wrote and the results it
reported, and tests/test_verify_seal_v1.py compares against them.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, List, Optional

SEAL_FORMAT = "actaseal.file-seal.v1"
SIGNATURE_DOMAIN = b"actaseal.file-seal.v1\x00"
BODY_FIELDS = ("format", "created_at", "label", "files", "previous_seal_sha256")

FREETSA_CA_SHA256 = "2151b61137ffa86bf664691ba67e7da0b19f98c758e3d228d5d8ebf27e044438"
FREETSA_CA_PEM = (
    b"-----BEGIN CERTIFICATE-----\n"
    b"MIIH/zCCBeegAwIBAgIJAMHphhYNqOmAMA0GCSqGSIb3DQEBDQUAMIGVMREwDwYD\n"
    b"VQQKEwhGcmVlIFRTQTEQMA4GA1UECxMHUm9vdCBDQTEYMBYGA1UEAxMPd3d3LmZy\n"
    b"ZWV0c2Eub3JnMSIwIAYJKoZIhvcNAQkBFhNidXNpbGV6YXNAZ21haWwuY29tMRIw\n"
    b"EAYDVQQHEwlXdWVyemJ1cmcxDzANBgNVBAgTBkJheWVybjELMAkGA1UEBhMCREUw\n"
    b"HhcNMTYwMzEzMDE1MjEzWhcNNDEwMzA3MDE1MjEzWjCBlTERMA8GA1UEChMIRnJl\n"
    b"ZSBUU0ExEDAOBgNVBAsTB1Jvb3QgQ0ExGDAWBgNVBAMTD3d3dy5mcmVldHNhLm9y\n"
    b"ZzEiMCAGCSqGSIb3DQEJARYTYnVzaWxlemFzQGdtYWlsLmNvbTESMBAGA1UEBxMJ\n"
    b"V3VlcnpidXJnMQ8wDQYDVQQIEwZCYXllcm4xCzAJBgNVBAYTAkRFMIICIjANBgkq\n"
    b"hkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtgKODjAy8REQ2WTNqUudAnjhlCrpE6ql\n"
    b"mQfNppeTmVvZrH4zutn+NwTaHAGpjSGv4/WRpZ1wZ3BRZ5mPUBZyLgq0YrIfQ5Fx\n"
    b"0s/MRZPzc1r3lKWrMR9sAQx4mN4z11xFEO529L0dFJjPF9MD8Gpd2feWzGyptlel\n"
    b"b+PqT+++fOa2oY0+NaMM7l/xcNHPOaMz0/2olk0i22hbKeVhvokPCqhFhzsuhKsm\n"
    b"q4Of/o+t6dI7sx5h0nPMm4gGSRhfq+z6BTRgCrqQG2FOLoVFgt6iIm/BnNffUr7V\n"
    b"DYd3zZmIwFOj/H3DKHoGik/xK3E82YA2ZulVOFRW/zj4ApjPa5OFbpIkd0pmzxzd\n"
    b"EcL479hSA9dFiyVmSxPtY5ze1P+BE9bMU1PScpRzw8MHFXxyKqW13Qv7LWw4sbk3\n"
    b"SciB7GACbQiVGzgkvXG6y85HOuvWNvC5GLSiyP9GlPB0V68tbxz4JVTRdw/Xn/XT\n"
    b"FNzRBM3cq8lBOAVt/PAX5+uFcv1S9wFE8YjaBfWCP1jdBil+c4e+0tdywT2oJmYB\n"
    b"BF/kEt1wmGwMmHunNEuQNzh1FtJY54hbUfiWi38mASE7xMtMhfj/C4SvapiDN837\n"
    b"gYaPfs8x3KZxbX7C3YAsFnJinlwAUss1fdKar8Q/YVs7H/nU4c4Ixxxz4f67fcVq\n"
    b"M2ITKentbCMCAwEAAaOCAk4wggJKMAwGA1UdEwQFMAMBAf8wDgYDVR0PAQH/BAQD\n"
    b"AgHGMB0GA1UdDgQWBBT6VQ2MNGZRQ0z357OnbJWveuaklzCBygYDVR0jBIHCMIG/\n"
    b"gBT6VQ2MNGZRQ0z357OnbJWveuakl6GBm6SBmDCBlTERMA8GA1UEChMIRnJlZSBU\n"
    b"U0ExEDAOBgNVBAsTB1Jvb3QgQ0ExGDAWBgNVBAMTD3d3dy5mcmVldHNhLm9yZzEi\n"
    b"MCAGCSqGSIb3DQEJARYTYnVzaWxlemFzQGdtYWlsLmNvbTESMBAGA1UEBxMJV3Vl\n"
    b"cnpidXJnMQ8wDQYDVQQIEwZCYXllcm4xCzAJBgNVBAYTAkRFggkAwemGFg2o6YAw\n"
    b"MwYDVR0fBCwwKjAooCagJIYiaHR0cDovL3d3dy5mcmVldHNhLm9yZy9yb290X2Nh\n"
    b"LmNybDCBzwYDVR0gBIHHMIHEMIHBBgorBgEEAYHyJAEBMIGyMDMGCCsGAQUFBwIB\n"
    b"FidodHRwOi8vd3d3LmZyZWV0c2Eub3JnL2ZyZWV0c2FfY3BzLmh0bWwwMgYIKwYB\n"
    b"BQUHAgEWJmh0dHA6Ly93d3cuZnJlZXRzYS5vcmcvZnJlZXRzYV9jcHMucGRmMEcG\n"
    b"CCsGAQUFBwICMDsaOUZyZWVUU0EgdHJ1c3RlZCB0aW1lc3RhbXBpbmcgU29mdHdh\n"
    b"cmUgYXMgYSBTZXJ2aWNlIChTYWFTKTA3BggrBgEFBQcBAQQrMCkwJwYIKwYBBQUH\n"
    b"MAGGG2h0dHA6Ly93d3cuZnJlZXRzYS5vcmc6MjU2MDANBgkqhkiG9w0BAQ0FAAOC\n"
    b"AgEAaK9+v5OFYu9M6ztYC+L69sw1omdyli89lZAfpWMMh9CRmJhM6KBqM/ipwoLt\n"
    b"nxyxGsbCPhcQjuTvzm+ylN6VwTMmIlVyVSLKYZcdSjt/eCUN+41K7sD7GVmxZBAF\n"
    b"ILnBDmTGJmLkrU0KuuIpj8lI/E6Z6NnmuP2+RAQSHsfBQi6sssnXMo4HOW5gtPO7\n"
    b"gDrUpVXID++1P4XndkoKn7Svw5n0zS9fv1hxBcYIHPPQUze2u30bAQt0n0iIyRLz\n"
    b"aWuhtpAtd7ffwEbASgzB7E+NGF4tpV37e8KiA2xiGSRqT5ndu28fgpOY87gD3ArZ\n"
    b"DctZvvTCfHdAS5kEO3gnGGeZEVLDmfEsv8TGJa3AljVa5E40IQDsUXpQLi8G+UC4\n"
    b"1DWZu8EVT4rnYaCw1VX7ShOR1PNCCvjb8S8tfdudd9zhU3gEB0rxdeTy1tVbNLXW\n"
    b"99y90xcwr1ZIDUwM/xQ/noO8FRhm0LoPC73Ef+J4ZBdrvWwauF3zJe33d4ibxEcb\n"
    b"8/pz5WzFkeixYM2nsHhqHsBKw7JPouKNXRnl5IAE1eFmqDyC7G/VT7OF669xM6hb\n"
    b"Ut5G21JE4cNK6NNucS+fzg1JPX0+3VhsYZjj7D5uljRvQXrJ8iHgr/M6j2oLHvTA\n"
    b"I2MLdq2qjZFDOCXsxBxJpbmLGBx9ow6ZerlUxzws2AWv2pk=\n"
    b"-----END CERTIFICATE-----\n"
)


class MissingDependency(Exception):
    pass


def seal_hash(seal: dict) -> str:
    """SHA-256 over the canonical JSON of the seal body: keys sorted, no
    whitespace, UTF-8 (not ASCII-escaped)."""
    body = {k: seal.get(k) for k in BODY_FIELDS}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _hash_file(path: str):
    h = hashlib.sha256()
    size = 0
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
            size += len(chunk)
    return h.hexdigest(), size


@dataclass
class SealVerification:
    ok: bool
    failures: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    files_checked: int = 0
    seal_sha256: Optional[str] = None
    timestamp_status: str = "UNTIMESTAMPED"
    timestamped_at: Optional[str] = None
    signed_by: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "status": "PASS" if self.ok else "FAIL",
            "seal_sha256": self.seal_sha256,
            "files_checked": self.files_checked,
            "failures": self.failures,
            "warnings": self.warnings,
            "timestamp_status": self.timestamp_status,
            "timestamped_at": self.timestamped_at,
            "signed_by": self.signed_by,
        }


def _safe_rel(path: Any) -> bool:
    if not isinstance(path, str) or not path or "\\" in path or "\x00" in path:
        return False
    p = PurePosixPath(path)
    return not p.is_absolute() and ".." not in p.parts and ":" not in p.parts[0]


def _well_formed_entry(entry: Any) -> bool:
    return (isinstance(entry, dict) and isinstance(entry.get("sha256"), str) and len(entry["sha256"]) == 64
            and isinstance(entry.get("size"), int) and not isinstance(entry.get("size"), bool))


def _previous_hash(previous: Any) -> Optional[str]:
    if not isinstance(previous, dict) or previous.get("format") != SEAL_FORMAT:
        return None
    digest = seal_hash(previous)
    return digest if digest == previous.get("seal_sha256") else None


def _gen_time(token_der_hex: str) -> Optional[str]:
    from asn1crypto import cms, tsp  # noqa: F401 -- tsp registers the TSTInfo content type

    try:
        ci = cms.ContentInfo.load(bytes.fromhex(token_der_hex))
        return ci["content"]["encap_content_info"]["content"].parsed["gen_time"].native.isoformat()
    except Exception:  # noqa: BLE001 -- informative only; the token was already verified
        return None


def _check_timestamp(result: SealVerification, anchor: dict, digest_hex: str, ca_paths: List[str]) -> None:
    try:
        import asn1crypto  # noqa: F401
    except ImportError as exc:
        raise MissingDependency(
            "the seal has an RFC 3161 timestamp; checking it needs asn1crypto "
            "(pip install asn1crypto), or pass --skip-timestamp") from exc
    from verify import verify_rfc3161_token

    tmp = None
    if not ca_paths:
        if anchor.get("tsa_name") != "freetsa" or hashlib.sha256(FREETSA_CA_PEM).hexdigest() != FREETSA_CA_SHA256:
            result.timestamp_status = "INVALID"
            result.failures.append("TSA_CA_UNKNOWN")
            return
        tmp = tempfile.NamedTemporaryFile("wb", suffix=".pem", delete=False)
        tmp.write(FREETSA_CA_PEM)
        tmp.close()
        ca_paths = [tmp.name]
    try:
        token = anchor.get("token_der_hex")
        if not isinstance(token, str):
            ok, reasons = False, ["tsa_anchor has no token_der_hex"]
        else:
            ok, reasons = verify_rfc3161_token(token, digest_hex, ca_paths)
    finally:
        if tmp is not None:
            os.unlink(tmp.name)
    if ok:
        result.timestamp_status = "OK"
        result.timestamped_at = _gen_time(token)
    else:
        result.timestamp_status = "INVALID"
        result.failures.append("TSA_INVALID: " + "; ".join(reasons))


def verify_seal(seal: Any, *, base, previous: Optional[dict] = None,
                expected_public_key_hex: Optional[str] = None, tsa_ca_paths: Optional[List[str]] = None,
                require_timestamp: bool = False, skip_timestamp: bool = False) -> SealVerification:
    if require_timestamp and skip_timestamp:
        raise ValueError("require_timestamp and skip_timestamp contradict each other")
    if not isinstance(seal, dict) or seal.get("format") != SEAL_FORMAT:
        return SealVerification(ok=False, failures=["SEAL_FORMAT_UNKNOWN"])
    if not isinstance(seal.get("files"), list):
        return SealVerification(ok=False, failures=["SEAL_MALFORMED: files is not a list"])

    result = SealVerification(ok=False)
    digest_hex = seal_hash(seal)
    result.seal_sha256 = digest_hex
    if digest_hex != seal.get("seal_sha256"):
        result.failures.append("SEAL_HASH_MISMATCH")

    # files
    base_abs = os.path.abspath(os.fspath(base))
    for entry in seal["files"]:
        path = entry.get("path") if isinstance(entry, dict) else None
        if not _safe_rel(path):
            result.failures.append("SEAL_PATH_INVALID: %r" % (path,))
            continue
        if not _well_formed_entry(entry):
            result.failures.append("SEAL_MALFORMED: %s" % path)
            continue
        abs_path = os.path.join(base_abs, *PurePosixPath(path).parts)
        if not os.path.isfile(abs_path) or os.path.islink(abs_path):
            result.failures.append("FILE_MISSING: %s" % path)
            continue
        digest, size = _hash_file(abs_path)
        result.files_checked += 1
        if digest != entry["sha256"] or size != entry["size"]:
            result.failures.append("FILE_CHANGED: %s" % path)

    # chain
    if previous is not None:
        prev_hash = _previous_hash(previous)
        if prev_hash is None:
            result.failures.append("PREVIOUS_SEAL_INVALID")
        elif seal.get("previous_seal_sha256") != prev_hash:
            result.failures.append("CHAIN_BROKEN")
    elif seal.get("previous_seal_sha256"):
        result.warnings.append("CHAIN_NOT_CHECKED")

    # signature
    sig = seal.get("signature")
    if isinstance(sig, dict):
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        pub_hex = str(sig.get("public_key_hex") or "")
        try:
            if sig.get("algorithm") != "ed25519":
                raise ValueError("unsupported algorithm")
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex)).verify(
                bytes.fromhex(str(sig.get("signature_hex") or "")), SIGNATURE_DOMAIN + bytes.fromhex(digest_hex))
            result.signed_by = pub_hex
        except (InvalidSignature, ValueError):
            result.failures.append("SIGNATURE_INVALID")
        if expected_public_key_hex is not None and pub_hex.lower() != expected_public_key_hex.lower():
            result.failures.append("SIGNER_MISMATCH")
        elif expected_public_key_hex is None:
            result.warnings.append("SIGNER_NOT_PINNED")
    elif sig is not None:
        result.failures.append("SIGNATURE_INVALID")
    elif expected_public_key_hex is not None:
        result.failures.append("SIGNATURE_MISSING")

    # timestamp
    anchor = seal.get("tsa_anchor")
    if isinstance(anchor, dict):
        if skip_timestamp:
            result.timestamp_status = "NOT_CHECKED"
            result.warnings.append("TIMESTAMP_NOT_CHECKED")
        else:
            _check_timestamp(result, anchor, digest_hex, list(tsa_ca_paths or []))
    elif anchor is not None:
        result.timestamp_status = "INVALID"
        result.failures.append("TSA_INVALID: tsa_anchor is not an object")
    elif require_timestamp:
        result.failures.append("TIMESTAMP_MISSING")
    else:
        result.warnings.append("UNTIMESTAMPED")

    result.ok = not result.failures
    return result


def _read_json(path: str, what: str) -> dict:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise SystemExit("cannot read %s %s: %s" % (what, path, exc))
    if not isinstance(value, dict):
        raise SystemExit("cannot read %s %s: not a JSON object" % (what, path))
    return value


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Verify an ActaSeal file seal offline.")
    ap.add_argument("seal", help="seal JSON written by `actaseal seal`")
    ap.add_argument("--base", default=".", help="directory the sealed paths are relative to (default: .)")
    ap.add_argument("--previous", help="the previous seal, to check the chain link")
    ap.add_argument("--public-key", help="hex Ed25519 public key the seal must be signed by")
    ap.add_argument("--tsa-ca", action="append", default=[], help="PEM CA certificate to trust for the timestamp (repeatable)")
    group = ap.add_mutually_exclusive_group()
    group.add_argument("--require-timestamp", action="store_true", help="fail when the seal has no timestamp")
    group.add_argument("--skip-timestamp", action="store_true", help="do not check the timestamp (no asn1crypto)")
    ap.add_argument("--json", action="store_true", help="print the result as JSON")
    args = ap.parse_args(argv)

    try:
        import cryptography  # noqa: F401
    except ImportError:
        print("verify_seal.py needs the 'cryptography' package: pip install cryptography", file=sys.stderr)
        return 2
    try:
        seal = _read_json(args.seal, "seal")
        previous = _read_json(args.previous, "previous seal") if args.previous else None
        result = verify_seal(seal, base=args.base, previous=previous, expected_public_key_hex=args.public_key,
                             tsa_ca_paths=args.tsa_ca, require_timestamp=args.require_timestamp,
                             skip_timestamp=args.skip_timestamp)
    except SystemExit as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except MissingDependency as exc:
        print(str(exc), file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
        return 0 if result.ok else 1
    if result.ok:
        when = (" at %s" % result.timestamped_at) if result.timestamped_at else ""
        print("VERIFIED: %d file(s) unchanged; seal %s" % (result.files_checked, result.seal_sha256))
        print("  timestamp: %s%s" % (result.timestamp_status, when))
        print("  signed by: %s" % (result.signed_by or "not signed"))
    else:
        print("FAILED: %d check(s) failed; seal %s" % (len(result.failures), result.seal_sha256))
        for f in result.failures:
            print("  - %s" % f)
    for w in result.warnings:
        print("  warning: %s" % w)
    return 0 if result.ok else 1


if __name__ == "__main__":
    sys.exit(main())
