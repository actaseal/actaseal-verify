"""The receipt's trust root is manifest.json's receipt_public_key_hex,
which the packet supplies itself. Two things must hold:

1. The signed receipt's signer_pubkey_hash (sha256 of the raw signer
   public key) must match that manifest key. Otherwise a packet re-signed
   with an attacker's key, leaving the signed hash pointing at the real
   signer, still printed VERIFIED.
2. A relying party can pin the operator's published key with
   --receipt-public-key HEX, and when they don't, the output says the key
   was only the packet's own claim instead of implying it was checked.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

REPO_ROOT = Path(__file__).resolve().parent.parent
VERIFY = REPO_ROOT / "verify.py"
DEMO = REPO_ROOT / "demo" / "demo-packet-unanchored"

_spec = importlib.util.spec_from_file_location("_verify_mod", VERIFY)
_verify = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_verify)


def _copy(tmp_path: Path) -> Path:
    dest = tmp_path / "packet"
    shutil.copytree(DEMO, dest)
    return dest


def _run(packet: Path, *flags: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(VERIFY), str(packet), *flags], capture_output=True, text=True, timeout=30
    )


def _manifest_key(packet: Path) -> str:
    return json.loads((packet / "manifest.json").read_text())["receipt_public_key_hex"]


def _resign(packet: Path, *, rebind_hash: bool) -> str:
    """Re-sign the receipt with a fresh attacker key and swap it into the
    manifest. rebind_hash=True also rewrites the signed signer_pubkey_hash
    (and authentication.json's copy) to the attacker key -- a fully
    consistent forgery only an out-of-band key pin can catch."""
    manifest = json.loads((packet / "manifest.json").read_text())
    receipt = json.loads((packet / "receipt.json").read_text())
    key = Ed25519PrivateKey.generate()
    pub_hex = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    if rebind_hash:
        new_hash = hashlib.sha256(bytes.fromhex(pub_hex)).hexdigest()
        receipt["signer_pubkey_hash"] = new_hash
        auth = json.loads((packet / "authentication.json").read_text())
        auth["signer_pubkey_hash"] = new_hash
        (packet / "authentication.json").write_text(json.dumps(auth))
    unsigned = {k: v for k, v in receipt.items() if k not in ("signature", "tsa_anchor")}
    receipt["signature"] = key.sign(_verify.canonical_dumps(unsigned).encode("utf-8")).hex()
    manifest["receipt_public_key_hex"] = pub_hex
    (packet / "manifest.json").write_text(json.dumps(manifest))
    (packet / "receipt.json").write_text(json.dumps(receipt))
    return pub_hex


def test_resigned_packet_with_unrebound_signed_hash_fails(tmp_path):
    packet = _copy(tmp_path)
    _resign(packet, rebind_hash=False)
    result = _run(packet)
    assert result.returncode == 1, result.stdout
    assert "RECEIPT_SIGNER_PUBKEY_HASH_MISMATCH" in result.stdout


def test_genuine_packet_without_pin_says_key_was_not_independently_checked(tmp_path):
    packet = _copy(tmp_path)
    result = _run(packet)
    assert result.returncode == 0, result.stdout
    assert "VERIFIED" in result.stdout
    assert "receipt key NOT checked against an independent key" in result.stdout
    assert "no --receipt-public-key given" in result.stdout
    assert _manifest_key(packet) in result.stdout


def test_genuine_packet_with_correct_pin_verifies(tmp_path):
    packet = _copy(tmp_path)
    result = _run(packet, "--receipt-public-key", _manifest_key(packet))
    assert result.returncode == 0, result.stdout
    assert "receipt key matches --receipt-public-key" in result.stdout
    assert "NOT checked against an independent key" not in result.stdout


def test_fully_consistent_forgery_passes_unpinned_but_fails_pinned(tmp_path):
    packet = _copy(tmp_path)
    real_key = _manifest_key(packet)
    _resign(packet, rebind_hash=True)
    unpinned = _run(packet)
    assert unpinned.returncode == 0, unpinned.stdout
    assert "NOT checked against an independent key" in unpinned.stdout
    pinned = _run(packet, "--receipt-public-key", real_key)
    assert pinned.returncode == 1, pinned.stdout
    assert "RECEIPT_KEY_NOT_TRUSTED" in pinned.stdout


def test_pin_flag_requires_a_value(tmp_path):
    packet = _copy(tmp_path)
    result = subprocess.run(
        [sys.executable, str(VERIFY), str(packet), "--receipt-public-key"],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode != 0
    assert "--receipt-public-key requires" in result.stdout
