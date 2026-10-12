"""verify.py --checkpoint: check a packet against a trusted ledger hash
when the signing key cannot be trusted or is not known.

The caller supplies, out of band, the hash of a ledger event they trust
(from the operator's published anchor, say). The packet passes on the
chain alone if that hash is in its unbroken slice at or after the
receipt's own ledger entry, and an event under that checkpoint records
this receipt's hash -- so the receipt's content, not just its position,
is committed by something the caller already trusts. The result says
CHAIN_VERIFIED_KEY_UNKNOWN and never claims a signature check.

Every other packet check still runs. A key or keyring the caller
supplies is never overridden by a checkpoint.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from generate_demo_packet import build_packet, canonical_dumps  # noqa: E402

FILES = ("manifest", "receipt", "acquisition", "custody", "authentication")


def _write(directory: Path, parts) -> Path:
    manifest, receipt, events, acquisition, custody, authentication = parts
    directory.mkdir(parents=True, exist_ok=True)
    for name, value in zip(FILES, (manifest, receipt, acquisition, custody, authentication)):
        (directory / f"{name}.json").write_text(canonical_dumps(value), encoding="utf-8")
    (directory / "ledger_slice.ndjson").write_text(
        "\n".join(canonical_dumps(event) for event in events) + "\n", encoding="utf-8"
    )
    return directory


def _packet(tmp_path, *, receipt_events=True):
    parts = build_packet(anchored=False, receipt_events=receipt_events)
    return _write(tmp_path / "packet", parts), parts


def _run(packet: Path, *args):
    return subprocess.run([sys.executable, str(ROOT / "verify.py"), str(packet), *args], capture_output=True, text=True)


def _hashes(parts):
    return [event["event_hash"] for event in parts[2]]


def _resign_with_another_key(packet: Path) -> None:
    """What a rotated or unknown key looks like to the verifier: the
    receipt is intact but the key in the packet is not the one that
    signed it."""
    manifest = json.loads((packet / "manifest.json").read_text())
    manifest["receipt_public_key_hex"] = Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()
    (packet / "manifest.json").write_text(canonical_dumps(manifest), encoding="utf-8")


# --- the packet shape -------------------------------------------------------

def test_builder_can_record_the_receipt_hash_in_the_chain(tmp_path):
    packet, parts = _packet(tmp_path)
    types = [event["event_type"] for event in parts[2]]
    assert types[-2:] == ["ReceiptStructured", "ReceiptSigned"]
    assert _run(packet).returncode == 0  # an ordinary, fully valid packet
    assert [e["event_type"] for e in build_packet(anchored=False)[2]][-1] == "Finalized"  # default unchanged


# --- with a good signature, a checkpoint is one more check -------------------

def test_valid_signature_and_checkpoint_reports_both(tmp_path):
    packet, parts = _packet(tmp_path)
    result = _run(packet, "--checkpoint", _hashes(parts)[-1])
    assert result.returncode == 0, result.stdout
    assert "receipt signature valid" in result.stdout
    assert "checkpoint" in result.stdout and "CHAIN_VERIFIED_KEY_UNKNOWN" not in result.stdout


def test_checkpoint_not_in_the_chain_fails_even_with_a_valid_signature(tmp_path):
    packet, _ = _packet(tmp_path)
    result = _run(packet, "--checkpoint", "ab" * 32)
    assert result.returncode == 1
    assert "CHECKPOINT_NOT_IN_SLICE" in result.stdout


def test_checkpoint_before_the_receipts_entry_does_not_cover_it(tmp_path):
    packet, parts = _packet(tmp_path)
    result = _run(packet, "--checkpoint", _hashes(parts)[0])
    assert result.returncode == 1
    assert "CHECKPOINT_BEFORE_RECEIPT_ENTRY" in result.stdout


# --- key unknown: the chain carries it --------------------------------------

def test_unknown_key_passes_on_the_chain_and_says_so(tmp_path):
    packet, parts = _packet(tmp_path)
    _resign_with_another_key(packet)
    assert _run(packet).returncode == 1  # without a checkpoint this packet fails, as before
    result = _run(packet, "--checkpoint", _hashes(parts)[-1])
    assert result.returncode == 0, result.stdout
    assert "CHAIN_VERIFIED_KEY_UNKNOWN" in result.stdout
    assert "receipt signature valid" not in result.stdout
    assert "signature was NOT verified" in result.stdout


def test_unknown_key_with_an_altered_receipt_fails(tmp_path):
    packet, parts = _packet(tmp_path)
    _resign_with_another_key(packet)
    receipt = json.loads((packet / "receipt.json").read_text())
    receipt["decision"] = "BLOCK"
    (packet / "receipt.json").write_text(canonical_dumps(receipt), encoding="utf-8")
    result = _run(packet, "--checkpoint", _hashes(parts)[-1])
    assert result.returncode == 1
    assert "CHECKPOINT_RECEIPT_NOT_COMMITTED" in result.stdout


def test_unknown_key_needs_the_receipt_hash_under_the_checkpoint(tmp_path):
    # The checkpoint names the receipt's own entry, which is before the
    # event that records the receipt hash: position is covered, content is not.
    packet, parts = _packet(tmp_path)
    _resign_with_another_key(packet)
    result = _run(packet, "--checkpoint", parts[1]["ledger_entry_hash"])
    assert result.returncode == 1
    assert "CHECKPOINT_RECEIPT_NOT_COMMITTED" in result.stdout


def test_unknown_key_on_a_chain_that_never_recorded_the_receipt_hash_fails(tmp_path):
    packet, parts = _packet(tmp_path, receipt_events=False)
    _resign_with_another_key(packet)
    result = _run(packet, "--checkpoint", _hashes(parts)[-1])
    assert result.returncode == 1
    assert "CHECKPOINT_RECEIPT_NOT_COMMITTED" in result.stdout


def test_unknown_key_with_a_broken_chain_fails(tmp_path):
    packet, parts = _packet(tmp_path)
    _resign_with_another_key(packet)
    lines = (packet / "ledger_slice.ndjson").read_text().splitlines()
    event = json.loads(lines[1])
    event["actor_id"] = "someone-else"
    lines[1] = canonical_dumps(event)
    (packet / "ledger_slice.ndjson").write_text("\n".join(lines) + "\n", encoding="utf-8")
    result = _run(packet, "--checkpoint", _hashes(parts)[-1])
    assert result.returncode == 1
    assert "CHAIN_VERIFIED_KEY_UNKNOWN" not in result.stdout


def test_a_fabricated_packet_cannot_supply_its_own_checkpoint(tmp_path):
    # A whole packet re-made under another key records a different
    # receipt hash, so its chain ends differently; a checkpoint the
    # caller got from the real operator is not in it.
    genuine = build_packet(anchored=False, receipt_events=True)
    forged_packet, forged = _packet(tmp_path)
    trusted = genuine[2][-1]["event_hash"]
    assert trusted not in _hashes(forged)
    result = _run(forged_packet, "--checkpoint", trusted)
    assert result.returncode == 1 and "CHECKPOINT_NOT_IN_SLICE" in result.stdout


# --- a key the caller supplied is never overridden --------------------------

def test_a_pinned_key_that_does_not_match_still_fails(tmp_path):
    packet, parts = _packet(tmp_path)
    result = _run(packet, "--checkpoint", _hashes(parts)[-1], "--receipt-public-key", "cd" * 32)
    assert result.returncode == 1
    assert "RECEIPT_KEY_NOT_TRUSTED" in result.stdout
    assert "CHAIN_VERIFIED_KEY_UNKNOWN" not in result.stdout


# --- the flag itself ---------------------------------------------------------

@pytest.mark.parametrize("value", ["", "xyz", "ab" * 31, "AB" * 33])
def test_malformed_checkpoint_is_refused(tmp_path, value):
    packet, _ = _packet(tmp_path)
    result = _run(packet, "--checkpoint", value)
    assert result.returncode == 2
    assert "UNABLE_TO_RUN" in result.stdout and "--checkpoint" in result.stdout


def test_checkpoint_needs_a_value(tmp_path):
    packet, _ = _packet(tmp_path)
    result = _run(packet, "--checkpoint")
    assert result.returncode == 2 and "UNABLE_TO_RUN" in result.stdout


def test_without_the_flag_output_is_unchanged(tmp_path):
    packet, _ = _packet(tmp_path, receipt_events=False)
    result = _run(packet)
    assert result.returncode == 0
    assert "checkpoint" not in result.stdout.lower()


def test_help_describes_the_mode():
    text = subprocess.run([sys.executable, str(ROOT / "verify.py"), "--help"], capture_output=True, text=True).stdout
    assert "--checkpoint" in text and "CHAIN_VERIFIED_KEY_UNKNOWN" in text
