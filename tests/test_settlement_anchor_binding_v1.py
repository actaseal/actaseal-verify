"""The settlement anchor is bound by its own signature and to the receipt's mandate_hash.

Reported on the SCITT list on 17 Nov 2026 (Bassem Kudsi): an anchored packet's anchor
could be edited, with anchor_hash recomputed, or replaced with SETTLEMENT_UNANCHORED,
and the packet still verified. These tests pin what is now caught, and what a packet
alone still cannot show (each such case must be stated in the VERIFIED output).

The last test is the field sweep: every single-field edit to a packet must either fail,
or sit in a file the output names as not covered by any signature."""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parent.parent
ANCHORED = ROOT / "demo" / "demo-packet-anchored"
UNSIGNED_DOCS = {"acquisition.json", "custody.json", "authentication.json"}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def run(packet, *flags):
    r = subprocess.run([sys.executable, str(ROOT / "verify.py"), str(packet), *flags], capture_output=True, text=True)
    return r.returncode, r.stdout


def copy(tmp_path):
    target = tmp_path / "packet"
    shutil.copytree(ANCHORED, target)
    return target


def edit_manifest(packet, change):
    manifest = json.loads((packet / "manifest.json").read_text())
    change(manifest)
    (packet / "manifest.json").write_text(canonical(manifest))
    return manifest


def settlement_key_hex():
    manifest = json.loads((ANCHORED / "manifest.json").read_text())
    return manifest["settlement_anchor"]["anchor_signature"]["public_key_hex"]


def test_demo_anchored_packet_verifies_with_its_settlement_key_pinned():
    code, out = run(ANCHORED, "--settlement-public-key", settlement_key_hex())
    assert code == 0 and "VERIFIED" in out, out


def test_edited_anchor_with_recomputed_hash_fails(tmp_path):
    packet = copy(tmp_path)

    def change(m):
        anchor = m["settlement_anchor"]["anchor"]
        anchor.update(rail="other-rail", settled_at="2030-01-01T00:00:00+00:00", anchor_id="forged")
        m["settlement_anchor"]["anchor_hash"] = __import__("hashlib").sha256(canonical(anchor).encode()).hexdigest()

    edit_manifest(packet, change)
    code, out = run(packet)
    assert code == 1 and "SETTLEMENT_ANCHOR_SIGNATURE_INVALID" in out, out


def test_anchor_resigned_by_another_key_fails_only_when_the_key_is_pinned(tmp_path):
    packet = copy(tmp_path)
    key = Ed25519PrivateKey.generate()

    def change(m):
        anchor = m["settlement_anchor"]["anchor"]
        anchor["settled_at"] = "2030-01-01T00:00:00+00:00"
        m["settlement_anchor"]["anchor_hash"] = __import__("hashlib").sha256(canonical(anchor).encode()).hexdigest()
        m["settlement_anchor"]["anchor_signature"] = {
            "algorithm": "ed25519",
            "public_key_hex": key.public_key().public_bytes_raw().hex(),
            "signature_hex": key.sign(canonical(anchor).encode()).hex(),
        }

    edit_manifest(packet, change)
    code, out = run(packet)
    assert code == 0 and "checked only against the key the packet declares" in out, out
    code, out = run(packet, "--settlement-public-key", settlement_key_hex())
    assert code == 1 and "SETTLEMENT_ANCHOR_KEY_MISMATCH" in out, out


def test_anchor_for_another_mandate_fails(tmp_path):
    packet = copy(tmp_path)
    edit_manifest(packet, lambda m: m["settlement_anchor"]["anchor"].update(mandate_hash="0" * 64))
    code, out = run(packet)
    assert code == 1 and "SETTLEMENT_ANCHOR_UNLINKED" in out, out


def test_unsigned_anchor_verifies_but_says_it_is_unsigned(tmp_path):
    packet = copy(tmp_path)
    edit_manifest(packet, lambda m: m["settlement_anchor"].pop("anchor_signature"))
    code, out = run(packet)
    assert code == 0 and "SETTLEMENT_ANCHOR_UNSIGNED" in out, out
    code, out = run(packet, "--settlement-public-key", settlement_key_hex())
    assert code == 1 and "SETTLEMENT_ANCHOR_UNSIGNED" in out, out


def test_relabelled_unanchored_verifies_but_says_the_status_is_unsigned(tmp_path):
    packet = copy(tmp_path)

    def change(m):
        m["settlement_anchor"] = {"status": "SETTLEMENT_UNANCHORED"}

    edit_manifest(packet, change)
    code, out = run(packet)
    assert code == 0 and "SETTLEMENT_STATUS_UNSIGNED" in out, out
    code, out = run(packet, "--settlement-public-key", settlement_key_hex())
    assert code == 1 and "SETTLEMENT_ANCHOR_UNSIGNED" in out, out


def _leaves(value, path=()):
    if isinstance(value, dict):
        for key, item in value.items():
            yield from _leaves(item, path + (key,))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _leaves(item, path + (index,))
    else:
        yield path, value


def _set(value, path, new):
    for key in path[:-1]:
        value = value[key]
    value[path[-1]] = new


def _mutate(value):
    if isinstance(value, bool):
        return not value
    if isinstance(value, (int, float)):
        return value + 1
    if isinstance(value, str) and value:
        return value[:-1] + ("1" if value[-1] == "0" else "0")
    return "x"


def _edits():
    for path in sorted(ANCHORED.glob("*.json")):
        for leaf, value in _leaves(json.loads(path.read_text())):
            yield path.name, None, leaf, value
    lines = (ANCHORED / "ledger_slice.ndjson").read_text().splitlines()
    for index, line in enumerate(lines):
        for leaf, value in _leaves(json.loads(line)):
            yield "ledger_slice.ndjson", index, leaf, value


EDITS = list(_edits())


@pytest.mark.parametrize(
    "name,line,leaf,value", EDITS, ids=["%s[%s]:%s" % (n, l, ".".join(map(str, p))) for n, l, p, _ in EDITS]
)
def test_every_field_edit_fails_or_is_declared_unsigned(tmp_path, name, line, leaf, value):
    packet = copy(tmp_path)
    if line is None:
        document = json.loads((packet / name).read_text())
        _set(document, leaf, _mutate(value))
        (packet / name).write_text(canonical(document))
    else:
        rows = [json.loads(row) for row in (packet / name).read_text().splitlines()]
        _set(rows[line], leaf, _mutate(value))
        (packet / name).write_text("\n".join(canonical(row) for row in rows) + "\n")
    code, out = run(packet)
    if code == 0:
        assert name in UNSIGNED_DOCS and "NOT_COVERED_BY_SIGNATURE" in out and name in out, out
