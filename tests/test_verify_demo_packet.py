from __future__ import annotations

import json
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VERIFY_PY = ROOT / "verify.py"
GENERATOR = ROOT / "generate_demo_packet.py"


def _run_verify(packet_dir: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(VERIFY_PY), str(packet_dir)],
        capture_output=True,
        text=True,
    )


def test_demo_packets_regenerate_and_verify_clean(tmp_path):
    subprocess.run([sys.executable, str(GENERATOR), str(tmp_path)], check=True)

    for name in ("demo-packet-unanchored", "demo-packet-anchored"):
        result = _run_verify(tmp_path / name)
        assert result.returncode == 0, result.stdout + result.stderr
        assert "VERIFIED" in result.stdout


def test_committed_demo_zips_verify_clean(tmp_path):
    for name in ("demo-packet-unanchored", "demo-packet-anchored"):
        zip_path = ROOT / "demo" / f"{name}.zip"
        extract_dir = tmp_path / name
        with zipfile.ZipFile(zip_path) as archive:
            archive.extractall(extract_dir)
        result = _run_verify(extract_dir)
        assert result.returncode == 0, result.stdout + result.stderr


def test_tampered_receipt_amount_fails_verification(tmp_path):
    subprocess.run([sys.executable, str(GENERATOR), str(tmp_path)], check=True)
    packet_dir = tmp_path / "demo-packet-unanchored"

    receipt_path = packet_dir / "receipt.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["decision"] = "BLOCK"  # tamper: flip the decision without re-signing
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")

    result = _run_verify(packet_dir)
    assert result.returncode == 1
    assert "RECEIPT_SIGNATURE_INVALID" in result.stdout


def test_broken_chain_fails_verification(tmp_path):
    subprocess.run([sys.executable, str(GENERATOR), str(tmp_path)], check=True)
    packet_dir = tmp_path / "demo-packet-unanchored"

    slice_path = packet_dir / "ledger_slice.ndjson"
    lines = [line for line in slice_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    events = [json.loads(line) for line in lines]
    events[1]["previous_event_hash"] = "0" * 64  # tamper: break the chain link
    slice_path.write_text("\n".join(json.dumps(e) for e in events) + "\n", encoding="utf-8")

    result = _run_verify(packet_dir)
    assert result.returncode == 1
    assert "CHAIN_BROKEN" in result.stdout


def test_verify_has_no_external_imports_beyond_cryptography():
    source = VERIFY_PY.read_text(encoding="utf-8")
    assert "import actaseal" not in source
    assert "from actaseal" not in source
    assert "requests" not in source
    assert "urllib" not in source
    assert "socket" not in source
