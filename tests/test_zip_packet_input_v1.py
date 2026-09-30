"""A packet's real-world shape is a .zip someone downloaded, not an
already-extracted directory -- `python verify.py pack.zip` is the first
command a recipient actually types, and it used to fail with a
NotADirectoryError (errno 20) that reads like a tampered/corrupt packet,
not "you forgot to unzip." verify.py now accepts a .zip path directly
(extracting into a fresh temp dir with the same zip-slip/decompression-
bomb/symlink protections actaseal.dispute.safe_zip applies in the
private repo), while the pre-existing directory-based flow keeps working
unchanged.
"""
from __future__ import annotations

import json
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VERIFY_PY = ROOT / "verify.py"
GENERATOR = ROOT / "generate_demo_packet.py"


def _run_verify(*args) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(VERIFY_PY), *[str(a) for a in args]], capture_output=True, text=True)


def _zip_dir(source_dir: Path, zip_path: Path) -> None:
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(source_dir.rglob("*")):
            if path.is_file():
                zf.write(path, path.relative_to(source_dir))


def _demo_packet_dir(tmp_path: Path) -> Path:
    subprocess.run([sys.executable, str(GENERATOR), str(tmp_path)], check=True)
    return tmp_path / "demo-packet-unanchored"


def test_directory_input_still_works_unchanged(tmp_path):
    """Pre-existing path: an already-extracted directory. Must be
    completely unaffected by the new zip-handling code."""
    packet_dir = _demo_packet_dir(tmp_path)
    result = _run_verify(packet_dir)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "VERIFIED" in result.stdout


def test_zip_input_verifies_clean_dispute_packet(tmp_path):
    packet_dir = _demo_packet_dir(tmp_path)
    zip_path = tmp_path / "pack.zip"
    _zip_dir(packet_dir, zip_path)

    result = _run_verify(zip_path)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "VERIFIED" in result.stdout
    assert "errno" not in result.stdout.lower()
    assert "not a directory" not in result.stdout.lower()


def test_committed_demo_zips_verify_directly_with_no_unzip_step():
    for name in ("demo-packet-unanchored", "demo-packet-anchored"):
        result = _run_verify(ROOT / "demo" / f"{name}.zip")
        assert result.returncode == 0, result.stdout + result.stderr
        assert "VERIFIED" in result.stdout


def test_tampered_zip_fails_with_the_correct_named_reason(tmp_path):
    packet_dir = _demo_packet_dir(tmp_path)
    receipt_path = packet_dir / "receipt.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["decision"] = "BLOCK"  # tamper: flip without re-signing
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")

    zip_path = tmp_path / "tampered.zip"
    _zip_dir(packet_dir, zip_path)

    result = _run_verify(zip_path)
    assert result.returncode == 1
    assert "RECEIPT_SIGNATURE_INVALID" in result.stdout


def test_malicious_zip_slip_absolute_path_is_rejected_and_writes_nothing(tmp_path):
    evil_target = Path("/tmp/actaseal_zipslip_poc_absolute.txt")
    evil_target.unlink(missing_ok=True)
    zip_path = tmp_path / "evil.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr(str(evil_target), b"pwned")
        zf.writestr("manifest.json", b"{}")

    result = _run_verify(zip_path)
    assert result.returncode == 1
    assert "UNSAFE_ZIP_MEMBER_NAME" in result.stdout
    assert not evil_target.exists()


def test_malicious_zip_slip_dotdot_traversal_is_rejected(tmp_path):
    zip_path = tmp_path / "evil.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("../../../tmp/actaseal_zipslip_poc_dotdot.txt", b"pwned")
        zf.writestr("manifest.json", b"{}")

    result = _run_verify(zip_path)
    assert result.returncode == 1
    assert "UNSAFE_ZIP_MEMBER_NAME" in result.stdout
    assert not Path("/tmp/actaseal_zipslip_poc_dotdot.txt").exists()


def test_nonexistent_path_gives_a_clear_error_not_errno_20(tmp_path):
    missing = tmp_path / "does-not-exist.zip"
    result = _run_verify(missing)
    assert result.returncode == 1
    assert "VERIFICATION FAILED" in result.stdout
    assert "UNREADABLE_PACKET" in result.stdout
    assert "no such file or directory" in result.stdout.lower()
    # the confusing, wrong-direction message this replaces
    assert "errno 20" not in result.stdout.lower()
    assert "not a directory" not in result.stdout.lower()


def test_a_plain_non_zip_file_gives_a_clear_error(tmp_path):
    plain_file = tmp_path / "not-a-packet.txt"
    plain_file.write_text("hello")
    result = _run_verify(plain_file)
    assert result.returncode == 1
    assert "UNREADABLE_PACKET" in result.stdout
    assert "not a zip archive" in result.stdout


def test_archive_export_zip_also_works_end_to_end(tmp_path):
    """The archive-export mode (auto-detected from manifest.json) must
    accept a zip input the same way the dispute-packet mode does --
    this is one shared resolve_packet_base() call ahead of both."""
    import sys as _sys

    sys_path_added = str(Path.home() / "a" / "active_code")
    if sys_path_added not in _sys.path:
        _sys.path.insert(0, sys_path_added)
    try:
        from scripts.seal_external_file import seal_file
    except ImportError:
        import pytest

        pytest.skip("private repo (active_code) not present -- cannot build a real inspection pack here")

    input_path = tmp_path / "secret.txt"
    input_path.write_text("some content, never expected in the pack")
    pack_path = tmp_path / "sealed.zip"
    result = seal_file(input_path=input_path, label="zip input test", output_path=pack_path, offline_tsa=True)

    verify_result = _run_verify(pack_path)
    assert verify_result.returncode == 0, verify_result.stdout + verify_result.stderr
    assert "VERIFIED (archive export)" in verify_result.stdout
