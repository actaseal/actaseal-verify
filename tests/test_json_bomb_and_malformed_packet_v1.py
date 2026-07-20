"""Attack-surface suite (companion to the private repo's
tests/test_packet_zip_attack_surface_v1.py): verify.py's own JSON
parsing must fail closed (UNREADABLE_PACKET / non-zero exit) against a
malformed or hostile packet directory, never crash uncaught or hang.

verify.py itself is not touched by this file -- kept to stdlib only,
same zero-import constraint as verify.py itself. Every attack is run
through `main()` via subprocess, exactly how a real caller invokes it.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VERIFY_PY = ROOT / "verify.py"


def _run_verify(packet_dir: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(VERIFY_PY), str(packet_dir)],
        capture_output=True,
        text=True,
        timeout=30,  # must never hang -- a real bomb should fail fast, not time out
    )


def _minimal_packet(tmp_path: Path, *, manifest_text: str) -> Path:
    (tmp_path / "manifest.json").write_text(manifest_text)
    (tmp_path / "receipt.json").write_text("{}")
    (tmp_path / "ledger_slice.ndjson").write_text("")
    return tmp_path


def test_deeply_nested_json_manifest_fails_closed_not_uncaught(tmp_path):
    # A RecursionError-inducing JSON bomb -- verify.py's load_packet
    # call inside main() is wrapped in a broad try/except Exception,
    # which DOES catch RecursionError (RecursionError -> RuntimeError
    # -> Exception) -- confirmed here, not assumed.
    bomb = "[" * 200_000 + "]" * 200_000
    packet_dir = _minimal_packet(tmp_path, manifest_text=bomb)

    result = _run_verify(packet_dir)
    assert result.returncode != 0
    assert "VERIFICATION FAILED" in result.stdout
    assert "UNREADABLE_PACKET" in result.stdout
    assert "Traceback" not in result.stderr  # never an uncaught crash


def test_huge_string_manifest_field_fails_closed(tmp_path):
    # Not a decompression bomb (verify.py reads from a plain directory,
    # not a zip) but the same "hostile huge JSON" shape -- a single
    # multi-hundred-MB string value should be caught (MemoryError or
    # a slow-but-bounded parse), never hang indefinitely (see the
    # subprocess timeout above) or crash uncaught.
    huge = '{"decision": "%s"}' % ("A" * (50 * 1024 * 1024))
    packet_dir = _minimal_packet(tmp_path, manifest_text=huge)

    result = _run_verify(packet_dir)
    # Either it parses (a 50MB string alone isn't necessarily fatal) and
    # fails on missing required manifest fields downstream, or it fails
    # to read at all -- either way, closed, not a crash/hang.
    assert result.returncode != 0
    assert "Traceback" not in result.stderr


def test_missing_manifest_json_fails_closed(tmp_path):
    (tmp_path / "receipt.json").write_text("{}")
    (tmp_path / "ledger_slice.ndjson").write_text("")

    result = _run_verify(tmp_path)
    assert result.returncode != 0
    assert "UNREADABLE_PACKET" in result.stdout


def test_manifest_is_not_an_object_fails_closed(tmp_path):
    # manifest.json parses fine as JSON but is the wrong shape (a bare
    # array, not an object) -- downstream .get() calls on a list would
    # raise AttributeError if unguarded; confirm it's still caught.
    packet_dir = _minimal_packet(tmp_path, manifest_text="[1, 2, 3]")
    result = _run_verify(packet_dir)
    assert result.returncode != 0
    assert "Traceback" not in result.stderr


def test_binary_garbage_instead_of_json_fails_closed(tmp_path):
    (tmp_path / "manifest.json").write_bytes(b"\x00\x01\x02\xff\xfe not json at all")
    (tmp_path / "receipt.json").write_text("{}")
    (tmp_path / "ledger_slice.ndjson").write_text("")

    result = _run_verify(tmp_path)
    assert result.returncode != 0
    assert "UNREADABLE_PACKET" in result.stdout
