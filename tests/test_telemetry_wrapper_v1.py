"""PROD11(l): opt-in, count-only telemetry lives in a SEPARATE wrapper
(verify_with_telemetry.py), never in verify.py itself -- verify.py's
own zero-network-call guarantee (test_verify_has_no_external_imports_beyond_cryptography)
must never be touched by this feature."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WRAPPER = ROOT / "verify_with_telemetry.py"
DEMO_PACKET = ROOT / "demo" / "demo-packet-unanchored"


def test_verify_py_itself_has_no_telemetry_reference():
    source = (ROOT / "verify.py").read_text(encoding="utf-8")
    assert "telemetry" not in source.lower()
    assert "urllib" not in source


def test_wrapper_produces_identical_output_and_exit_code_to_plain_verify(tmp_path):
    plain = subprocess.run([sys.executable, str(ROOT / "verify.py"), str(DEMO_PACKET)], capture_output=True, text=True)
    wrapped = subprocess.run([sys.executable, str(WRAPPER), str(DEMO_PACKET)], capture_output=True, text=True)
    assert wrapped.returncode == plain.returncode == 0
    assert wrapped.stdout == plain.stdout


def test_wrapper_with_telemetry_flag_still_passes_and_strips_the_flag():
    result = subprocess.run(
        [sys.executable, str(WRAPPER), "--telemetry", str(DEMO_PACKET)], capture_output=True, text=True
    )
    assert result.returncode == 0
    assert "VERIFIED" in result.stdout


def test_wrapper_endpoint_empty_by_default():
    import importlib.util

    spec = importlib.util.spec_from_file_location("verify_with_telemetry", WRAPPER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert mod.TELEMETRY_ENDPOINT == ""


def test_telemetry_ping_never_raises_on_network_failure(monkeypatch):
    import importlib.util

    spec = importlib.util.spec_from_file_location("verify_with_telemetry", WRAPPER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    monkeypatch.setattr(mod, "TELEMETRY_ENDPOINT", "http://127.0.0.1:1/unreachable")
    mod._send_telemetry_ping(result="FAIL", failure_count=3)  # must not raise
