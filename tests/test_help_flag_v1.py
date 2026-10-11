"""`-h` / `--help` is the first thing a recipient types at an unfamiliar
script. Both verifiers used to treat it as an input path and fail (a
"no such file" error that reads like a broken packet). They now print
their usage text and exit 0 without reading any input.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ["verify.py", "verify_receipt.py"]


def _run(script: str, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(ROOT / script), *args],
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        timeout=60,
    )


@pytest.mark.parametrize("script", SCRIPTS)
@pytest.mark.parametrize("flag", ["-h", "--help"])
def test_help_flag_prints_usage_and_exits_zero(script, flag):
    proc = _run(script, flag)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "Usage: python %s" % script in proc.stdout
    assert proc.stderr == ""


@pytest.mark.parametrize("script", SCRIPTS)
def test_help_flag_wins_even_alongside_other_arguments(script, tmp_path):
    # A help request must never be read as a verification verdict: it does
    # not touch the named input at all, so a missing path still exits 0.
    proc = _run(script, str(tmp_path / "does-not-exist"), "--help")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "Usage: python %s" % script in proc.stdout


@pytest.mark.parametrize("script", SCRIPTS)
def test_help_output_is_not_a_pass_verdict(script):
    # Exit 0 is also the "verified" exit code, so the help text itself must
    # not be mistakable for a successful verification line.
    proc = _run(script, "--help")
    assert not any(line.startswith("PASS") for line in proc.stdout.splitlines())
