"""browser/ runs the site's own verify.py in Pyodide. These tests pin the
two things that page depends on: that browser/glue.py (the only Python it
adds) produces exactly what the CLI produces, and that the committed
runtime files are the pinned ones, not something swapped in.
"""
from __future__ import annotations

import hashlib
import importlib
import json
import re
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
BROWSER = ROOT / "browser"
RUNTIME = BROWSER / "runtime"
DEMO_ZIPS = [ROOT / "demo" / "demo-packet-unanchored.zip", ROOT / "demo" / "demo-packet-anchored.zip"]


@pytest.fixture()
def glue(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT))
    monkeypatch.syspath_prepend(str(BROWSER))
    sys.modules.pop("glue", None)
    return importlib.import_module("glue")


def _cli(*args):
    return subprocess.run([sys.executable, str(ROOT / "verify.py"), *map(str, args)],
                          capture_output=True, text=True)


@pytest.mark.parametrize("packet", DEMO_ZIPS, ids=lambda p: p.name)
def test_glue_matches_cli_on_demo_packets(glue, packet):
    code, output, _ = glue.run(str(packet))
    cli = _cli(packet)
    assert code == cli.returncode == 0
    assert output == cli.stdout


def test_glue_reports_tampering_like_cli(glue, tmp_path):
    extracted = tmp_path / "p"
    with zipfile.ZipFile(DEMO_ZIPS[0]) as zf:
        zf.extractall(extracted)
    receipt = extracted / "receipt.json"
    data = json.loads(receipt.read_text())
    data["receipt_signature_hex"] = "00" * 64
    receipt.write_text(json.dumps(data))
    tampered = tmp_path / "tampered.zip"
    with zipfile.ZipFile(tampered, "w") as zf:
        for p in sorted(extracted.rglob("*")):
            if p.is_file():
                zf.write(p, p.relative_to(extracted))

    code, output, _ = glue.run(str(tampered))
    cli = _cli(tampered)
    assert code == cli.returncode == 1
    assert output == cli.stdout
    assert "VERIFICATION FAILED" in output


def test_glue_passes_optional_inputs_as_cli_flags(glue):
    _, _, args = glue.run(str(DEMO_ZIPS[0]), "ab" * 32, ["a.pem", "b.pem"], "anchors.jsonl")
    assert args == [str(DEMO_ZIPS[0]), "--sth-public-key", "ab" * 32,
                    "--tsa-ca-cert", "a.pem", "--tsa-ca-cert", "b.pem", "--anchors", "anchors.jsonl"]


def test_glue_flags_exist_in_verify_py():
    src = (ROOT / "verify.py").read_text()
    for flag in re.findall(r'"(--[a-z-]+)"', (BROWSER / "glue.py").read_text()):
        assert '"%s"' % flag in src, flag


def _sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_runtime_wheels_match_pyodide_lock():
    lock = json.loads((RUNTIME / "pyodide-lock.json").read_text())["packages"]
    wheels = sorted(p.name for p in RUNTIME.glob("*.whl"))
    by_file = {meta["file_name"]: meta for meta in lock.values()}
    assert wheels, "browser/runtime has no wheels"
    for name in wheels:
        assert _sha256(RUNTIME / name) == by_file[name]["sha256"], name


def test_runtime_is_what_the_fetch_script_produces(tmp_path):
    tarball = ROOT / ".cache" / "pyodide-314.0.7.tar.bz2"
    if not tarball.exists():
        pytest.skip("pinned Pyodide tarball not cached locally (scripts/fetch_browser_runtime.py downloads it)")
    before = {p.name: _sha256(p) for p in RUNTIME.iterdir()}
    backup = tmp_path / "runtime"
    shutil.copytree(RUNTIME, backup)
    try:
        subprocess.run([sys.executable, str(ROOT / "scripts" / "fetch_browser_runtime.py")], check=True)
        after = {p.name: _sha256(p) for p in RUNTIME.iterdir()}
    finally:
        shutil.rmtree(RUNTIME)
        shutil.copytree(backup, RUNTIME)
    assert after == before


def test_page_loads_only_same_origin_code():
    html = (BROWSER / "index.html").read_text() + (BROWSER / "app.js").read_text()
    for src in re.findall(r'(?:src|from|import\()\s*=?\s*["\']([^"\']+)', html):
        assert not src.startswith(("http:", "https:", "//")), src
