"""The browser page also checks a share pack: one refund's events, sent to the customer.

A share pack (tenant_export.v1 holding one action) is a different format from the dispute
packet verify.py checks, and ships with its own checker, verify_tenant_export.py. The page runs
that file, unmodified, when the zip is a share pack. These tests hold glue.py to the command
line, on the demo share pack and on a changed one, and check the format is told apart.
"""
from __future__ import annotations

import importlib
import json
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
BROWSER = ROOT / "browser"
SHARE = ROOT / "demo" / "demo-share-pack.zip"
PACKET = ROOT / "demo" / "demo-packet-unanchored.zip"
SHARE_KEY = (ROOT / "demo" / "demo-share-pack.key").read_text().strip()


@pytest.fixture()
def glue(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT))
    monkeypatch.syspath_prepend(str(BROWSER))
    for name in ("glue", "verify_tenant_export"):
        sys.modules.pop(name, None)
    return importlib.import_module("glue")


def _cli(*args):
    return subprocess.run([sys.executable, str(ROOT / "verify_tenant_export.py"), *map(str, args)],
                          capture_output=True, text=True)


def test_the_format_is_told_apart(glue):
    assert glue.kind(str(SHARE)) == "share_pack"
    assert glue.kind(str(PACKET)) == "packet"


def test_the_bundled_checker_is_the_one_this_site_serves():
    with zipfile.ZipFile(SHARE) as z:
        assert z.read("verify_tenant_export.py") == (ROOT / "verify_tenant_export.py").read_bytes()


def test_glue_matches_the_cli_on_the_demo_share_pack(glue):
    code, output, args = glue.run_share_pack(str(SHARE), SHARE_KEY)
    cli = _cli(SHARE, "--public-key", SHARE_KEY)
    assert code == cli.returncode == 0
    assert output == cli.stdout and json.loads(output)["verified"] is True
    assert args == [str(SHARE), "--public-key", SHARE_KEY]


def test_a_wrong_key_or_a_changed_event_fails(glue, tmp_path):
    code, output, _ = glue.run_share_pack(str(SHARE), "00" * 32)
    assert code == 1 and json.loads(output)["verified"] is False
    changed = tmp_path / "changed.zip"
    with zipfile.ZipFile(SHARE) as src, zipfile.ZipFile(changed, "w") as dst:
        for name in src.namelist():
            data = src.read(name)
            if name == "events.ndjson":
                data = data.replace(b'"tenant_id"', b'"tenant_id" ', 1)
            dst.writestr(name, data)
    code, output, _ = glue.run_share_pack(str(changed), SHARE_KEY)
    cli = _cli(changed, "--public-key", SHARE_KEY)
    assert code == cli.returncode == 1 and output == cli.stdout


def test_the_page_loads_the_checker_and_names_the_format():
    app = (BROWSER / "app.js").read_text()
    page = (BROWSER / "index.html").read_text()
    assert "../verify_tenant_export.py" in app and "run_share_pack" in app
    assert 'id="demo-share"' in page and "share pack" in page.lower()
