"""The @actaseal/verify npm package is ready to publish: the tarball holds
what a user needs (code, types, licence, a README npm will show), `npm test`
passes, and nothing outside the listed files ships. Nothing here publishes.
Skipped when node/npm are not installed."""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parent.parent / "tamper_demo"
pytestmark = pytest.mark.skipif(shutil.which("npm") is None, reason="npm is not installed")


def _pack():
    r = subprocess.run(["npm", "pack", "--dry-run", "--json"], cwd=PKG, capture_output=True, text=True, check=True)
    return json.loads(r.stdout)[0]


def test_tarball_holds_exactly_what_a_user_needs():
    files = {f["path"] for f in _pack()["files"]}
    assert files == {"verify_min.js", "index.d.ts", "README.md", "LICENSE", "package.json"}


def test_readme_is_the_one_npm_renders():
    assert (PKG / "README.md").exists() and not (PKG / "README.npm.md").exists()


def test_metadata_is_complete():
    pkg = json.loads((PKG / "package.json").read_text())
    assert pkg["license"] == "Apache-2.0" and pkg["types"] == "index.d.ts"
    assert pkg["exports"]["."]["require"] == "./verify_min.js" and pkg["exports"]["."]["types"] == "./index.d.ts"
    assert pkg["publishConfig"]["access"] == "public"
    assert "test" in pkg["scripts"] and "prepublishOnly" in pkg["scripts"]
    assert (PKG / "LICENSE").read_text() == (PKG.parent / "LICENSE").read_text()


def test_npm_test_passes():
    r = subprocess.run(["npm", "test", "--silent"], cwd=PKG, capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr


def test_types_name_every_export():
    src = (PKG / "index.d.ts").read_text()
    for name in ("canonicalDumps", "canonicalHash", "verifyEvents", "verifyReceipt", "verifyPacket"):
        assert name in src
