"""ONE-SHOT cloud C3: what goes to the package index is the verifier and its readme and licence, nothing else (no tests,
no pricing or comparison files), and the verify.py inside it is byte-identical to the one packets are checked with."""
from __future__ import annotations

import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _build_sdist(out: Path) -> Path:
    code = "import setuptools.build_meta as b, sys; print(b.build_sdist(sys.argv[1]))"
    result = subprocess.run([sys.executable, "-c", code, str(out)], cwd=ROOT, capture_output=True, text=True)
    if result.returncode != 0:
        pytest.skip("setuptools cannot build here: " + result.stderr[-200:])
    return out / result.stdout.strip().splitlines()[-1]


def test_the_source_distribution_holds_only_the_verifier(tmp_path):
    sdist = _build_sdist(tmp_path)
    with tarfile.open(sdist) as tar:
        names = [n.split("/", 1)[1] for n in tar.getnames() if "/" in n]
        verify_py = tar.extractfile(next(m for m in tar.getmembers() if m.name.endswith("/verify.py"))).read()
    allowed_prefixes = ("actaseal_verify.egg-info",)
    allowed = {"LICENSE", "MANIFEST.in", "PKG-INFO", "README.md", "pyproject.toml", "setup.cfg",
               "verify.py", "verify_receipt.py", "verify_seal.py"}
    stray = [n for n in names if n not in allowed and not n.startswith(allowed_prefixes)]
    assert stray == [], stray
    assert not any("test" in n.lower() for n in names)
    assert verify_py == (ROOT / "verify.py").read_bytes()
