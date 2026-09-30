"""conformance/generate_vectors.py used to mint a fresh Ed25519 key on
every run (both directly and via generate_demo_packet.build_packet()'s
own default) -- every vector file changed on every regeneration, even
when no underlying content changed (593c2e0 touched 23+ files, two
lines each, purely because the embedded verifier's own self-digest
changed). This corpus is PUBLIC and pinned by third-party implementers;
that churn made every regeneration a false breakage for them, and made
a genuinely hand-edited vector indistinguishable from a routine, no-op
regeneration in the diff this module's own docstring asks reviewers to
check before committing.

This test runs the real script twice (subprocess, exactly as a human
would) and asserts byte-identical output. Checked, not assumed: this
corpus contains no PQ/ML-DSA signing at all (see the generator's own
docstring, and the grep this test re-derives below), so there is no
hedged-signature exception to carve out here.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
GENERATOR = REPO_ROOT / "conformance" / "generate_vectors.py"
VECTORS_DIR = REPO_ROOT / "conformance" / "vectors"
PIN_FILE = REPO_ROOT / "conformance" / "vectors.sha256"


def test_no_pq_or_ecdsa_signing_exists_in_this_corpus():
    """Guards the claim the module docstring makes ("no PQ/ML-DSA
    signing at all... no ECDSA either") against silent drift -- if a
    future vector adds one of these, this test (not a human's memory)
    is what notices the determinism story here needs revisiting."""
    import ast

    def code_only(path: Path) -> str:
        # Module docstring discusses liboqs/ML-DSA by name (in the
        # negative, explaining why no exception is needed) -- strip it so
        # this check looks at actual code, not prose that mentions the
        # same words while explaining their absence.
        tree = ast.parse(path.read_text(encoding="utf-8"))
        module_docstring = ast.get_docstring(tree)
        source = path.read_text(encoding="utf-8")
        return source.replace(module_docstring, "", 1) if module_docstring else source

    generator_code = code_only(GENERATOR)
    demo_packet_code = code_only(REPO_ROOT / "generate_demo_packet.py")
    for forbidden in ("liboqs", "import oqs", "MLDSA", "ml_dsa", "ec.generate_private_key", "EllipticCurvePrivateKey"):
        assert forbidden not in generator_code, f"{forbidden!r} found in generate_vectors.py's code (outside its docstring)"
        assert forbidden not in demo_packet_code, f"{forbidden!r} found in generate_demo_packet.py's code (outside its docstring)"


def _run_generator() -> None:
    result = subprocess.run([sys.executable, str(GENERATOR)], capture_output=True, text=True, cwd=str(REPO_ROOT))
    assert result.returncode == 0, result.stdout + result.stderr


def _snapshot(tmp_path: Path, name: str) -> Path:
    dest = tmp_path / name
    shutil.copytree(VECTORS_DIR, dest / "vectors")
    shutil.copy2(PIN_FILE, dest / "vectors.sha256")
    return dest


def test_regenerating_with_no_content_change_is_fully_byte_identical(tmp_path):
    backup = _snapshot(tmp_path, "backup")
    try:
        _run_generator()
        run1 = _snapshot(tmp_path, "run1")
        _run_generator()
        run2 = _snapshot(tmp_path, "run2")

        pin1 = (run1 / "vectors.sha256").read_text()
        pin2 = (run2 / "vectors.sha256").read_text()
        assert pin1 == pin2, "vectors.sha256 pin differs between two clean regenerations"

        files1 = sorted(p.relative_to(run1 / "vectors") for p in (run1 / "vectors").rglob("*") if p.is_file())
        files2 = sorted(p.relative_to(run2 / "vectors") for p in (run2 / "vectors").rglob("*") if p.is_file())
        assert files1 == files2, "the two runs produced a different set of vector files"

        mismatches = []
        for rel in files1:
            content1 = (run1 / "vectors" / rel).read_bytes()
            content2 = (run2 / "vectors" / rel).read_bytes()
            if content1 != content2:
                mismatches.append(str(rel))
        assert not mismatches, f"these files differ between two clean regenerations: {mismatches}"
    finally:
        shutil.rmtree(VECTORS_DIR)
        shutil.copytree(backup / "vectors", VECTORS_DIR)
        shutil.copy2(backup / "vectors.sha256", PIN_FILE)


def test_default_build_packet_behavior_is_unchanged_and_still_random(tmp_path):
    """The seed-injection parameter added to generate_demo_packet.
    build_packet() must not change its default behavior: called with no
    signing_key, two calls must still produce two DIFFERENT keys (the
    top-level demo-packet generation and its own tests rely on this)."""
    sys.path.insert(0, str(REPO_ROOT))
    import generate_demo_packet as gen

    manifest_a, *_ = gen.build_packet(anchored=False)
    manifest_b, *_ = gen.build_packet(anchored=False)
    assert manifest_a["receipt_public_key_hex"] != manifest_b["receipt_public_key_hex"]
