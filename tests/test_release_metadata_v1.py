"""What this repository says about its own version is consistent, and the
release notes state the facts a holder of older packets needs."""
from __future__ import annotations

import hashlib
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VERSION = "1.0.2"


def _pyproject_version() -> str:
    return re.search(r'^version = "([^"]+)"', (ROOT / "pyproject.toml").read_text(encoding="utf-8"), flags=re.M).group(1)


def test_package_version():
    assert _pyproject_version() == VERSION


def test_release_notes_exist_for_this_version_and_name_the_verifier_digest():
    notes = (ROOT / "docs" / "release-notes" / f"{VERSION}.md").read_text(encoding="utf-8")
    sys.path.insert(0, str(ROOT))
    try:
        import verify
    finally:
        sys.path.remove(str(ROOT))
    body = verify.verifier_body_sha256((ROOT / "verify.py").read_bytes())
    assert body in notes, "release notes must state this verify.py's body digest (the value packets pin)"
    assert hashlib.sha256((ROOT / "verify.py").read_bytes()).hexdigest() in notes
    for phrase in ("--checkpoint", "VERIFIER_DIGEST_MISMATCH", "No check was removed or loosened"):
        assert phrase in notes, phrase


def test_root_versions_marker_is_unchanged():
    sys.path.insert(0, str(ROOT))
    try:
        import verify
    finally:
        sys.path.remove(str(ROOT))
    assert verify.VERIFIER_SUPPORTS_ROOT_VERSIONS == ("v1", "v2")
    assert verify.VERIFIER_SUPPORTS_APPROVAL_PAYLOAD_VERSIONS == ("v1", "v2")


def test_no_file_states_an_older_package_version_as_current():
    for name in ("pyproject.toml", "README.md", "llms.txt"):
        text = (ROOT / name).read_text(encoding="utf-8")
        assert "actaseal-verify==1.0.1" not in text and 'version = "1.0.1"' not in text, name
