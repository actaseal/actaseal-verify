"""CHANGELOG.md states the version history as it actually is: every git
tag, and which of them were also published elsewhere. The numbering has
gaps and one step backwards-looking jump; the file says so instead of
tidying it."""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TEXT = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")


def test_every_git_tag_is_listed():
    tags = subprocess.run(["git", "tag", "-l"], cwd=ROOT, capture_output=True, text=True).stdout.split()
    for tag in tags:  # a shallow clone has none; then there is nothing to compare
        assert f"`{tag}`" in TEXT, f"tag {tag} is missing from CHANGELOG.md"


def test_known_history_is_stated():
    for fact in ("`v0.1.0`", "`v0.2.0`", "`v0.2.1`", "`v0.2.2`", "`v1.0.1`", "10.5281/zenodo.23309308",
                 "10.5281/zenodo.23309816", "10.5281/zenodo.23309307", "2026-07-20"):
        assert fact in TEXT, fact
    assert "no `v1.0.0` tag" in TEXT


def test_current_version_has_an_entry_marked_unreleased_until_it_is_tagged():
    version = re.search(r'^version = "([^"]+)"', (ROOT / "pyproject.toml").read_text(encoding="utf-8"), flags=re.M).group(1)
    assert f"## {version}" in TEXT
    tags = subprocess.run(["git", "tag", "-l"], cwd=ROOT, capture_output=True, text=True).stdout.split()
    section = TEXT.split(f"## {version}", 1)[1].split("\n## ", 1)[0]
    if f"v{version}" not in tags:
        assert "not yet tagged" in section.lower()
