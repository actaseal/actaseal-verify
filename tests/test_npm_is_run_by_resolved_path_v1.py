"""A test that starts npm names it by the path shutil.which found, never the bare word.

On Windows npm is npm.cmd; subprocess.run(["npm", ...]) cannot start it (WinError 2), while
shutil.which("npm") finds it, so the skip guard passes and the test then fails. That kept the
Windows job red from 2026-10-18 on (tests/test_npm_package_ready_v1.py, two tests). Linux cannot
show it, so this holds the source to the rule.
"""
from __future__ import annotations

import re
from pathlib import Path

BARE = re.compile(r"""\[\s*["']np[mx]["']\s*,""")


def test_no_test_starts_npm_by_its_bare_name():
    offenders = [
        f"{p.name}:{n}"
        for p in sorted(Path(__file__).parent.glob("test_*.py"))
        if p.name != Path(__file__).name
        for n, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1)
        if BARE.search(line)
    ]
    assert not offenders, offenders
