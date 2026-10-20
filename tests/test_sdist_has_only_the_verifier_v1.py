"""The source distribution published on PyPI carries the verifier, its readme and licence, and nothing else:
no tests, no pages, no internal notes. A file in the sdist is a file anyone can read."""
import pathlib
import subprocess
import sys
import tarfile
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _members() -> list[str]:
    with tempfile.TemporaryDirectory() as out:
        code = (
            "import setuptools.build_meta as b, sys; print(b.build_sdist(sys.argv[1]))"
        )
        done = subprocess.run([sys.executable, "-c", code, out], cwd=ROOT, capture_output=True, text=True, check=False)
        assert done.returncode == 0, done.stderr[-800:]
        archive = pathlib.Path(out) / done.stdout.strip().splitlines()[-1]
        with tarfile.open(archive) as tar:
            return [m.name.split("/", 1)[1] for m in tar.getmembers() if m.isfile() and "/" in m.name]


def test_the_sdist_holds_no_tests_pages_or_notes():
    names = _members()
    for name in names:
        top = name.split("/")[0]
        assert top not in {"tests", "scripts", "docs", "conformance", "browser", "demo", "tamper_demo", ".github"}, name
        assert not name.endswith(".html"), name
        assert name not in {"AGENTS.md", "CONTRIBUTING.md", "llms.txt", "SPEC.md"}, name


def test_the_sdist_still_holds_the_verifier_and_the_licence():
    names = set(_members())
    assert {"verify.py", "verify_seal.py", "verify_receipt.py", "LICENSE", "README.md", "pyproject.toml"} <= names
