"""Nothing a visitor reads in this repository's public pages describes how
the licensed product is built, sold or staffed. Outcomes only.

This repository is public, so its own files may be named: a path or a
.py file is a finding only when it does not exist here. Checked on the
visible text of every page and on the prose documents a visitor is
pointed at.

The verifier's own source files are covered too, in full: comments,
docstrings (which are the --help text) and every string they can print.
They were cleaned in the 1.0.2 release, the deliberate versioned change
their pinned digest requires.
"""
import html
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
TRACKED = set(subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True).stdout.split())
TRACKED_NAMES = {Path(p).name for p in TRACKED}
PROSE = ["README.md", "llms.txt", "docs/whitepaper.md", "SPEC.md", "SECURITY.md", "AGENTS.md",
         "CONTRIBUTING.md", "conformance/README.md", "tamper_demo/README.md", ".well-known/security.txt"]

PATTERNS = [
    ("internal document", re.compile(r"CLAUDE\.md|README-DEPLOY|USER_ACTIONS|STATE\.md|KNOWN_FAILURES|CAPABILITIES\.md|VERIFIER_SYNC", re.I)),
    ("private repository", re.compile(r"private (actaseal |product )?repo|private actaseal (gateway|product)", re.I)),
    ("product setting name", re.compile(r"\bACTASEAL_[A-Z0-9_]+\b")),
    ("route", re.compile(r"\b(GET|POST|PUT|PATCH|DELETE)\s+/[\w{}./-]+")),
    ("roadmap", re.compile(r"\broadmap\b|coming soon|not yet built|not yet implemented", re.I)),
    ("admission about the product's code", re.compile(r"legacy[- ]scaffold|dead code|unenforced|not (yet )?wired|unwired", re.I)),
    ("module path", re.compile(r"\bactaseal\.(?!com\b|sdk\b|mcp\b|egg)[a-z_]+\.[a-z_]+")),
    ("tier with price", re.compile(r"\b(Foundation|Firm|Enterprise|Starter|Pro|Team)\b[^.\n]{0,80}[$₹€£]\s?\d", re.I)),
    ("price", re.compile(r"[$₹€£]\s?\d[\d,]{2,}")),
    ("metering limit", re.compile(r"\bup to \d+ (archived )?(engagements|agents|users|seats|actions)|per (archived )?engagement, per year|\b\d+ (archived )?engagements per year", re.I)),
    ("tier language", re.compile(r"\bfor your tier\b|\bat every tier\b|\bevery tier\b", re.I)),
    ("watermark", re.compile(r"watermark", re.I)),
    ("discount terms", re.compile(r"discount|early[- ]adopter|early deployer|first (three|few|\d+) (deployments|customers|firms)|design partner|founding customer", re.I)),
    ("company stage", re.compile(r"no customers|not in production|in production yet|one person|solo founder|single founder|small vendor|no committee", re.I)),
    ("score or percentage", re.compile(r"\b\d+(\.\d+)?\s?%|\bconfidence (score|level)\b|\b(risk|trust|readiness|quality) score\b", re.I)),
]


def _targets():
    for rel in sorted(TRACKED):
        if rel.endswith(".html") and not rel.startswith(("tests/", "dist/")):
            yield rel
    for rel in PROSE:
        if rel in TRACKED:
            yield rel
    for rel in sorted(TRACKED):
        if rel.startswith("docs/release-notes/") or rel in ("CHANGELOG.md", "CITATION.cff"):
            yield rel


def _visible(rel: str) -> str:
    raw = (ROOT / rel).read_text(encoding="utf-8")
    if not rel.endswith(".html"):
        return raw
    raw = re.sub(r"<(script|style)\b.*?</\1>", " ", raw, flags=re.S)
    raw = re.sub(r"<!--.*?-->", " ", raw, flags=re.S)
    metas = " ".join(re.findall(r'<meta[^>]+content="([^"]*)"', raw))
    return re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", raw) + " " + metas))


def _exists_here(token: str) -> bool:
    token = token.lstrip("./")
    return token in TRACKED or Path(token).name in TRACKED_NAMES or any(p.startswith(token.rstrip("/") + "/") for p in TRACKED)


def _findings(rel: str) -> list[str]:
    text = _visible(rel)
    found = []
    around = lambda m: text[max(0, m.start() - 40):m.end() + 30].replace("\n", " ").strip()  # noqa: E731
    for label, pattern in PATTERNS:
        found += [f"{label}: {around(m)!r}" for m in pattern.finditer(text)]
    for m in re.finditer(r"(?<![@\w.-])(?:[\w.-]+/)*[\w-]+\.py\b", text):
        if not _exists_here(m.group(0)):
            found.append(f"source file not in this repository: {around(m)!r}")
    for m in re.finditer(r"(?<![@/.\w-])actaseal/[\w/.-]+", text):
        if m.group(0).startswith("actaseal/actaseal-verify"):  # this repository's own address
            continue
        if not _exists_here(m.group(0)):
            found.append(f"source path not in this repository: {around(m)!r}")
    return found


# The whitepaper quotes card-scheme thresholds and an analyst projection.
# Those are other parties' published figures, each with its source named
# beside it, not a score or a number about this product. The exception is
# held to exactly that: see the test below.
THIRD_PARTY_FIGURES = {"docs/whitepaper.md": {"score or percentage"}}


@pytest.mark.parametrize("rel", list(_targets()))
def test_public_text_exposes_nothing_internal(rel):
    allowed = THIRD_PARTY_FIGURES.get(rel, set())
    found = [f for f in _findings(rel) if f.split(":", 1)[0] not in allowed]
    assert not found, "\n".join(found)


def test_every_percentage_in_the_whitepaper_names_its_source():
    text = (ROOT / "docs" / "whitepaper.md").read_text(encoding="utf-8")
    for block in re.split(r"\n(?=- |\n)", text):
        if re.search(r"\d\s?%", block):
            assert re.search(r"reported|sourced|per [A-Z]", block), f"unsourced figure: {block[:120]!r}"


def test_the_check_itself_catches_each_kind():
    samples = {
        "internal document": "as CLAUDE.md says",
        "private repository": "in the private actaseal repo",
        "module path": "handled by actaseal.gateway.runtime",
        "tier with price": "Firm tier is $48,000 a year",
        "metering limit": "up to 25 archived engagements",
        "watermark": "exports are watermarked",
        "discount terms": "an early-adopter rate",
        "company stage": "a small vendor",
        "product setting name": "set ACTASEAL_SIGNING_KEY first",
        "route": "call POST /gateway/preflight",
        "roadmap": "this is (roadmap)",
        "admission about the product's code": "no broken-legacy-scaffold problem",
        "score or percentage": "a 97% match",
    }
    for label, sample in samples.items():
        assert dict(PATTERNS)[label].search(sample), label
    assert _exists_here("verify.py") and not _exists_here("actaseal/dispute/verifier_gate.py")


# --- the scripts people run: comments, help text, printed strings ----------

SCRIPTS = sorted(rel for rel in TRACKED if rel.endswith(".py") and "/" not in rel)
SOURCE_PATTERNS = [
    pattern for pattern in PATTERNS
    if pattern[0] in {"internal document", "private repository", "module path", "product setting name", "roadmap",
                      "admission about the product's code"}
] + [
    ("internal task label", re.compile(r"\b(ONESHOT|ONE-SHOT|FINAL-BATCH|READINESS-AND-SHIP|ATTESTATION-LIVE)\b|\b(PROD|HARD|PLUG|RCA)\d+\b|\bTASK \d|\bTask [A-Z0-9]\b")),
    ("another file's name for this one", re.compile(r"offline_verifier\.py")),
    ("kept-in-step-with pointer", re.compile(r"lock-step with actaseal", re.I)),
]


def test_the_scripts_are_what_this_covers():
    assert {"verify.py", "verify_receipt.py", "verify_seal.py"} <= set(SCRIPTS)


@pytest.mark.parametrize("rel", SCRIPTS)
def test_script_source_names_nothing_internal(rel):
    text = (ROOT / rel).read_text(encoding="utf-8")
    found = []
    for label, pattern in SOURCE_PATTERNS:
        for match in pattern.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            found.append(f"{label} (line {line}): {text[max(0, match.start() - 30):match.end() + 30]!r}")
    for match in re.finditer(r"(?<![@/.\w-])actaseal/[\w/.-]+", text):
        if not match.group(0).startswith("actaseal/actaseal-verify") and not _exists_here(match.group(0)):
            found.append(f"source path not in this repository: {match.group(0)!r}")
    assert not found, "\n".join(found)


@pytest.mark.parametrize("script", ["verify.py", "verify_receipt.py", "verify_seal.py"])
def test_help_text_names_nothing_internal(script):
    import sys

    result = subprocess.run([sys.executable, str(ROOT / script), "--help"], capture_output=True, text=True)
    text = result.stdout + result.stderr
    assert text.strip()
    found = [f"{label}: {m.group(0)!r}" for label, pattern in SOURCE_PATTERNS for m in pattern.finditer(text)]
    assert not found, "\n".join(found)


def test_the_source_check_catches_what_was_there_before():
    was = [
        "actaseal/dispute/verifier_gate.py\nin the private actaseal repo reads this exact marker",
        "# Hybrid classical+PQ (ONESHOT-MONEY T2, ActaSeal private repo): signature",
        "Must stay in lock-step with actaseal.anchoring._merkle_root",
        "TASK 1 (pin the shipped verifier)",
        "Lighter-weight sibling of offline_verifier.py",
        "see VERIFIER_SYNC.md",
    ]
    for sample in was:
        assert any(pattern.search(sample) for _label, pattern in SOURCE_PATTERNS), sample
