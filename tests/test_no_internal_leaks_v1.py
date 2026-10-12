"""Nothing a visitor reads in this repository's public pages describes how
the licensed product is built, sold or staffed. Outcomes only.

This repository is public, so its own files may be named: a path or a
.py file is a finding only when it does not exist here. Checked on the
visible text of every page and on the prose documents a visitor is
pointed at.

Not covered, and known: the verifier's own source file carries comments
and a help text that name files of the licensed product. That file's
bytes are pinned by digest in issued packets and in release artifacts,
so it is changed only in a deliberate verifier release, not here.
"""
import html
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
TRACKED = set(subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True).stdout.split())
TRACKED_NAMES = {Path(p).name for p in TRACKED}
PROSE = ["README.md", "llms.txt", "docs/whitepaper.md", "SPEC.md", "SECURITY.md"]

PATTERNS = [
    ("internal document", re.compile(r"CLAUDE\.md|README-DEPLOY|USER_ACTIONS|STATE\.md|KNOWN_FAILURES|CAPABILITIES\.md|VERIFIER_SYNC", re.I)),
    ("private repository", re.compile(r"private (actaseal )?repo", re.I)),
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
        "score or percentage": "a 97% match",
    }
    for label, sample in samples.items():
        assert dict(PATTERNS)[label].search(sample), label
    assert _exists_here("verify.py") and not _exists_here("actaseal/dispute/verifier_gate.py")
