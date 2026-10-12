"""How to install this and how to cite it, kept true.

The package is on PyPI under its own name, so the README says so. The
citation file says what the Zenodo metadata says. The DOI shown is the
concept DOI, which always resolves to the latest archived version, so it
does not go stale with each release.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
CONCEPT_DOI = "10.5281/zenodo.23309307"
README = (ROOT / "README.md").read_text(encoding="utf-8")


def test_readme_installs_from_pypi_by_name():
    assert "pip install actaseal-verify" in README
    assert "pip install ." not in README


def test_badge_and_citation_use_the_concept_doi():
    badge = re.search(r"\[!\[DOI\]\((\S+)\)\]\((\S+)\)", README)
    assert badge and CONCEPT_DOI in badge.group(1) and badge.group(2) == f"https://doi.org/{CONCEPT_DOI}"
    assert f"https://doi.org/{CONCEPT_DOI}" in README.split("## Citation", 1)[1]
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert f'DOI = "https://doi.org/{CONCEPT_DOI}"' in pyproject


def test_citation_file_matches_the_zenodo_metadata():
    yaml = pytest.importorskip("yaml")
    cff = yaml.safe_load((ROOT / "CITATION.cff").read_text(encoding="utf-8"))
    zenodo = json.loads((ROOT / ".zenodo.json").read_text(encoding="utf-8"))
    creator = zenodo["creators"][0]
    family, given = [part.strip() for part in creator["name"].split(",")]
    (author,) = cff["authors"]
    assert (author["family-names"], author["given-names"]) == (family, given) == ("Goshi", "Xavier")
    assert author["orcid"] == f"https://orcid.org/{creator['orcid']}" == "https://orcid.org/0009-0006-0583-6968"
    assert author["affiliation"] == creator["affiliation"]
    assert cff["title"] == zenodo["title"]
    assert cff["license"] == zenodo["license"] == "Apache-2.0"
    assert cff["type"] == "software" == zenodo["upload_type"]
    assert cff["doi"] == CONCEPT_DOI
    assert cff["cff-version"] == "1.2.0" and cff["message"]
    assert sorted(cff["keywords"]) == sorted(zenodo["keywords"])
    assert cff["repository-code"] == "https://github.com/actaseal/actaseal-verify"
    related = zenodo["related_identifiers"][0]["identifier"]
    assert any(ref.get("url") == related for ref in cff["references"])


def test_citation_file_claims_no_release_that_has_not_happened():
    yaml = pytest.importorskip("yaml")
    cff = yaml.safe_load((ROOT / "CITATION.cff").read_text(encoding="utf-8"))
    # The concept DOI covers every version; a version and a release date
    # here would have to be edited at each release and would be wrong
    # between a commit and its publication.
    assert "version" not in cff and "date-released" not in cff
