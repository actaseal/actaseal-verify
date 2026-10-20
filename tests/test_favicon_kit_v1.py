"""H14 (ONE-SHOT 6B): the pages carry the small-icon kit whose hash is drawn in paper colour, so it shows on a dark tab."""
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent
PAGES = ["index.html", "spec_freeze.html", "browser/index.html"]
LINES = (
    '<link rel="icon" href="/favicon.ico" sizes="any">',
    '<link rel="icon" href="/brand/actaseal-favicon-oxblood.svg" type="image/svg+xml">',
    '<link rel="apple-touch-icon" href="/apple-touch-icon.png">',
)


def test_every_page_names_the_three_icons_once_and_the_files_exist():
    for page in PAGES:
        text = (ROOT / page).read_text(encoding="utf-8")
        for line in LINES:
            assert text.count(line) == 1, f"{page}: {line}"
    for name in ("favicon.ico", "apple-touch-icon.png", "brand/actaseal-favicon-oxblood.svg"):
        assert (ROOT / name).is_file(), name


def test_the_svg_icon_draws_the_hash_in_paper_colour():
    assert "#f4efe6" in (ROOT / "brand/actaseal-favicon-oxblood.svg").read_text(encoding="utf-8").lower()


def test_the_icon_files_are_real_images():
    assert (ROOT / "apple-touch-icon.png").read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"
    assert (ROOT / "favicon.ico").read_bytes()[:4] == b"\x00\x00\x01\x00"
