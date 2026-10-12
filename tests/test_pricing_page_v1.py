"""The pricing page says what is sold and how to ask for a price. It does
not publish tiers, usage limits, discounts, or how the product is
configured, and it does not quote an amount that has not been decided."""
import html
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent
PAGE = ROOT / "pricing.html"


def _text() -> str:
    raw = PAGE.read_text(encoding="utf-8")
    raw = re.sub(r"<(script|style)\b.*?</\1>", " ", raw, flags=re.S)
    return re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", raw)))


def test_states_the_offer_in_one_line():
    text = _text()
    assert "Annual licence, self-hosted." in text
    assert "From <DECIDE:price> / year" in text
    assert "contact us" in text.lower()


def test_has_a_contact_button():
    raw = PAGE.read_text(encoding="utf-8")
    assert re.search(r'<a[^>]+class="[^"]*\bbutton\b[^"]*"[^>]+href="mailto:[^"]+@actaseal\.com', raw) or re.search(
        r'<a[^>]+href="mailto:[^"]+@actaseal\.com[^"]*"[^>]+class="[^"]*\bbutton\b', raw
    )


def test_quotes_no_amount():
    text = _text()
    assert not re.search(r"[$₹€£]\s?\d", text), "an amount is quoted"
    assert not re.search(r"\d[\d,]{3,}\s*(/|per)\s*year", text), "an amount is quoted"


def test_no_tiers_limits_or_discount_terms():
    low = _text().lower()
    for phrase in (
        "tier", "foundation", "enterprise", "archived engagements per year", "up to 25", "up to 150",
        "unlimited", "first references", "first three deployments", "reference", "inr",
    ):
        assert phrase not in low, f"pricing page still says {phrase!r}"


def test_no_configuration_internals():
    low = _text().lower()
    for phrase in ("environment variable", "configuration-file", "config file", "at startup"):
        assert phrase not in low, f"pricing page still says {phrase!r}"


def test_no_company_status_disclaimers():
    low = _text().lower()
    for phrase in ("soc 2", "soc 2", "no hosted service", "small vendor", "hosted uptime"):
        assert phrase not in low, f"pricing page still says {phrase!r}"


def test_still_says_the_verifier_is_open():
    text = _text()
    assert "Apache License 2.0" in text


def test_has_a_book_a_demo_action_that_is_a_plain_email_link():
    raw = PAGE.read_text(encoding="utf-8")
    link = re.search(r'<a[^>]+href="(mailto:[^"]+)"[^>]*>\s*Book a demo\s*</a>', raw)
    assert link, "no 'Book a demo' link"
    assert "@actaseal.com" in link.group(1)


def test_loads_nothing_from_a_third_party():
    raw = PAGE.read_text(encoding="utf-8")
    assert "<script" not in raw.lower()
    for url in re.findall(r'(?:src|href)="(https?://[^"]+)"', raw):
        host = url.split("/")[2]
        assert host in {"github.com"} or host.endswith("actaseal.com"), f"third-party reference: {url}"
