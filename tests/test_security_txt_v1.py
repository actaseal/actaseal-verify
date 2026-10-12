"""/.well-known/security.txt on this site: one contact, the security
address, and an expiry that has not passed (RFC 9116). .nojekyll must be
present or the host does not serve the directory at all."""
from __future__ import annotations

import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LINES = (ROOT / ".well-known" / "security.txt").read_text(encoding="utf-8").splitlines()


def _values(field: str) -> list[str]:
    return [line.split(":", 1)[1].strip() for line in LINES if line.startswith(field + ":")]


def test_contact_is_the_security_address_only():
    assert _values("Contact") == ["mailto:security@actaseal.com"]


def test_expires_is_present_once_and_in_the_future():
    (expires,) = _values("Expires")
    when = datetime.datetime.fromisoformat(expires.replace("Z", "+00:00"))
    assert when > datetime.datetime.now(datetime.timezone.utc), "security.txt has expired"


def test_canonical_names_this_host_and_the_directory_is_served():
    assert _values("Canonical") == ["https://verify.actaseal.com/.well-known/security.txt"]
    assert (ROOT / "CNAME").read_text(encoding="utf-8").strip() == "verify.actaseal.com"
    assert (ROOT / ".nojekyll").is_file()
