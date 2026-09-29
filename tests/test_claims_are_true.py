"""Every public page's factual claims, checked against reality.

Any claim that can drift MUST get a test here. If you cannot write the
test, you may not make the claim.
"""
import pathlib, re, subprocess
ROOT = pathlib.Path(__file__).resolve().parent.parent
PRODUCT = pathlib.Path.home()/"a/active_code"
PUBLIC = ["README.md","llms.txt","docs/whitepaper.md","index.html","comparison.html",
          "graveyard.html","pricing.html","spec_freeze.html"]
def texts():
    return {f:(ROOT/f).read_text(encoding="utf-8") for f in PUBLIC if (ROOT/f).exists()}

def test_verify_py_line_count_claims_match_reality():
    actual = len((ROOT/"verify.py").read_text(encoding="utf-8").splitlines())
    for f,t in texts().items():
        for n in re.findall(r"~?([\d,]{3,6})\s+lines", t):
            claimed = int(n.replace(",",""))
            assert abs(claimed-actual) <= actual*0.05, f"{f}: claims {claimed} lines, actual {actual}"

def test_no_private_repo_citations():
    for f,t in texts().items():
        assert "private repo" not in t.lower(), f"{f}: cites a repo nobody can open"

def test_no_unwired_capability_words():
    # ops/continuity_monitor.py: periodic check + alerting were never wired.
    for f,t in texts().items():
        for w in ("alerting","real-time monitoring","continuous monitoring","unphishable","WYSIWYS"):
            assert w.lower() not in t.lower(), f"{f}: claims '{w}', which is not implemented"

def test_shipped_verifier_is_this_file():
    other = PRODUCT/"actaseal/dispute/offline_verifier.py"
    if other.exists():
        assert (ROOT/"verify.py").read_bytes()==other.read_bytes(), \
            "verify.py has drifted from the shipped offline_verifier.py"

def test_no_hash_pin_claim_without_a_hash_pin():
    pinned = "verifier_sha256" in (ROOT/"verify.py").read_text(encoding="utf-8")
    for f,t in texts().items():
        if not pinned:
            assert "hash-pinned" not in t, f"{f}: claims hash-pinning that does not exist"

def _selector_source():
    p = PRODUCT/"actaseal/api/server.py"
    return p.read_text(encoding="utf-8") if p.exists() else None

def test_priced_key_custody_is_actually_selectable_at_boot():
    """pricing.html sells AWS KMS custody as included. It must be a real
    boot option, not an unwired module."""
    src = _selector_source()
    page = (ROOT/"pricing.html")
    if src is None or not page.exists():
        return
    t = page.read_text(encoding="utf-8")
    if "AWS KMS" in t:
        assert 'SIGNER_AWS_KMS = "aws_kms"' in src, \
            "pricing.html sells AWS KMS custody but the bootstrap has no aws_kms backend"

def test_not_yet_selectable_list_is_still_not_selectable():
    """The 'implemented but not selectable at boot' disclosure must stop
    being a disclosure the moment those backends get wired -- otherwise the
    page understates what the buyer is paying for."""
    src = _selector_source()
    page = (ROOT/"pricing.html")
    if src is None or not page.exists():
        return
    t = page.read_text(encoding="utf-8")
    if "not yet selectable at boot" not in t.lower():
        return
    for token, label in (('"vault_transit"', "Vault Transit"),
                         ('"ml_dsa_65"', "ML-DSA-65"),
                         ('"hybrid_ed25519_ml_dsa_65"', "hybrid Ed25519 + ML-DSA-65")):
        if token in src:
            assert label not in t, (
                f"{label} is now selectable at boot; remove it from the "
                "'not yet selectable' disclosure in pricing.html and price it")

def test_no_soc2_certification_claim():
    for f,t in texts().items():
        low = t.lower()
        for phrase in ("soc 2 certified","soc 2 compliant","soc2 certified",
                       "soc 2 type ii report available","soc 2 attested"):
            assert phrase not in low, f"{f}: claims {phrase!r}, which is not true"
