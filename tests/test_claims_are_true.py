"""Every public page's factual claims, checked against reality.

Any claim that can drift MUST get a test here. If you cannot write the
test, you may not make the claim.
"""
import pathlib, re, subprocess
ROOT = pathlib.Path(__file__).resolve().parent.parent
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
    other = pathlib.Path.home()/"a/active_code/actaseal/dispute/offline_verifier.py"
    if other.exists():
        assert (ROOT/"verify.py").read_bytes()==other.read_bytes(), \
            "verify.py has drifted from the shipped offline_verifier.py"

def test_no_hash_pin_claim_without_a_hash_pin():
    pinned = "verifier_sha256" in (ROOT/"verify.py").read_text(encoding="utf-8")
    for f,t in texts().items():
        if not pinned:
            assert "hash-pinned" not in t, f"{f}: claims hash-pinning that does not exist"
