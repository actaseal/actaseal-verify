# AGENTS.md

Instructions for AI coding agents working in this repository.

## What this repo is

`actaseal-verify`: a standalone, zero-dependency-beyond-`cryptography`
offline verifier for ActaSeal dispute evidence packets. See
[llms.txt](llms.txt) for the machine-readable summary and
[README.md](README.md) for full human-facing docs.

## Hard constraints

- **`verify.py` must stay zero-import beyond the standard library plus
  `cryptography`.** No new dependency, ever, without a very deliberate
  reason -- this file's entire value proposition is "read it in one
  sitting, run it with almost nothing installed." See
  `tests/test_verify_demo_packet.py::test_verify_has_no_external_imports_beyond_cryptography`
  -- keep that test green.
- **Never fabricate a check.** If a field is underivable or a claim
  can't be verified, `verify.py` reports the gap explicitly (a named
  failure code) -- it never invents a passing result.
- **This file is the byte-pinned source of truth** for the private
  `actaseal-product` repo's `actaseal/dispute/offline_verifier.py`
  (see that repo's `VERIFIER_SYNC.md`). A change here that fixes a
  real bug should be synced there via that repo's
  `scripts/sync_public_verifier.py` -- do not assume this repo's
  changes propagate automatically.

## Before committing

- Run `pytest -q` (this repo's real, complete test suite -- unlike the
  private product repo, there is no broken-legacy-scaffold problem
  here to work around).
- Run `python verify.py demo/demo-packet-unanchored` and
  `python verify.py demo/demo-packet-anchored` -- both must PASS.
- If you touched `verify.py`, re-run the conformance suite
  (`conformance/`) against it.

## Style

- No comments explaining WHAT code does (names should do that) -- only
  WHY, when genuinely non-obvious (a workaround, a spec citation, a
  hidden invariant).
- Prefer editing existing files over creating new ones.
- Match this repo's existing tone in docs: honest about gaps and
  limitations, no marketing language, cite sources for any factual
  claim about a third party.
