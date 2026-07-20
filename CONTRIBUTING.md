# Contributing

Thanks for considering a contribution to `actaseal-verify`, the
standalone, zero-dependency-beyond-`cryptography` offline verifier for
ActaSeal dispute evidence packets.

## Before you start

- **`verify.py` must stay zero-import beyond the standard library plus
  `cryptography`.** This is the whole point of the file -- see
  `tests/test_verify_demo_packet.py::test_verify_has_no_external_imports_beyond_cryptography`.
  A PR adding a new dependency to `verify.py` itself will not be
  merged; put new functionality in a separate script instead (see
  `verify_with_telemetry.py` for the pattern -- calls `verify.py`'s
  `main()` unchanged, adds behavior around it, never inside it).
- **Never fabricate a check.** If something can't be verified from the
  packet's own contents, report the gap with a named failure code --
  never invent a passing result.
- **`AGENTS.md`** has the same rules, phrased for AI coding agents --
  read it too if you're using one.

## Development setup

```bash
pip install cryptography pytest
pytest -q
python verify.py demo/demo-packet-unanchored   # must PASS
python verify.py demo/demo-packet-anchored     # must PASS
```

## Pull requests

- Keep the diff focused -- one concern per PR.
- Add a test for anything you change or add (this repo's whole test
  suite is real and fast; there's no "broken legacy scaffold" excuse
  to avoid here, unlike some larger codebases).
- Explain the WHY in your commit message, not just the what.

## Good first issues

1. **Add a `--json` output mode to `verify.py`.** Currently it prints
   human-readable text; a machine-readable `{"verified": bool,
   "failures": [...]}` JSON mode (behind a new flag, output format
   only, no new checks) would help CI/scripting consumers. Keep it
   zero-dependency (stdlib `json` only).
2. **Port one more `verify.py` check into `tamper_demo/verify_min.js`.**
   The JS port currently covers chain integrity + Ed25519 signature
   only (see `tamper_demo/README.npm.md` for the documented scope
   gap). Porting `verify_scope_conformance` next would be a good,
   bounded next step -- match `verify.py`'s exact logic, add a Node
   test case.
3. **Add a conformance vector for a torn/truncated `ledger_slice.ndjson`.**
   `conformance/` has vectors for various tampering; check whether a
   genuinely truncated (not just byte-flipped) final line is already
   covered, and add one if not.
4. **Document the exact CPython/`cryptography` version matrix this has
   been tested against**, and add that matrix to CI
   (`.github/workflows/ci.yml` already runs 3.9/3.11/3.12 -- confirm
   the actual minimum supported `cryptography` version and pin a floor
   in `requirements.txt` if it isn't already accurate).
5. **Write a `verify.py` usage guide for a specific real-world role**
   (e.g. "for an insurance claims adjuster," "for a chargeback analyst")
   -- the current README is accurate but general-audience; a
   role-specific walkthrough with a realistic example would lower the
   barrier for that audience specifically.

Comment on the corresponding GitHub issue (or open one referencing
this list) before starting, so two people don't duplicate work.
