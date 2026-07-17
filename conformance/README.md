# ActaSeal offline-verifier conformance suite

Precedent for this shape of thing: Sigstore and Certificate Transparency
both publish conformance test vectors so a third party can check a
*re-implementation* of the verifier, not just trust ours. This directory
does the same for `verify.py` (the offline dispute-packet verifier at
the root of this repo).

## What's here

- `vectors/` -- five fixed test-vector packets, each a self-contained
  dispute packet directory (`manifest.json`, `receipt.json`,
  `ledger_slice.ndjson`, `acquisition.json`, `custody.json`,
  `authentication.json`) plus an `expected.json` stating the verdict
  `verify.py` must produce against it.
- `generate_vectors.py` -- regenerates every vector from
  `generate_demo_packet.build_packet()` (the same dependency-free
  packet builder the top-level demo packets use). Tampered vectors take
  a freshly built valid packet and mutate exactly one field with a
  plain JSON/string edit -- never by calling into signing code.
- `vectors.sha256` -- a content pin over every file under `vectors/`,
  the same idea as `../offline_verifier.sha256` pinning the synced
  verifier. `test_conformance.py::test_vectors_pin_file_matches_committed_vectors`
  fails if a vector was hand-edited without being regenerated and
  re-pinned through `generate_vectors.py`.
- `test_conformance.py` -- a pytest runner that feeds each vector
  through `verify.py` as a subprocess and asserts exit code + which
  failure codes appear in its output.

## The vectors

| Vector | What it proves |
|---|---|
| `valid/` | A well-formed packet, no tampering, verifies cleanly end to end (hash chain, receipt signature, authentication docs, scope conformance, settlement anchor). |
| `tampered_payload/` | Editing one ledger event's `payload` after the fact fails `PAYLOAD_HASH_MISMATCH` recomputation, cascading into `EVENT_ID_MISMATCH` / `EVENT_HASH_MISMATCH` for that event. |
| `tampered_chain/` | Rewriting one event's `previous_event_hash` to point elsewhere fails `CHAIN_BROKEN`, even though every individual event is still internally self-consistent. |
| `wrong_signature/` | Flipping one hex character of the receipt's `signature` fails Ed25519 verification (`RECEIPT_SIGNATURE_INVALID`) against the manifest's pinned public key. |
| `rotated_key_still_verifies/` | Two independently-keyed packets (`issued_before_rotation/`, `issued_after_rotation/`) each verify on their own terms, because `verify.py`'s trust root is each packet's *own* `manifest.json` key, not one hardcoded key -- rotating the operator's live signing key never invalidates receipts issued under the key that was live when they were signed. |

`expected.json` in each vector directory is machine-readable: `verified`
(bool), `exit_code` (int), and for failing vectors,
`must_include_failure_substrings` (a list of failure-code substrings
that must appear in `verify.py`'s stdout).

## Running the suite

```
pip install -r requirements-dev.txt   # or just: pip install cryptography pytest
python -m pytest conformance/
```

## Checking your own verifier against these vectors

If you're re-implementing this verifier from `SPEC.md` rather than
reusing `verify.py` directly, the contract to satisfy is:

1. For each vector directory under `vectors/` other than
   `rotated_key_still_verifies/`, read `expected.json` and confirm your
   implementation reaches the same `verified`/`exit_code` result.
2. For `rotated_key_still_verifies/`, run your verifier separately
   against `issued_before_rotation/` and `issued_after_rotation/` --
   both must independently verify, each against the public key recorded
   in *its own* `manifest.json`.
3. You do not need to match `verify.py`'s exact failure-code strings --
   those are this implementation's diagnostic detail, not part of the
   packet format contract. What matters is reaching the same
   verified/not-verified verdict for the same reason category (a
   tampered payload, a broken chain link, a bad signature).

## Regenerating vectors

```
python conformance/generate_vectors.py
```

Review the diff under `vectors/`, then commit `vectors/` and
`vectors.sha256` together -- same workflow as
`../scripts/sync_public_verifier.py` re-pinning `offline_verifier.sha256`
in the private repo. Because `generate_demo_packet.build_packet()` mints
a fresh Ed25519 key on every run, regenerating always changes the exact
bytes of `valid/`, `tampered_payload/`, `tampered_chain/`,
`wrong_signature/`, and both `rotated_key_still_verifies/` sub-packets
(and therefore `vectors.sha256`) even with no logical change -- the pin
guards against *undetected* hand-edits between regenerations, not
byte-for-byte reproducibility across them.
