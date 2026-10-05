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
  the same idea as the `verifier_sha256` pin inside every packet.
  `test_conformance.py::test_vectors_pin_file_matches_committed_vectors`
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
`vectors.sha256` together. Because `generate_demo_packet.build_packet()` mints
a fresh Ed25519 key on every run, regenerating always changes the exact
bytes of `valid/`, `tampered_payload/`, `tampered_chain/`,
`wrong_signature/`, and both `rotated_key_still_verifies/` sub-packets
(and therefore `vectors.sha256`) even with no logical change -- the pin
guards against *undetected* hand-edits between regenerations, not
byte-for-byte reproducibility across them. `generate_vectors.py` only
ever deletes/rebuilds these five named dispute-packet vector sets
(`DISPUTE_PACKET_VECTOR_NAMES`) -- it never touches `archive_attestation_v1/`
below.

## Archive-attestation vectors (`vectors/archive_attestation_v1/`)

A separate, hand-authored (not `generate_vectors.py`-generated) vector
set for `verify.py`'s two additive functions covering a DIFFERENT
artifact type -- an AS 1215 archive engagement's attestation, not a
money-action dispute packet: `verify_rfc3161_token` (a real,
pre-captured freetsa.org RFC 3161 TimeStampToken, pass/hash-mismatch/
no-trusted-root) and `verify_scitt_receipt` (a real SCITT/RFC 9943
Receipt from ActaSeal's transparency service,
pass/tampered-leaf). `freetsa_root_ca.pem` and `unrelated_root_ca.pem`
ship alongside so the vectors are self-contained. Covered by
`test_archive_attestation_conformance.py`, not `test_conformance.py`
(the RFC 3161 vectors additionally require `pip install actaseal[rfc3161]`
for `asn1crypto`; the SCITT-receipt vectors need only `cryptography`).
Included in `vectors.sha256`'s pin like everything else under `vectors/`.

## Receipt-checkpoint vectors (`vectors/receipt_checkpoint/`)

Three vectors for `verify_receipt.py`'s `--checkpoint` keyless/hash-linked mode
(`signature_verified/`, `key_unknown/`, `tampered/`), generated by
`generate_vectors.py`'s `build_receipt_checkpoint_*` functions. Each
`expected.json` carries `exit_code`, `mode` (`SIGNATURE_VERIFIED` /
`CHAIN_VERIFIED_KEY_UNKNOWN` / `FAIL`), and `must_include_substrings`. Covered by
`test_receipt_checkpoint_conformance.py`, which also asserts the three modes are
pairwise distinct.

## SCITT structured-result vectors (`vectors/receipt_scitt_result/`)

Five vectors for `verify_receipt.py`'s `--emit-result` / `--trust-material-complete`
flags (see the top-level `README.md`'s "Verify a single receipt" section for what
these mean, including the full `outcome`/`exit_code`/`failed_checks` field set),
generated by `generate_vectors.py`'s `build_scitt_*` functions:

| Vector | Covers |
|---|---|
| `default_not_evaluated/` | No key, a resolving `--checkpoint`, `--trust-material-complete` NOT given -> `NOT_EVALUATED` / `ACCEPTED` / outcome `ACCEPTED`. |
| `declared_complete_refused/` | Same artifact and checkpoint as above, only the flag differs -> `NOT_EVALUATED` / `REFUSED_BY_POLICY` / outcome `REJECTED`. |
| `empty_trust_refused/` | No key, no checkpoint, flag given anyway -> `NOT_EVALUATED` / `REFUSED_BY_POLICY`, explicitly not `CRYPTOGRAPHICALLY_INVALID`; `failed_checks: ["malformed_input"]` (receipt_public_key_hex is still required with no --checkpoint). |
| `signature_invalid/{default,declared_complete}/` | A genuinely tampered signature -> `CRYPTOGRAPHICALLY_INVALID` / `ACCEPTED` / outcome `REJECTED` under both flag values. |
| `valid_signature_broken_chain/` | A genuinely VALID signature over a tampered `ledger_slice` (no `--checkpoint`) -> `verdict: CRYPTOGRAPHICALLY_VALID` but `outcome: REJECTED`, `exit_code: 1`, `failed_checks: ["legacy_chain"]` -- the case that motivated adding these three fields: `verdict` alone is not safe to read as acceptability. |

Each vector directory carries `input.json` (the document), `meta.json` (the
`--checkpoint` / `--trust-material-complete` values to invoke `verify_receipt.py`
with), and `expected_result.json` (the exit code and the exact `--emit-result`
JSON object `verify_receipt.py` must reproduce) -- the expected result is captured
from a real subprocess run of `verify_receipt.py` at generation time
(`generate_vectors.py`'s `_run_verify_receipt_emit_result`), not hand-computed, so
a regression in the decision logic is caught at regeneration time too. Covered by
`test_receipt_scitt_result_conformance.py`.
