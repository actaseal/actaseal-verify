# actaseal-verify

Verify an ActaSeal dispute evidence packet yourself, in about 60 seconds,
without installing ActaSeal, without a network call, and without trusting
us. This repo is one script (`verify.py`) plus a spec. A second script,
`verify_seal.py`, does the same for sealed files (see below).

Who this is for: an underwriter, dispute analyst, or auditor who has been
handed a packet (a `.zip`) and wants to check, independently, that:

- the evidence chain hasn't been tampered with (every event's hash
  recomputes from its own recorded content, and the chain is unbroken);
- the receipt's signature is genuinely valid over that chain;
- the chain-of-custody and acquisition documents (the FRE 901/902 basis
  for admissibility) are present and internally consistent;
- if the packet claims a payment-rail settlement anchor, that anchor's
  hash actually recomputes from its declared content.

## Verify a packet in 60 seconds

```bash
pip install cryptography     # the only third-party dependency
unzip your-packet.zip -d packet
python verify.py packet
```

(Or `pip install .` from this repo, then `python -m verify packet`.)

Exit code `0` and `VERIFIED: ...` means every check above passed. Exit
code `1` prints exactly which check failed and why -- nothing is silently
waved through. Exit code `2` means `cryptography` isn't installed (no
partial/soft-pass is possible).

Try it right now against the demo packets checked into this repo:

```bash
python verify.py demo/demo-packet-unanchored
python verify.py demo/demo-packet-anchored   # includes a rail settlement anchor
```

Or try it entirely in your browser, no install: **[tamper_demo/](tamper_demo/index.html)**
loads a real signed packet, lets you edit any field, and re-verifies live as you type --
break the hash chain or the signature and watch it turn red immediately. Nothing is sent
anywhere; it's a JS port of the same checks (`tamper_demo/verify_min.js`), using the
browser's native WebCrypto Ed25519 support.

To check your **own** packet without installing anything, open
**[browser/](browser/index.html)**: it runs this repo's `verify.py`,
unmodified, in the browser via [Pyodide](https://pyodide.org) (Python
compiled to WebAssembly), with the same flags (`--sth-public-key`,
`--tsa-ca-cert`, `--anchors`), output and exit code as the CLI. The packet
is read locally and not uploaded. The page shows the SHA-256 of the
`verify.py` it ran so you can compare it with your own copy. The runtime
(Pyodide 314.0.7 plus `cryptography`, ~16 MB) is served from this site and
reproduced byte for byte by `scripts/fetch_browser_runtime.py`, which checks
every file against a pinned hash.

## Use it in CI

`action.yml` in this repository is a reusable GitHub Action:

```yaml
- uses: actaseal/actaseal-verify@main
  with:
    packet-dir: ./extracted-packet
    # anchors: ./anchors.jsonl   # optional
```

Fails the step (non-zero exit) if the packet doesn't verify.

## Use it from Node / a browser

`@actaseal/verify` (`tamper_demo/`, `npm install @actaseal/verify`) is a
minimal, zero-dependency WebCrypto port covering chain integrity and
Ed25519 receipt signatures only -- see `tamper_demo/README.npm.md` for
its exact (reduced) scope before relying on it for anything beyond a
quick client-side check. The real `verify.py` above is the canonical,
full-scope verifier.

## Verify sealed files (logs, an evidence pack)

ActaSeal can also seal a set of files -- application logs, an evidence pack, an
audit submission -- once or daily. `verify_seal.py` checks such a seal yourself,
offline:

```bash
pip install cryptography asn1crypto   # asn1crypto only for the RFC 3161 timestamp
python verify_seal.py seal-2026-10-05.json --base /path/to/the/files \
    --previous seal-2026-10-04.json --public-key <the sealer's public key> \
    --tsa-ca <timestamp authority CA>.pem --require-timestamp
```

It checks that every sealed file is byte-for-byte unchanged, that the seal itself
was not edited, the Ed25519 signature and that it is by the key you expect, the
link to the previous seal (a dropped or rewritten day breaks it), and the RFC 3161
timestamp over the seal. Exit code `0` and `VERIFIED` means all passed; `1` lists
each failed check; `2` means it could not run.

- Without `--public-key`, a valid signature only shows the seal is self-consistent:
  anyone can re-seal changed files with their own key. Get the key from the sealer
  through a separate channel.
- The timestamp's certificate must chain to a CA you pass with `--tsa-ca`, or to
  freeTSA's root (embedded, SHA-256 pinned) for seals timestamped by freeTSA; never
  to a CA named inside the seal. `--skip-timestamp` checks everything else.
- Only the files a seal lists are checked; files added later are not reported. A
  seal shows files did not change after sealing, not that they were correct then.

`conformance/vectors/file_seal_v1/` holds seals ActaSeal wrote and the results it
reported; the tests check this script gives the same.

## Verify a single receipt

`verify.py` checks a full dispute packet (a directory). If you only have a single
receipt JSON -- pasted from an email, attached to a chargeback response -- use the
lighter-weight `verify_receipt.py` instead:

```bash
pip install cryptography
python verify_receipt.py receipt_document.json
```

It also supports a keyless/hash-linked mode (`--checkpoint <hex>`, for when the
signing key is rotated or unknown but a trusted ledger checkpoint hash is
available out of band) and two flags for machine-readable, SCITT-aligned output:

- `--emit-result` additionally prints one line of JSON, schema
  `actaseal-verify-result.v1`, with eight fields, always present:
  - `verdict` (`CRYPTOGRAPHICALLY_VALID` / `CRYPTOGRAPHICALLY_INVALID` /
    `NOT_EVALUATED`) -- describes *only* the cryptographic outcome.
  - `disposition` (`ACCEPTED` / `REFUSED_BY_POLICY`) -- what a relying party
    should do about the trust-material situation (see below); never a crypto
    outcome.
  - `outcome` (`ACCEPTED` / `REJECTED`) -- the exit code's meaning, spelled
    out: `ACCEPTED` iff `exit_code` is `0`, `REJECTED` otherwise. No third
    value.
  - `exit_code` -- the actual integer this process is about to return (`0`
    PASS, `1` FAIL, `2` malformed input / can't run).
  - `failed_checks` -- an array of check identifiers
    (`signature`/`checkpoint`/`legacy_chain`/`validation_material`) with
    status `"failed"`; `["malformed_input"]` for an exit-2 branch where no
    check ever ran; `["archive_attestation"]` for a failed archive-attestation
    document; `[]` when nothing failed.
  - `trust_material_complete` (see below).
  - `integrity_protection` (always `"none"` -- see below).
  - `checks` -- the structured, per-check detail behind `failed_checks`.
  Without this flag, output and exit codes are unchanged from before this
  flag existed.

  **Read the full result, not `verdict` alone.** `verdict` is the pure
  cryptographic fact and nothing else: a receipt with a genuinely valid
  signature but a separately broken `ledger_slice` reports `verdict:
  CRYPTOGRAPHICALLY_VALID` -- the signature math really did pass -- while
  `outcome: REJECTED`, `exit_code: 1`, and `failed_checks: ["legacy_chain"]`
  say, correctly, that this receipt must not be accepted. A consumer that
  reads `verdict` alone and treats "VALID" as "accept it" gets this one
  wrong; `outcome`/`exit_code`/`failed_checks` exist specifically so that
  mistake isn't necessary.
- `--trust-material-complete` is a relying-party declaration (boolean, **default
  `false`**) that the trust material you supplied -- a `receipt_public_key_hex`,
  or none -- is a *complete* account of the keys you are willing to trust, not
  merely "I didn't supply one." Omitting the flag is never read as a declaration
  of completeness.

The interesting case is an unresolvable signing key (no `receipt_public_key_hex`,
verified instead via `--checkpoint`'s hash-linkage -- `CHAIN_VERIFIED_KEY_UNKNOWN`
in the human-readable output above, unchanged):

| `--trust-material-complete` | verdict | disposition |
|---|---|---|
| not given (default) | `NOT_EVALUATED` | `ACCEPTED` -- the check could not run; nothing was refused |
| given | `NOT_EVALUATED` | `REFUSED_BY_POLICY` -- the key is declared outside your trust boundary |
| given, with *no* key or checkpoint at all | `NOT_EVALUATED` | `REFUSED_BY_POLICY` -- same shape as above, not a crypto failure |

A signature that genuinely runs and fails is always `CRYPTOGRAPHICALLY_INVALID` /
`ACCEPTED`, regardless of `--trust-material-complete` -- an established failure is
never softened by a completeness declaration.

**`integrity_protection` is honestly `"none"`.** `verify_receipt.py` is a
standalone, offline script with no separately trusted verifier identity of its
own -- signing its own output would bind that signature to nothing a relying
party could anchor trust in. Whatever consumption-side completeness obligation
your own policy imposes on *you*, the relying party reading this result, does not
apply to `verify_receipt.py` itself as the emitter: it reports what it found and
declares, honestly, that the result travels with no integrity protection of its
own -- transport and storage integrity for the emitted JSON is your
responsibility, same as for any other unsigned tool output.

`conformance/vectors/receipt_scitt_result/` pins five input/result pairs covering
the table above, plus the valid-signature-broken-chain case just described; see
`conformance/README.md`.

## Telemetry: opt-in, count-only, off by default, NOT in verify.py itself

`verify.py` makes zero network calls, period -- that's a real,
tested guarantee (`tests/test_verify_demo_packet.py::
test_verify_has_no_external_imports_beyond_cryptography`), not a
default that can be toggled. Telemetry lives entirely in a separate,
optional wrapper instead: `verify_with_telemetry.py` calls `verify.py`'s
own `main()` completely unchanged, and only after that call returns
does it (optionally) send a ping -- `verify.py` itself never imports
`urllib` or knows telemetry exists.

```bash
python verify_with_telemetry.py --telemetry <packet_dir>
```

Even with `--telemetry` passed, the wrapper ships with
`TELEMETRY_ENDPOINT` set to an empty string, so it's currently an inert
no-op regardless -- nothing is transmitted until a maintainer
deliberately sets a real endpoint in a future release. When/if that
happens, a ping sends exactly three fields: the wrapper's own version
string, the verification outcome (`PASS`/`FAIL`), and a failure count
(derived by counting verify.py's own printed failure lines, never by
inspecting packet content) -- never a filename, never anything about
the specific receipt or ledger being verified. Best-effort only: any
network failure is silently swallowed and never affects the exit code
or printed result, which are always exactly what plain `python verify.py`
would have produced.

## Why "zero-import" is the whole point

`verify.py` has no dependency on ActaSeal's code, config, database, or
network access -- it is standalone by construction (see the assertion in
`tests/test_verify_demo_packet.py::test_verify_has_no_external_imports_beyond_cryptography`).
The only third-party package it needs is `cryptography`, for Ed25519/ECDSA
signature checks. That means:

- you can read the whole verifier in one sitting (~1,550 lines, no
  framework, no magic) and know exactly what it checks;
- you never run vendor code against your own systems to check evidence
  someone handed you -- it only reads files from the packet directory;
- the packet embeds its own trust root (`manifest.json`'s
  `receipt_public_key_hex`) -- verification needs no external key file,
  registry, or live service lookup. You separately compare that key
  against the operator's published key out of band; the packet cannot
  forge that comparison, only be internally consistent or not.

This is the file that ships inside every real ActaSeal dispute packet as
`verify.py` -- what you're running here is not a simplified demo version,
it's the literal artifact.

## What "VERIFIED" actually means

Passing does not mean "ActaSeal says this is fine." It means every one of
these independently re-derives from data already inside the packet:

1. **Ledger chain integrity** -- each event's `payload_hash`, `event_id`,
   and `event_hash` recompute from that event's own fields; the slice is
   an unbroken hash chain from the manifest's declared starting point.
2. **Receipt signature** -- the receipt's Ed25519/ECDSA signature verifies
   against `manifest.json`'s embedded public key, over the canonical JSON
   of the receipt (minus the signature field itself).
3. **Receipt-to-chain binding** -- the receipt's `ledger_entry_hash` names
   a real event in the slice, for the same action, and that event's
   recorded action hash matches the receipt's.
4. **Chain-of-custody / acquisition basis (FRE 901(b)(9), 902(13)-(14))**
   -- the acquisition report names its tool, clock source, and custodian;
   custody events are time-ordered and each bound to a real ledger event
   hash; the authentication statement's key id, pubkey hash, and mandate
   hash match the receipt.
5. **Scope conformance** -- if the receipt claims an in-scope or breach
   verdict, that verdict traces back to a `ScopeEvaluated` ledger event
   whose recorded scope/action hashes recompute correctly.
6. **Settlement anchor** -- if the packet claims a payment-rail
   settlement anchor, its `anchor_hash` recomputes from the anchor
   content; an unanchored packet says so explicitly (never silent).

See [`SPEC.md`](SPEC.md) for the full packet format.

## What this does *not* verify

- That the underlying transaction/refund/decision was *correct* -- only
  that the recorded evidence is internally consistent and unaltered.
- That `receipt_public_key_hex` belongs to the operator you think it
  does -- that binding is on you, out of band (e.g. compare against a
  key the operator has published elsewhere).
- Anything about a deployment you haven't been handed a packet from.

## Repo layout

```
verify.py                    the verifier -- the only file that matters at verify time
verify_seal.py               verifier for sealed files (logs, evidence packs)
generate_demo_packet.py      builds the two demo packets below, from scratch, standalone
demo/demo-packet-unanchored/ a valid packet with no settlement anchor
demo/demo-packet-anchored/   a valid packet with a payment-rail settlement anchor
tamper_demo/                 in-browser, editable, live-verifying demo (see above)
SPEC.md                      packet format reference
tests/                       pytest suite: valid packets pass, tampered ones fail loudly
```

## License

Apache-2.0. See [LICENSE](LICENSE).

## Security

See [SECURITY.md](SECURITY.md) for how to report a vulnerability.
