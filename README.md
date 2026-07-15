# actaseal-verify

Verify an ActaSeal dispute evidence packet yourself, in about 60 seconds,
without installing ActaSeal, without a network call, and without trusting
us. This repo is one script (`verify.py`) plus a spec.

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

## Why "zero-import" is the whole point

`verify.py` has no dependency on ActaSeal's code, config, database, or
network access -- it is standalone by construction (see the assertion in
`tests/test_verify_demo_packet.py::test_verify_has_no_external_imports_beyond_cryptography`).
The only third-party package it needs is `cryptography`, for Ed25519/ECDSA
signature checks. That means:

- you can read the whole verifier in one sitting (~360 lines, no
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
generate_demo_packet.py      builds the two demo packets below, from scratch, standalone
demo/demo-packet-unanchored/ a valid packet with no settlement anchor
demo/demo-packet-anchored/   a valid packet with a payment-rail settlement anchor
SPEC.md                      packet format reference
tests/                       pytest suite: valid packets pass, tampered ones fail loudly
```

## License

Apache-2.0. See [LICENSE](LICENSE).

## Security

See [SECURITY.md](SECURITY.md) for how to report a vulnerability.
