# @actaseal/verify

A minimal, zero-dependency JS/WebCrypto port of ActaSeal's offline
dispute-packet verifier, extracted from the in-browser tamper-and-verify
demo. Runs in any environment with WebCrypto Ed25519 support (Node 19+,
current Chrome/Firefox/Safari) -- no bundled crypto library, no
external dependency at all.

## Scope -- read before relying on this for anything real

**This is a reduced-scope subset**, not a full port of the canonical
Python verifier (`verify.py` at the root of this repository). It checks:

- ledger chain integrity (`verifyEvents`)
- the receipt's **Ed25519** signature only (`verifyReceipt`) -- an
  ECDSA P-256-signed receipt is NOT checked by this package; a full
  verification of such a receipt needs the real `verify.py`.

It does **not** check authentication docs, scope-conformance,
settlement anchors, or continuity checkpoints -- see `verify.py`'s own
full check list for everything the canonical verifier covers that this
package does not.

**For anything beyond a quick, dependency-free sanity check, run the
real `verify.py` against the full packet.** This package exists for
environments where shelling out to Python isn't an option (a browser,
a Node-based CI step) and a reduced-scope client-side check is still
useful -- it is not a drop-in replacement for the canonical verifier.

## Install

```
npm install @actaseal/verify
```

## Usage

```js
const { verifyPacket } = require("@actaseal/verify");

const result = await verifyPacket(manifest, receipt, events);
// { verified: boolean, failures: string[] }
```

`manifest`, `receipt`, and `events` are the parsed JSON contents of a
dispute packet's `manifest.json`, `receipt.json`, and
`ledger_slice.ndjson` (one parsed object per line) respectively.

## License

Apache-2.0, same as the rest of this repository.
