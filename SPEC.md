# ActaSeal dispute packet format (`dispute_packet.v1`)

A packet is a directory (or zip of that directory) containing exactly
these members:

| File | Purpose |
|---|---|
| `manifest.json` | Trust root, action identity, chain-start pointer, headline claims |
| `receipt.json` | The signed policy decision receipt |
| `ledger_slice.ndjson` | The contiguous hash-chained ledger events for this action, one JSON object per line |
| `acquisition.json` | How/when/by-what-tool the packet was exported (FRE 901(b)(9) basis) |
| `custody.json` | Time-ordered chain-of-custody events, each bound to a ledger event hash |
| `authentication.json` | Self-authentication statement (FRE 902(13)-(14) basis) |
| `verify.py` | Literal copy of this repo's verifier -- always ships inside the packet |

All JSON in this spec is canonicalized the same way everywhere it's
hashed: `json.dumps(value, sort_keys=True, separators=(",", ":"),
ensure_ascii=False, allow_nan=False)`, then SHA-256 over the UTF-8 bytes.
Every hash referenced below (`payload_hash`, `event_id`, `event_hash`,
`anchor_hash`, `scope_hash`, `action_hash`) is computed exactly this way.
This is why the packet is offline-verifiable: nothing requires a live
service to recompute.

## `manifest.json`

```jsonc
{
  "schema_version": "dispute_packet.v1",
  "action_id": "refund-demo-001",
  "receipt_public_key_hex": "...",      // trust root -- compare out of band
  "event_count": 3,                      // must equal len(ledger_slice.ndjson)
  "chain_start_previous_event_hash": null,  // must equal events[0].previous_event_hash
  "scope_conformance_headline": "in_scope", // "in_scope" | "BREACH:<dims>" | "not_evaluated"
  "settlement_anchor": {
    "status": "SETTLEMENT_UNANCHORED"    // or "anchored" (see below) -- never omitted
  }
}
```

An anchored `settlement_anchor` block instead looks like:

```jsonc
"settlement_anchor": {
  "status": "anchored",
  "anchor": { /* arbitrary rail-specific content, e.g. rail id, anchor id, timestamp, mandate_hash */ },
  "anchor_hash": "sha256(canonical(anchor))"
}
```

## `ledger_slice.ndjson`

One JSON object per line, each with these fields:

```
event_type, tenant_id, workspace_id, actor_id, action_id, action_type,
timestamp, schema_version, payload, payload_hash, previous_event_hash,
event_id, event_hash
```

Derivation (must hold for every event):

```
material = {the 11 fields above except event_id, event_hash}
payload_hash   == sha256(canonical(payload))
event_id       == sha256(canonical({**material, "event_id_basis": "ledger_event_id.v1"}))
event_hash     == sha256(canonical({**material, "event_id": event_id}))
events[0].previous_event_hash == manifest.chain_start_previous_event_hash
events[i>0].previous_event_hash == events[i-1].event_hash
```

The slice must contain at least one event whose `action_id` matches
`manifest.action_id`.

Two event types carry meaning beyond the generic chain check:

- **Any event whose `event_hash` equals `receipt.ledger_entry_hash`**
  is the event the receipt is bound to. If its `payload.action_packet_hash`
  is present, it must equal `receipt.action_hash`, and its `action_id`
  must equal `manifest.action_id`.
- **`ScopeEvaluated`** events carry `payload = {verdict, breach_dimensions,
  intent_scope, executed_action, scope_hash, action_hash}`, where
  `scope_hash == sha256(canonical(intent_scope))` and
  `action_hash == sha256(canonical(executed_action))`.

## `receipt.json`

```jsonc
{
  "decision": "ALLOW",                 // or BLOCK / APPROVAL_REQUIRED / etc
  "reason_code": "APPROVAL_GRANTED",
  "action_hash": "...",
  "evidence_set_hash": "...",
  "ledger_entry_hash": "...",          // must name a real event, see above
  "timestamp": "...",
  "algorithm": "ed25519",              // or "ecdsa-p256-sha256"
  "key_id": "...",
  "signer_pubkey_hash": "...",
  "mandate_hash": "...",
  "scope_conformance": { "verdict": ..., "breaches": [...], "scope_hash": ..., "action_hash": ... },
  "signature": "..."                   // hex-encoded signature over canonical(receipt minus "signature")
}
```

Signature check: `signature` must verify, under `algorithm`, against
`manifest.receipt_public_key_hex`, over
`canonical(receipt with "signature" popped)`.

## `acquisition.json`, `custody.json`, `authentication.json`

Minimum required content -- see `verify.py`'s `verify_authentication_docs`
for the exact checks:

- `acquisition.json.tool` must have non-empty `name` and `version`;
  `clock_source` and `acquired_at` must be non-empty.
- `custody.json.custody_events` must be non-empty, sorted by `at`
  ascending, and each event's `ledger_event_hash` must be a hash present
  in `ledger_slice.ndjson`.
- `authentication.json.hash_algorithm` must be `"sha256"`;
  `signer_key_id`, `signer_pubkey_hash`, and `mandate_hash` must match the
  same-named fields on `receipt.json` (`key_id` maps to
  `signer_key_id`); `external_anchor_log_id` must match
  `acquisition.json.external_anchor.log_id`.

## Extending the format

Adding a new check to `verify.py` must never require anything beyond the
Python standard library and `cryptography` -- that constraint is
enforced by `tests/test_verify_demo_packet.py`. If a new field can't be
checked with just those two, it doesn't belong in the offline verifier;
put it in a separate, clearly-labeled online check instead.
