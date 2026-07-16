/*
 * Minimal client-side port of verify.py's core checks, for the
 * in-browser tamper-and-verify demo (tamper_demo/index.html).
 *
 * Route taken: WebCrypto (SubtleCrypto.verify with the "Ed25519"
 * algorithm), not a bundled crypto library. Ed25519 via SubtleCrypto
 * ships in current Chrome/Firefox/Safari and in Node 19+ (used here
 * only for testing this file with `node`, never shipped to the page)
 * -- no external JS dependency, matching this repo's existing
 * zero-dependency-beyond-stdlib posture for verify.py itself. Only the
 * subset of verify.py needed for the demo packet is ported: chain
 * integrity (verify_events) and the Ed25519 receipt signature
 * (verify_receipt's Ed25519 branch only -- the demo packet is always
 * Ed25519-signed, so the ECDSA branch is not ported here; a real
 * ECDSA-signed receipt should be checked with the real verify.py, not
 * this demo page).
 *
 * Pure functions, no DOM access -- importable by both the browser page
 * and a Node test harness (tests/test_tamper_demo_js.py runs it via
 * `node` as a subprocess).
 */
(function (root, factory) {
  const mod = factory();
  if (typeof module !== "undefined" && module.exports) {
    module.exports = mod;
  } else {
    root.ActaSealVerifyMin = mod;
  }
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  const EVENT_ID_BASIS = "ledger_event_id.v1";
  const SCHEMA_VERSION = "dispute_packet.v1";
  const EVENT_MATERIAL_FIELDS = [
    "event_type", "tenant_id", "workspace_id", "actor_id", "action_id",
    "action_type", "timestamp", "schema_version", "payload", "payload_hash",
    "previous_event_hash",
  ];

  // RFC 8785-adjacent canonical JSON: sorted object keys, compact
  // separators -- matches Python's json.dumps(sort_keys=True,
  // separators=(",", ":")) for the plain-old-data (str/int/bool/null/
  // dict/list) shapes every field in this packet actually has. Floats
  // never appear in receipt/ledger-event fields (money is always a
  // decimal STRING here, not a JSON number), so no ECMAScript-number
  // formatting edge case applies.
  function canonicalDumps(value) {
    if (value === null || value === undefined) return "null";
    if (typeof value === "boolean") return value ? "true" : "false";
    if (typeof value === "number") {
      if (!Number.isInteger(value)) {
        throw new Error("canonicalDumps: non-integer numbers are not supported by this minimal port");
      }
      return String(value);
    }
    if (typeof value === "string") return JSON.stringify(value);
    if (Array.isArray(value)) {
      return "[" + value.map(canonicalDumps).join(",") + "]";
    }
    if (typeof value === "object") {
      const keys = Object.keys(value).sort();
      return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonicalDumps(value[k])).join(",") + "}";
    }
    throw new Error("canonicalDumps: unsupported type " + typeof value);
  }

  function bytesToHex(bytes) {
    return Array.from(new Uint8Array(bytes)).map((b) => b.toString(16).padStart(2, "0")).join("");
  }

  function hexToBytes(hex) {
    const clean = hex || "";
    const out = new Uint8Array(clean.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
    return out;
  }

  async function canonicalHash(value) {
    const data = new TextEncoder().encode(canonicalDumps(value));
    const digest = await crypto.subtle.digest("SHA-256", data);
    return bytesToHex(digest);
  }

  async function verifyEvents(manifest, events, failures) {
    if (manifest.schema_version !== SCHEMA_VERSION) failures.push("MANIFEST_SCHEMA_MISMATCH");
    if (manifest.event_count !== events.length) {
      failures.push(`EVENT_COUNT_MISMATCH: manifest=${manifest.event_count} slice=${events.length}`);
    }
    if (events.length === 0) {
      failures.push("EMPTY_LEDGER_SLICE");
      return;
    }
    if ((events[0].previous_event_hash ?? null) !== (manifest.chain_start_previous_event_hash ?? null)) {
      failures.push("CHAIN_START_MISMATCH");
    }
    let previousHash = null;
    for (let index = 0; index < events.length; index++) {
      const event = events[index];
      try {
        const material = {};
        for (const field of EVENT_MATERIAL_FIELDS) material[field] = event[field];

        const payloadHash = await canonicalHash(event.payload);
        if (payloadHash !== event.payload_hash) failures.push(`PAYLOAD_HASH_MISMATCH: event ${index}`);

        const expectedId = await canonicalHash({ ...material, event_id_basis: EVENT_ID_BASIS });
        if (expectedId !== event.event_id) failures.push(`EVENT_ID_MISMATCH: event ${index}`);

        const expectedHash = await canonicalHash({ ...material, event_id: event.event_id });
        if (expectedHash !== event.event_hash) failures.push(`EVENT_HASH_MISMATCH: event ${index}`);

        if (index > 0 && event.previous_event_hash !== previousHash) {
          failures.push(`CHAIN_BROKEN: event ${index}`);
        }
        previousHash = event.event_hash;
      } catch (exc) {
        failures.push(`MALFORMED_EVENT: event ${index}: ${exc.message}`);
        return;
      }
    }
    const actionId = manifest.action_id;
    if (!events.some((e) => e.action_id === actionId)) {
      failures.push(`ACTION_NOT_IN_SLICE: ${JSON.stringify(actionId)}`);
    }
  }

  async function verifyReceipt(manifest, receipt, events, failures) {
    const unsigned = { ...receipt };
    const signature = unsigned.signature || "";
    delete unsigned.signature;
    const algorithm = receipt.algorithm || "ed25519";

    if (algorithm !== "ed25519") {
      failures.push(`RECEIPT_SIGNATURE_ALGORITHM_UNSUPPORTED_IN_DEMO: ${algorithm} -- use the real verify.py`);
    } else {
      try {
        const data = new TextEncoder().encode(canonicalDumps(unsigned));
        const signatureBytes = hexToBytes(signature);
        const publicKeyBytes = hexToBytes(manifest.receipt_public_key_hex);
        const key = await crypto.subtle.importKey("raw", publicKeyBytes, { name: "Ed25519" }, false, ["verify"]);
        const ok = await crypto.subtle.verify({ name: "Ed25519" }, key, signatureBytes, data);
        if (!ok) failures.push("RECEIPT_SIGNATURE_INVALID");
      } catch (exc) {
        failures.push("RECEIPT_SIGNATURE_INVALID");
      }
    }

    const boundEvent = events.find((e) => e.event_hash === receipt.ledger_entry_hash);
    if (!boundEvent) {
      failures.push("RECEIPT_LEDGER_ENTRY_NOT_IN_SLICE");
      return;
    }
    if (boundEvent.action_id !== manifest.action_id) {
      failures.push("RECEIPT_BOUND_TO_DIFFERENT_ACTION");
    }
  }

  async function verifyPacket(manifest, receipt, events) {
    const failures = [];
    await verifyEvents(manifest, events, failures);
    await verifyReceipt(manifest, receipt, events, failures);
    return { verified: failures.length === 0, failures };
  }

  return { canonicalDumps, canonicalHash, verifyEvents, verifyReceipt, verifyPacket };
});
