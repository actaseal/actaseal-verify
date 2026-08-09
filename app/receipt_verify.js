/*
 * Client-side port of actaseal/dispute/verify_receipt.py's checks, for the
 * in-browser receipt-verification sandbox (web/receipt_verify_sandbox.html).
 *
 * Unlike tamper_demo/verify_min.js in the public actaseal-verify repo
 * (which verifies a full dispute PACKET -- manifest + receipt + ledger
 * slice -- and only supports Ed25519), this ports the lighter
 * standalone-RECEIPT verifier and supports both signature algorithms
 * actaseal.signing knows about: Ed25519 and ECDSA P-256/SHA-256. Route
 * taken: WebCrypto (SubtleCrypto), no bundled crypto library -- Ed25519
 * via SubtleCrypto ships in current Chrome/Firefox/Safari and in Node 19+
 * (used here only for testing this file with `node`, never shipped to
 * the page); ECDSA P-256 via SubtleCrypto is universally supported.
 *
 * Pure functions, no DOM access -- importable by both the browser page
 * and a Node test harness (tests/test_receipt_verify_sandbox_js_v1.py
 * runs it via `node` as a subprocess).
 */
(function (root, factory) {
  const mod = factory();
  if (typeof module !== "undefined" && module.exports) {
    module.exports = mod;
  } else {
    root.ActaSealReceiptVerify = mod;
  }
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  const ALGORITHM_ED25519 = "ed25519";
  const ALGORITHM_ECDSA_P256_SHA256 = "ecdsa-p256-sha256";

  // RFC 8785-adjacent canonical JSON: sorted object keys, compact
  // separators -- matches Python's json.dumps(sort_keys=True,
  // separators=(",", ":")). Money fields are decimal STRINGS in this
  // system, never JSON numbers, so no ECMAScript-number formatting edge
  // case applies to real receipts.
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

  function hexToBytes(hex) {
    const clean = hex || "";
    const out = new Uint8Array(Math.floor(clean.length / 2));
    for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
    return out;
  }

  async function verifySignature(receipt, publicKeyHex, failures) {
    const unsigned = { ...receipt };
    const signature = unsigned.signature || "";
    delete unsigned.signature;
    const algorithm = receipt.algorithm || ALGORITHM_ED25519;

    try {
      const data = new TextEncoder().encode(canonicalDumps(unsigned));
      const signatureBytes = hexToBytes(signature);
      const publicKeyBytes = hexToBytes(publicKeyHex);

      if (algorithm === ALGORITHM_ED25519) {
        const key = await crypto.subtle.importKey("raw", publicKeyBytes, { name: "Ed25519" }, false, ["verify"]);
        const ok = await crypto.subtle.verify({ name: "Ed25519" }, key, signatureBytes, data);
        if (!ok) failures.push("RECEIPT_SIGNATURE_INVALID");
      } else if (algorithm === ALGORITHM_ECDSA_P256_SHA256) {
        const key = await crypto.subtle.importKey(
          "spki", publicKeyBytes, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]
        );
        // ECDSA signatures here are DER-encoded (matches Python
        // `cryptography`'s ec.ECDSA output); WebCrypto's ECDSA.verify
        // expects raw (r||s) IEEE P1363 format, so DER is converted first.
        const rawSignature = derEcdsaToRaw(signatureBytes);
        const ok = await crypto.subtle.verify(
          { name: "ECDSA", hash: "SHA-256" }, key, rawSignature, data
        );
        if (!ok) failures.push("RECEIPT_SIGNATURE_INVALID");
      } else {
        failures.push("RECEIPT_SIGNATURE_ALGORITHM_UNKNOWN: " + algorithm);
      }
    } catch (exc) {
      failures.push("RECEIPT_SIGNATURE_INVALID");
    }
  }

  // Minimal DER (SEQUENCE of two INTEGERs) -> raw fixed-width r||s decoder
  // for P-256 (32-byte components), no external ASN.1 library.
  function derEcdsaToRaw(der) {
    if (der[0] !== 0x30) throw new Error("not a DER ECDSA signature");
    let offset = 2;
    if (der[1] & 0x80) offset += (der[1] & 0x7f); // long-form length, skip
    function readInt() {
      if (der[offset] !== 0x02) throw new Error("expected DER INTEGER");
      let len = der[offset + 1];
      offset += 2;
      let bytes = der.slice(offset, offset + len);
      offset += len;
      // strip a leading 0x00 sign-padding byte, left-pad to 32 bytes
      while (bytes.length > 32 && bytes[0] === 0x00) bytes = bytes.slice(1);
      const out = new Uint8Array(32);
      out.set(bytes, 32 - bytes.length);
      return out;
    }
    const r = readInt();
    const s = readInt();
    const raw = new Uint8Array(64);
    raw.set(r, 0);
    raw.set(s, 32);
    return raw;
  }

  function verifyChain(receipt, ledgerSlice, failures) {
    if (!ledgerSlice || ledgerSlice.length === 0) {
      failures.push("EMPTY_LEDGER_SLICE");
      return;
    }
    let previousHash = null;
    for (let index = 0; index < ledgerSlice.length; index++) {
      const event = ledgerSlice[index];
      if (index > 0 && event.previous_event_hash !== previousHash) {
        failures.push(`CHAIN_BROKEN: event ${index}`);
      }
      previousHash = event.event_hash;
    }
    const sliceHashes = new Set(ledgerSlice.map((e) => e.event_hash));
    if (!sliceHashes.has(receipt.ledger_entry_hash)) {
      failures.push("RECEIPT_LEDGER_ENTRY_NOT_IN_SLICE");
    }
  }

  // document: { receipt: {...}, receipt_public_key_hex: "...", ledger_slice: [...] (optional) }
  async function verifyDocument(document) {
    const failures = [];
    if (!document || typeof document !== "object") {
      return { verified: false, malformed: true, failures: ["MALFORMED_INPUT: top-level JSON must be an object"] };
    }
    const receipt = document.receipt;
    const publicKeyHex = document.receipt_public_key_hex;
    if (!receipt || typeof receipt !== "object") {
      return { verified: false, malformed: true, failures: ["MALFORMED_INPUT: missing or non-object 'receipt' field"] };
    }
    if (!publicKeyHex || typeof publicKeyHex !== "string") {
      return { verified: false, malformed: true, failures: ["MALFORMED_INPUT: missing 'receipt_public_key_hex' field"] };
    }

    await verifySignature(receipt, publicKeyHex, failures);
    if (document.ledger_slice != null) {
      verifyChain(receipt, document.ledger_slice, failures);
    }

    return { verified: failures.length === 0, malformed: false, failures, decision: receipt.decision };
  }

  return { canonicalDumps, verifySignature, verifyChain, verifyDocument, derEcdsaToRaw };
});
