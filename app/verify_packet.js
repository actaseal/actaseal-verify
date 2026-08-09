/*
 * H6 (ONESHOT-HARDEN): JS/WebCrypto port of the CORE checks in
 * actaseal/dispute/offline_verifier.py (byte-pinned, never edited by
 * this file -- see actaseal/dispute/VERIFIER_SYNC.md). This slice
 * (H6a) covers verify_events + verify_receipt: per-event hash-chain
 * recomputation and receipt signature/binding. Further checks
 * (authentication docs, scope conformance, continuity checkpoint,
 * settlement anchor) land in later slices.
 *
 * Reuses receipt_verify.js's canonicalDumps/derEcdsaToRaw so the two
 * modules never drift on canonical-JSON or ECDSA-decoding behavior.
 *
 * Pure functions, no DOM access -- importable by both a browser page
 * and a Node test harness (tests/test_offline_verifier_js_parity_v1.py
 * runs it via `node` as a subprocess, against real packets built by
 * actaseal.dispute.packet.build_dispute_packet and checked against the
 * real Python offline_verifier.py for parity).
 */
(function (root, factory) {
  const mod = factory();
  if (typeof module !== "undefined" && module.exports) {
    module.exports = mod;
  } else {
    root.ActaSealVerifyPacket = mod;
  }
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  const receiptVerify =
    typeof require !== "undefined"
      ? require("./receipt_verify.js")
      : (typeof self !== "undefined" ? self.ActaSealReceiptVerify : this.ActaSealReceiptVerify);
  const { canonicalDumps, derEcdsaToRaw } = receiptVerify;

  const ALGORITHM_ED25519 = "ed25519";
  const ALGORITHM_ECDSA_P256_SHA256 = "ecdsa-p256-sha256";

  const SCHEMA_VERSION = "dispute_packet.v1";
  const EVENT_ID_BASIS = "ledger_event_id.v1";
  const EVENT_MATERIAL_FIELDS = [
    "event_type",
    "tenant_id",
    "workspace_id",
    "actor_id",
    "action_id",
    "action_type",
    "timestamp",
    "schema_version",
    "payload",
    "payload_hash",
    "previous_event_hash",
  ];

  function hexToBytes(hex) {
    const clean = hex || "";
    const out = new Uint8Array(Math.floor(clean.length / 2));
    for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
    return out;
  }

  function bytesToHex(bytes) {
    return Array.from(bytes)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }

  async function canonicalHash(value) {
    const data = new TextEncoder().encode(canonicalDumps(value));
    const digest = await crypto.subtle.digest("SHA-256", data);
    return bytesToHex(new Uint8Array(digest));
  }

  function pick(obj, fields) {
    const out = {};
    for (const field of fields) out[field] = obj[field];
    return out;
  }

  async function verifyEvents(manifest, events, failures) {
    if (manifest.schema_version !== SCHEMA_VERSION) failures.push("MANIFEST_SCHEMA_MISMATCH");
    if (manifest.event_count !== events.length) {
      failures.push(`EVENT_COUNT_MISMATCH: manifest=${manifest.event_count} slice=${events.length}`);
    }
    if (!events || events.length === 0) {
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
        const material = pick(event, EVENT_MATERIAL_FIELDS);
        if ((await canonicalHash(event.payload)) !== event.payload_hash) {
          failures.push(`PAYLOAD_HASH_MISMATCH: event ${index}`);
        }
        const expectedId = await canonicalHash({ ...material, event_id_basis: EVENT_ID_BASIS });
        if (expectedId !== event.event_id) failures.push(`EVENT_ID_MISMATCH: event ${index}`);
        const expectedHash = await canonicalHash({ ...material, event_id: event.event_id });
        if (expectedHash !== event.event_hash) failures.push(`EVENT_HASH_MISMATCH: event ${index}`);
        if (index > 0 && event.previous_event_hash !== previousHash) {
          failures.push(`CHAIN_BROKEN: event ${index}`);
        }
        previousHash = event.event_hash;
      } catch (exc) {
        failures.push(`MALFORMED_EVENT: event ${index}: ${exc}`);
        return;
      }
    }
    const actionId = manifest.action_id;
    if (!events.some((event) => event.action_id === actionId)) {
      failures.push(`ACTION_NOT_IN_SLICE: ${JSON.stringify(actionId)}`);
    }
  }

  async function verifyReceiptSignature(manifest, receipt, failures) {
    const unsigned = { ...receipt };
    const signature = unsigned.signature || "";
    delete unsigned.signature;
    delete unsigned.tsa_anchor;
    const algorithm = receipt.algorithm || ALGORITHM_ED25519;
    try {
      const data = new TextEncoder().encode(canonicalDumps(unsigned));
      const signatureBytes = hexToBytes(signature);
      const publicKeyBytes = hexToBytes(manifest.receipt_public_key_hex);

      if (algorithm === ALGORITHM_ED25519) {
        const key = await crypto.subtle.importKey("raw", publicKeyBytes, { name: "Ed25519" }, false, ["verify"]);
        const ok = await crypto.subtle.verify({ name: "Ed25519" }, key, signatureBytes, data);
        if (!ok) failures.push("RECEIPT_SIGNATURE_INVALID");
      } else if (algorithm === ALGORITHM_ECDSA_P256_SHA256) {
        const key = await crypto.subtle.importKey(
          "spki", publicKeyBytes, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]
        );
        const rawSignature = derEcdsaToRaw(signatureBytes);
        const ok = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, rawSignature, data);
        if (!ok) failures.push("RECEIPT_SIGNATURE_INVALID");
      } else {
        failures.push(`RECEIPT_SIGNATURE_ALGORITHM_UNKNOWN: ${algorithm}`);
      }
    } catch (exc) {
      failures.push("RECEIPT_SIGNATURE_INVALID");
    }
  }

  function verifyReceiptBinding(manifest, receipt, events, failures) {
    const boundEvent = events.find((event) => event.event_hash === receipt.ledger_entry_hash);
    if (!boundEvent) {
      failures.push("RECEIPT_LEDGER_ENTRY_NOT_IN_SLICE");
      return;
    }
    if (boundEvent.action_id !== manifest.action_id) {
      failures.push("RECEIPT_BOUND_TO_DIFFERENT_ACTION");
    }
    const recordedActionHash = (boundEvent.payload || {}).action_packet_hash;
    if (recordedActionHash != null && recordedActionHash !== receipt.action_hash) {
      failures.push("RECEIPT_ACTION_HASH_MISMATCH");
    }
  }

  function verifyAuthenticationDocs(receipt, events, docs, failures) {
    const acquisition = docs.acquisition;
    const custody = docs.custody;
    const authentication = docs.authentication;
    if (acquisition === undefined || acquisition === null) failures.push("ACQUISITION_REPORT_MISSING");
    if (custody === undefined || custody === null) failures.push("CUSTODY_DOC_MISSING");
    if (authentication === undefined || authentication === null) failures.push("AUTHENTICATION_STATEMENT_MISSING");
    const sliceHashes = new Set(events.map((event) => event.event_hash));

    if (acquisition != null) {
      const tool = acquisition.tool || {};
      if (!tool.name || !tool.version) failures.push("ACQUISITION_TOOL_UNDECLARED: acquisition.json lacks tool name+version");
      if (!acquisition.clock_source) failures.push("ACQUISITION_CLOCK_SOURCE_UNDECLARED: acquisition.json");
      if (!acquisition.acquired_at) failures.push("ACQUISITION_TIME_UNDECLARED: acquisition.json");
    }

    if (custody != null) {
      const custodyEvents = custody.custody_events || [];
      if (custodyEvents.length === 0) failures.push("CUSTODY_EMPTY: custody.json records no custody events");
      const timestamps = custodyEvents.map((event) => String(event.at || ""));
      const sorted = [...timestamps].sort();
      if (JSON.stringify(timestamps) !== JSON.stringify(sorted)) {
        failures.push("CUSTODY_ORDER_INVALID: custody.json events are not time-ordered");
      }
      custodyEvents.forEach((event, index) => {
        if (!sliceHashes.has(event.ledger_event_hash)) {
          failures.push(
            `CUSTODY_EVENT_UNBOUND: custody.json event ${index} is not bound to a ledger event hash in the slice`
          );
        }
      });
    }

    if (authentication != null) {
      if (authentication.hash_algorithm !== "sha256") failures.push("AUTHENTICATION_HASH_ALGO_MISMATCH: authentication.json");
      for (const [docField, receiptField] of [
        ["signer_key_id", "key_id"],
        ["signer_pubkey_hash", "signer_pubkey_hash"],
        ["mandate_hash", "mandate_hash"],
      ]) {
        if ((authentication[docField] ?? null) !== (receipt[receiptField] ?? null)) {
          failures.push(`AUTHENTICATION_${docField.toUpperCase()}_MISMATCH: authentication.json diverges from receipt`);
        }
      }
      if (acquisition != null) {
        const anchor = acquisition.external_anchor || {};
        if ((authentication.external_anchor_log_id ?? null) !== (anchor.log_id ?? null)) {
          failures.push("AUTHENTICATION_ANCHOR_LOG_MISMATCH: authentication.json vs acquisition.json");
        }
      }
    }
  }

  function scopeHeadline(scopeConformance) {
    if (scopeConformance == null) return "not_evaluated";
    if (scopeConformance.verdict === "IN_SCOPE") return "in_scope";
    const dims = (scopeConformance.breaches || []).map((breach) => String(breach.dimension)).join(",");
    return `BREACH:${dims}`;
  }

  async function verifyScopeConformance(manifest, receipt, events, failures) {
    if (!("scope_conformance_headline" in manifest)) {
      failures.push("SCOPE_HEADLINE_MISSING: manifest.json");
    } else {
      const expected = scopeHeadline(receipt.scope_conformance);
      if (manifest.scope_conformance_headline !== expected) {
        failures.push(
          `SCOPE_HEADLINE_MISMATCH: manifest.json says ${JSON.stringify(manifest.scope_conformance_headline)} receipt derives ${JSON.stringify(expected)}`
        );
      }
    }

    const actionId = manifest.action_id;
    const scopeEvents = events.filter((event) => event.event_type === "ScopeEvaluated" && event.action_id === actionId);
    const result = receipt.scope_conformance;
    if (result != null && scopeEvents.length === 0) {
      failures.push("SCOPE_EVENT_MISSING: receipt.json claims a scope conformance the ledger_slice.ndjson never witnessed (no ScopeEvaluated event)");
    }
    if (result == null && scopeEvents.length > 0) {
      failures.push("SCOPE_RESULT_MISSING: receipt.json carries no scope_conformance but ledger_slice.ndjson records a ScopeEvaluated event");
    }
    if (result != null && scopeEvents.length > 0) {
      const payload = scopeEvents[scopeEvents.length - 1].payload || {};
      if (payload.verdict !== result.verdict) failures.push("SCOPE_VERDICT_MISMATCH: receipt.json vs ledger_slice.ndjson");
      const eventDims = (payload.breach_dimensions || []).map(String);
      const receiptDims = (result.breaches || []).map((breach) => String(breach.dimension));
      if (JSON.stringify(eventDims) !== JSON.stringify(receiptDims)) {
        failures.push(`SCOPE_DIMENSIONS_MISMATCH: receipt.json breaches ${JSON.stringify(receiptDims)} vs ledger ${JSON.stringify(eventDims)}`);
      }
      for (const [hashField, sourceField] of [["scope_hash", "intent_scope"], ["action_hash", "executed_action"]]) {
        const source = payload[sourceField];
        if (source == null || payload[hashField] !== (await canonicalHash(source))) {
          failures.push(`SCOPE_HASH_MISMATCH: ScopeEvaluated ${hashField} does not recompute from its recorded ${sourceField}`);
        } else if (result[hashField] !== payload[hashField]) {
          failures.push(`SCOPE_HASH_MISMATCH: receipt.json ${hashField} diverges from ledger`);
        }
      }
    }
  }

  async function verifyApproverSnapshot(manifest, receipt, events, failures) {
    const snapshotHash = receipt.approver_snapshot_hash;
    if (snapshotHash == null) return;

    const actionId = manifest.action_id;
    const snapshotEvents = events.filter(
      (event) => event.event_type === "ApproverSnapshotCaptured" && event.action_id === actionId
    );
    if (snapshotEvents.length === 0) {
      failures.push(
        "APPROVER_SNAPSHOT_EVENT_MISSING: receipt.json claims an approver_snapshot_hash the ledger_slice.ndjson never witnessed (no ApproverSnapshotCaptured event)"
      );
      return;
    }
    const payload = snapshotEvents[snapshotEvents.length - 1].payload || {};
    if ((await canonicalHash(payload)) !== snapshotHash) {
      failures.push(
        "APPROVER_SNAPSHOT_HASH_MISMATCH: ApproverSnapshotCaptured payload does not recompute to receipt.json's approver_snapshot_hash"
      );
    }
  }

  async function verifySettlementAnchor(manifest, failures) {
    const block = manifest.settlement_anchor;
    if (block == null) {
      failures.push("SETTLEMENT_FIELD_MISSING: manifest.json carries no settlement_anchor block (even an unanchored packet must state SETTLEMENT_UNANCHORED)");
      return;
    }
    const status = block.status;
    if (status === "SETTLEMENT_UNANCHORED") {
      const keys = Object.keys(block);
      if (keys.length !== 1 || keys[0] !== "status") {
        failures.push(`SETTLEMENT_ANCHOR_INVALID: unanchored block carries extra fields ${JSON.stringify(keys.filter((k) => k !== "status").sort())}`);
      }
      return;
    }
    if (status !== "anchored") {
      failures.push(`SETTLEMENT_ANCHOR_INVALID: unknown status ${JSON.stringify(status)}`);
      return;
    }
    const anchor = block.anchor;
    if (typeof anchor !== "object" || anchor === null) {
      failures.push("SETTLEMENT_ANCHOR_INVALID: anchored block has no anchor content");
      return;
    }
    if (block.anchor_hash !== (await canonicalHash(anchor))) {
      failures.push("SETTLEMENT_ANCHOR_HASH_MISMATCH: anchor_hash does not recompute from the anchor content in manifest.json");
    }
  }

  async function leafHash(dataBytes) {
    const prefixed = new Uint8Array(1 + dataBytes.length);
    prefixed[0] = 0x00;
    prefixed.set(dataBytes, 1);
    return new Uint8Array(await crypto.subtle.digest("SHA-256", prefixed));
  }

  async function nodeHash(left, right) {
    const combined = new Uint8Array(1 + left.length + right.length);
    combined[0] = 0x01;
    combined.set(left, 1);
    combined.set(right, 1 + left.length);
    return new Uint8Array(await crypto.subtle.digest("SHA-256", combined));
  }

  // RFC 9162 section 2.1.3.2 inclusion-proof verification. Must stay in
  // lock-step with actaseal.anchoring._root_from_audit_path /
  // offline_verifier.py's function of the same name.
  async function rootFromAuditPath(leaf, index, treeSize, path) {
    if (index < 0 || index >= treeSize) throw new Error("leaf index outside claimed tree size");
    let fn = index;
    let sn = treeSize - 1;
    let node = leaf;
    for (const sibling of path) {
      if (sn === 0) throw new Error("audit path longer than the claimed tree allows");
      if (fn % 2 === 1 || fn === sn) {
        node = await nodeHash(sibling, node);
        if (fn % 2 === 0) {
          while (fn % 2 === 0 && fn !== 0) {
            fn = Math.floor(fn / 2);
            sn = Math.floor(sn / 2);
          }
        }
      } else {
        node = await nodeHash(node, sibling);
      }
      fn = Math.floor(fn / 2);
      sn = Math.floor(sn / 2);
    }
    if (sn !== 0) throw new Error("audit path shorter than the claimed tree requires");
    return node;
  }

  function largestPow2Lt(n) {
    let split = 1;
    while (split * 2 < n) split *= 2;
    return split;
  }

  // Must stay in lock-step with actaseal.anchoring._verify_consistency_nodes
  // / offline_verifier.py's function of the same name.
  async function verifyConsistencyNodes(m, n, proof) {
    if (m === n) {
      const h = proof[0];
      return [h, h];
    }
    const k = largestPow2Lt(n);
    if (m <= k) {
      const [oldH, newHLeft] = await verifyConsistencyNodes(m, k, proof.slice(0, -1));
      const newH = await nodeHash(newHLeft, proof[proof.length - 1]);
      return [oldH, newH];
    }
    const [oldHRight, newHRight] = await verifyConsistencyNodes(m - k, n - k, proof.slice(0, -1));
    const oldH = await nodeHash(proof[proof.length - 1], oldHRight);
    const newH = await nodeHash(proof[proof.length - 1], newHRight);
    return [oldH, newH];
  }

  function sthSigningBytes(sth) {
    return new TextEncoder().encode(
      canonicalDumps({
        log_id: sth.log_id ?? null,
        tree_size: sth.tree_size ?? null,
        root_hash: sth.root_hash ?? null,
        timestamp: sth.timestamp ?? null,
      })
    );
  }

  // Must stay in lock-step with actaseal.anchoring.verify_tree_head /
  // offline_verifier.py's _verify_sth_signature.
  async function verifySthSignature(sth, publicKeyHex) {
    const algorithm = sth.algorithm || ALGORITHM_ED25519;
    try {
      const data = sthSigningBytes(sth);
      const signatureBytes = hexToBytes(sth.signature || "");
      const publicKeyBytes = hexToBytes(publicKeyHex);
      if (algorithm === ALGORITHM_ED25519) {
        const key = await crypto.subtle.importKey("raw", publicKeyBytes, { name: "Ed25519" }, false, ["verify"]);
        return await crypto.subtle.verify({ name: "Ed25519" }, key, signatureBytes, data);
      }
      if (algorithm === ALGORITHM_ECDSA_P256_SHA256) {
        const key = await crypto.subtle.importKey(
          "spki", publicKeyBytes, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]
        );
        const rawSignature = derEcdsaToRaw(signatureBytes);
        return await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, rawSignature, data);
      }
      return false;
    } catch (exc) {
      return false;
    }
  }

  // Must stay in lock-step with actaseal.receipt.receipt_hash/signing_bytes
  // / offline_verifier.py's _compute_receipt_hash.
  async function computeReceiptHash(receipt) {
    const unsigned = { ...receipt };
    delete unsigned.signature;
    delete unsigned.tsa_anchor;
    const data = new TextEncoder().encode(canonicalDumps(unsigned));
    const digest = await crypto.subtle.digest("SHA-256", data);
    return bytesToHex(new Uint8Array(digest));
  }

  // T8 (ONESHOT-4 batch 3) parity: optional, additive -- silent no-op
  // when checkpoint is absent, same posture as offline_verifier.py's
  // verify_continuity_checkpoint.
  async function verifyContinuityCheckpoint(receipt, docs, failures) {
    const checkpoint = docs.checkpoint;
    if (checkpoint === undefined || checkpoint === null) return;

    const sth = checkpoint.sth;
    const sthPublicKeyHex = checkpoint.sth_public_key_hex;
    if (typeof sth !== "object" || sth === null || !sthPublicKeyHex) {
      failures.push("CHECKPOINT_DOC_MALFORMED: checkpoint.json is missing sth or sth_public_key_hex");
      return;
    }
    if (!(await verifySthSignature(sth, sthPublicKeyHex))) {
      failures.push("STH_SIGNATURE_INVALID:checkpoint.json's signed tree head does not verify against its own public key");
    }

    const proof = docs.inclusion_proof;
    if (proof === undefined || proof === null) {
      failures.push("INCLUSION_PROOF_MISSING");
      return;
    }

    const receiptHashValue = await computeReceiptHash(receipt);
    const expectedLeaf = bytesToHex(await leafHash(new TextEncoder().encode(receiptHashValue)));
    if (proof.leaf_hash !== expectedLeaf) {
      failures.push("ANCHOR_INCLUSION_PROOF_INVALID:inclusion_proof.leaf_hash does not commit to this receipt's hash");
    } else {
      try {
        const computed = await rootFromAuditPath(
          hexToBytes(proof.leaf_hash),
          parseInt(proof.entry_id, 10),
          parseInt(proof.sth_tree_size, 10),
          (proof.audit_path || []).map(hexToBytes)
        );
        if (bytesToHex(computed) !== proof.sth_root) {
          failures.push("ANCHOR_INCLUSION_PROOF_INVALID:inclusion_proof audit path does not reproduce sth_root");
        }
      } catch (exc) {
        failures.push(`ANCHOR_INCLUSION_PROOF_INVALID:inclusion_proof is malformed: ${exc}`);
      }
    }

    if (proof.sth_root !== sth.root_hash || proof.sth_tree_size !== sth.tree_size) {
      failures.push(
        `ANCHOR_CHECKPOINT_MISMATCH:inclusion_proof's checkpoint (root=${JSON.stringify(proof.sth_root)}, tree_size=${JSON.stringify(proof.sth_tree_size)}) does not match checkpoint.json's signed tree head (root=${JSON.stringify(sth.root_hash)}, tree_size=${JSON.stringify(sth.tree_size)})`
      );
    }

    const cproof = docs.consistency_proof;
    if (cproof === undefined || cproof === null) return;

    let m = cproof.old_tree_size;
    let n = cproof.new_tree_size;
    if (!Number.isInteger(m) || !Number.isInteger(n)) {
      failures.push("ANCHOR_CONSISTENCY_PROOF_INVALID:consistency_proof has non-integer tree sizes");
      return;
    }
    if (m < 0 || n < 0 || m > n) {
      failures.push("ANCHOR_CONSISTENCY_PROOF_INVALID:consistency_proof has an invalid tree-size relationship");
      return;
    }
    if (m === 0) {
      if (cproof.proof && cproof.proof.length) {
        failures.push("ANCHOR_CONSISTENCY_PROOF_INVALID:consistency_proof with old_tree_size=0 must carry no proof nodes");
      }
      return;
    }
    if (m === n) {
      if ((cproof.proof && cproof.proof.length) || cproof.old_root !== cproof.new_root) {
        failures.push("ANCHOR_CONSISTENCY_PROOF_INVALID:consistency_proof for equal tree sizes must have no proof nodes and matching roots");
      }
      return;
    }
    if (!cproof.proof || !cproof.proof.length) {
      failures.push("ANCHOR_CONSISTENCY_PROOF_INVALID:consistency_proof is missing required proof nodes");
      return;
    }
    try {
      const nodes = cproof.proof.map(hexToBytes);
      const [oldHash, newHash] = await verifyConsistencyNodes(m, n, nodes);
      if (bytesToHex(oldHash) !== cproof.old_root) {
        failures.push("ANCHOR_CONSISTENCY_PROOF_INVALID:consistency_proof does not reproduce old_root");
      }
      if (bytesToHex(newHash) !== cproof.new_root) {
        failures.push("ANCHOR_CONSISTENCY_PROOF_INVALID:consistency_proof does not reproduce new_root");
      }
    } catch (exc) {
      failures.push("ANCHOR_CONSISTENCY_PROOF_INVALID:consistency_proof is malformed");
    }
  }

  // core: { manifest, receipt, events, docs } -- manifest.json,
  // receipt.json, ledger_slice.ndjson, and the optional FRE-901 docs
  // (acquisition/custody/authentication -- null when absent), already
  // parsed into JSON.
  async function verifyPacket(core) {
    const failures = [];
    if (!core || typeof core !== "object") {
      return { verified: false, malformed: true, failures: ["MALFORMED_INPUT: top-level JSON must be an object"] };
    }
    const { manifest, receipt, events } = core;
    const docs = core.docs || {};
    if (!manifest || typeof manifest !== "object") {
      return { verified: false, malformed: true, failures: ["MALFORMED_INPUT: missing or non-object 'manifest'"] };
    }
    if (!receipt || typeof receipt !== "object") {
      return { verified: false, malformed: true, failures: ["MALFORMED_INPUT: missing or non-object 'receipt'"] };
    }
    if (!Array.isArray(events)) {
      return { verified: false, malformed: true, failures: ["MALFORMED_INPUT: missing or non-array 'events'"] };
    }

    await verifyEvents(manifest, events, failures);
    await verifyReceiptSignature(manifest, receipt, failures);
    verifyReceiptBinding(manifest, receipt, events, failures);
    await verifyContinuityCheckpoint(receipt, docs, failures);
    verifyAuthenticationDocs(receipt, events, docs, failures);
    await verifyScopeConformance(manifest, receipt, events, failures);
    await verifyApproverSnapshot(manifest, receipt, events, failures);
    await verifySettlementAnchor(manifest, failures);

    return { verified: failures.length === 0, malformed: false, failures, decision: receipt.decision };
  }

  return {
    canonicalHash,
    verifyEvents,
    verifyReceiptSignature,
    verifyReceiptBinding,
    verifyAuthenticationDocs,
    verifyScopeConformance,
    verifyApproverSnapshot,
    verifySettlementAnchor,
    verifyContinuityCheckpoint,
    verifyPacket,
  };
});
