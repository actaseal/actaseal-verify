// npm test: the package verifies the repository's demo packet and refuses a tampered copy.
const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");
const { verifyPacket } = require("./verify_min.js");

const dir = path.join(__dirname, "..", "demo", "demo-packet-unanchored");
const load = () => ({
  manifest: JSON.parse(fs.readFileSync(path.join(dir, "manifest.json"), "utf8")),
  receipt: JSON.parse(fs.readFileSync(path.join(dir, "receipt.json"), "utf8")),
  events: fs.readFileSync(path.join(dir, "ledger_slice.ndjson"), "utf8").trim().split("\n").map((l) => JSON.parse(l)),
});

test("the demo packet verifies", async () => {
  const { manifest, receipt, events } = load();
  const r = await verifyPacket(manifest, receipt, events);
  assert.deepStrictEqual(r, { verified: true, failures: [] });
});

test("a tampered event is refused", async () => {
  const { manifest, receipt, events } = load();
  events[0].payload = { ...events[0].payload, tampered: true };
  const r = await verifyPacket(manifest, receipt, events);
  assert.strictEqual(r.verified, false);
  assert.ok(r.failures.length > 0);
});

test("a stripped receipt signature is refused", async () => {
  const { manifest, receipt, events } = load();
  delete receipt.signature;
  const r = await verifyPacket(manifest, receipt, events);
  assert.strictEqual(r.verified, false);
});
