// Runs this site's own verify.py, unmodified, in the browser via Pyodide.
// The packet is read locally and never sent anywhere.
import { loadPyodide } from "./runtime/pyodide.mjs";

const $ = (id) => document.getElementById(id);
let py = null;
let verifySha = null;
// The keyring this site itself serves, once the reader asks for it. Kept
// apart from anything the reader supplied: it is not an independent key.
let sameOriginKeyring = null;

async function sha256Hex(bytes) {
  const d = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function boot() {
  try {
    py = await loadPyodide({ indexURL: new URL("./runtime/", location.href).href });
    await py.loadPackage("cryptography", { messageCallback: () => {} });
    const src = new Uint8Array(await (await fetch("../verify.py", { cache: "no-store" })).arrayBuffer());
    verifySha = await sha256Hex(src);
    const glue = await (await fetch("./glue.py", { cache: "no-store" })).text();
    py.FS.mkdirTree("/verifier");
    py.FS.writeFile("/verifier/verify.py", src);
    py.FS.writeFile("/verifier/glue.py", glue);
    py.runPython("import sys; sys.path.insert(0, '/verifier'); import glue");
    $("engine").textContent = "Ready. Files are read in this browser and never uploaded.";
    $("engine").dataset.state = "ready";
    $("sha").textContent = verifySha;
  } catch (e) {
    $("engine").textContent = `Could not load the verifier: ${e.message}`;
    $("engine").dataset.state = "error";
    console.error(e);
  }
  sync();
}

function sync() {
  $("run").disabled = !(py && $("packet").files.length);
  $("demo").disabled = !py;
}

async function run(demoBytes = null) {
  const work = "/work";
  try { py.FS.rmdir(work); } catch { /* first run */ }
  py.FS.mkdirTree(work);
  const write = async (file, name) => {
    const path = `${work}/${name}`;
    py.FS.writeFile(path, new Uint8Array(await file.arrayBuffer()));
    return path;
  };
  const packet = `${work}/packet.zip`;
  py.FS.writeFile(packet, demoBytes ?? new Uint8Array(await $("packet").files[0].arrayBuffer()));
  const certs = [];
  for (const [i, f] of [...$("tsa").files].entries()) certs.push(await write(f, `tsa-ca-${i}.pem`));
  const anchors = $("anchors").files[0] ? await write($("anchors").files[0], "anchors.jsonl") : null;
  const key = $("sthkey").value.trim() || null;

  // Which key the receipt signature is held to, most independent first:
  // a key the reader pasted, a keyring file the reader chose, the keyring
  // this site serves, or nothing (the packet's own declared key).
  const pastedKey = $("receiptkey").value.trim() || null;
  let keyringPath = null;
  let keySource = "unpinned";
  if (pastedKey) {
    keySource = "pinned";
  } else if ($("keyring").files[0]) {
    keyringPath = await write($("keyring").files[0], "keyring.json");
    keySource = "pinned";
  } else if (sameOriginKeyring) {
    keyringPath = `${work}/site-keyring.json`;
    py.FS.writeFile(keyringPath, sameOriginKeyring);
    keySource = "same-origin";
  }

  const fn = py.globals.get("glue").run;
  const res = fn(packet, key, py.toPy(certs), anchors, pastedKey, keyringPath);
  const [code, output, args] = res.toJs();
  res.destroy();
  fn.destroy();
  for (const p of py.FS.readdir(work)) if (p !== "." && p !== "..") py.FS.unlink(`${work}/${p}`);
  show(code, output, args, keySource);
}

const KEY_STATUS = {
  pinned: "Signing key: PINNED. The receipt was checked against a key you supplied.",
  "same-origin": "Signing key: SAME-ORIGIN. The receipt was checked against the keyring this site serves. " +
    "That is only as trustworthy as this site: whoever controls this page controls that file. " +
    "To remove that dependence, paste a key or load a keyring you obtained from the operator yourself.",
  unpinned: "Signing key: NOT PINNED. The signature was checked only against the key the packet itself declares. " +
    "A packet re-signed end to end with someone else's key would pass the same way. " +
    "Paste the operator's published key, or load its keyring, to rule that out.",
};

function show(code, output, args, keySource = null) {
  const box = $("result");
  box.hidden = false;
  const verdict = code === 0 ? "VERIFIED" : code === 1 ? "VERIFICATION FAILED" : "UNABLE TO RUN";
  box.className = `result ${code === 0 ? "ok" : "bad"}`;
  $("verdict").textContent = `${verdict} · exit ${code}`;
  $("cmd").textContent = `python verify.py ${args.map((a) => a.replace(/^\/work\//, "")).join(" ")}`;
  $("output").textContent = output;
  const status = $("key-status");
  status.hidden = !keySource;
  if (keySource) {
    status.dataset.state = keySource;
    status.textContent = KEY_STATUS[keySource];
  }
  box.scrollIntoView({ behavior: "smooth", block: "start" });
}

for (const id of ["packet", "tsa", "anchors"]) $(id).addEventListener("change", sync);
$("sameorigin").addEventListener("click", async () => {
  const state = $("sameorigin-state");
  try {
    const response = await fetch("/.well-known/actaseal-keys.json", { cache: "no-store" });
    if (!response.ok) throw new Error(`this site publishes no keyring (HTTP ${response.status})`);
    const bytes = new Uint8Array(await response.arrayBuffer());
    const count = JSON.parse(new TextDecoder().decode(bytes)).keys.length;
    sameOriginKeyring = bytes;
    state.dataset.state = "loaded";
    state.textContent = `Loaded ${count} key(s) from ${location.origin}/.well-known/actaseal-keys.json. ` +
      "Used only if you supply no key or keyring of your own.";
  } catch (e) {
    sameOriginKeyring = null;
    state.dataset.state = "error";
    state.textContent = `Could not load it: ${e.message}`;
  }
});
$("demo").addEventListener("click", async () => {
  try {
    const bytes = new Uint8Array(await (await fetch("../demo/demo-packet-anchored.zip")).arrayBuffer());
    await run(bytes);
    $("cmd").textContent = $("cmd").textContent.replace("packet.zip", "demo-packet-anchored.zip");
  } catch (e) {
    show(2, `Browser error: ${e.message}`, []);
    console.error(e);
  }
});
$("run").addEventListener("click", () => run().catch((e) => {
  show(2, `Browser error: ${e.message}`, []);
  console.error(e);
}));
boot();
