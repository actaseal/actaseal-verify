// Runs this site's own verify.py, unmodified, in the browser via Pyodide.
// The packet is read locally and never sent anywhere.
import { loadPyodide } from "./runtime/pyodide.mjs";

const $ = (id) => document.getElementById(id);
let py = null;
let verifySha = null;

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
}

async function run() {
  const work = "/work";
  try { py.FS.rmdir(work); } catch { /* first run */ }
  py.FS.mkdirTree(work);
  const write = async (file, name) => {
    const path = `${work}/${name}`;
    py.FS.writeFile(path, new Uint8Array(await file.arrayBuffer()));
    return path;
  };
  const packet = await write($("packet").files[0], "packet.zip");
  const certs = [];
  for (const [i, f] of [...$("tsa").files].entries()) certs.push(await write(f, `tsa-ca-${i}.pem`));
  const anchors = $("anchors").files[0] ? await write($("anchors").files[0], "anchors.jsonl") : null;
  const key = $("sthkey").value.trim() || null;

  const fn = py.globals.get("glue").run;
  const res = fn(packet, key, py.toPy(certs), anchors);
  const [code, output, args] = res.toJs();
  res.destroy();
  fn.destroy();
  for (const p of py.FS.readdir(work)) if (p !== "." && p !== "..") py.FS.unlink(`${work}/${p}`);
  show(code, output, args);
}

function show(code, output, args) {
  const box = $("result");
  box.hidden = false;
  const verdict = code === 0 ? "VERIFIED" : code === 1 ? "VERIFICATION FAILED" : "UNABLE TO RUN";
  box.className = `result ${code === 0 ? "ok" : "bad"}`;
  $("verdict").textContent = `${verdict} · exit ${code}`;
  $("cmd").textContent = `python verify.py ${args.map((a) => a.replace(/^\/work\//, "")).join(" ")}`;
  $("output").textContent = output;
  box.scrollIntoView({ behavior: "smooth", block: "start" });
}

for (const id of ["packet", "tsa", "anchors"]) $(id).addEventListener("change", sync);
$("run").addEventListener("click", () => run().catch((e) => {
  show(2, `Browser error: ${e.message}`, []);
  console.error(e);
}));
boot();
