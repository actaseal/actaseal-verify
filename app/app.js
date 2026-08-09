"use strict";

/* ActaSeal offline verifier -- browser driver.
 *
 * Loads Pyodide, mounts the synced verify.py copy from
 * actaseal_verify_bundle/ into Pyodide's virtual filesystem, and exposes
 * window.verifyPacket(jsonText) which runs the REAL Python verifier
 * in-process (no subprocess, no server) and returns two independent
 * readouts:
 *
 *   - integrity: verify.py's own crypto/structural pass/fail, taken
 *     directly from its return code and printed failure lines. This
 *     script never re-derives or second-guesses that result.
 *   - recorded: the packet's own decision, reason_code, and scope
 *     conformance headline, read directly from the pasted/selected
 *     fixture -- displayed as-is, never classified as pass/fail. (These
 *     are the same fields verify.py itself prints on its "decision: ..."
 *     line when integrity passes.)
 */

const VECTORS_MANIFEST = "vectors/manifest.json";
const BUNDLE_PATH = "actaseal_verify_bundle/verify.py";

const statusEl = document.getElementById("status");
const verifyBtn = document.getElementById("verify-btn");
const inputEl = document.getElementById("packet-input");
const selectEl = document.getElementById("vector-select");
const panelIntegrity = document.getElementById("panel-integrity");
const panelRecorded = document.getElementById("panel-recorded");
const panelTwo = document.getElementById("panel-two");
const panelRecordedWarning = document.getElementById("panel-recorded-warning");

let pyodideReady = null;
let runVerifyFixture = null; // Python callable, set once Pyodide is ready
let callCounter = 0;

function setStatus(text) {
  statusEl.textContent = text;
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

async function loadVectorDropdown() {
  const response = await fetch(VECTORS_MANIFEST);
  const entries = await response.json();
  for (const entry of entries) {
    const option = document.createElement("option");
    option.value = entry.vector_file;
    option.textContent = `${entry.vector_file} -- expects: ${entry.expected_verdict}`;
    selectEl.appendChild(option);
  }
}

selectEl.addEventListener("change", async () => {
  const file = selectEl.value;
  if (!file) return;
  const response = await fetch(`vectors/${file}`);
  const text = await response.text();
  inputEl.value = text;
});

async function initPyodide() {
  setStatus("Loading Pyodide runtime from CDN...");
  const pyodide = await loadPyodide();

  // Best-effort only: some Pyodide builds cannot load or initialize the
  // 'cryptography' wasm package. We do NOT force an install (no micropip
  // fallback here) -- if this fails, verify.py's own _load_crypto_backend()
  // detects it and switches to the vendored pure-Python Ed25519 verifier
  // (see actaseal_verify_bundle/verify.py). ECDSA-signed receipts are only
  // verifiable when this package actually loaded.
  setStatus("Loading the 'cryptography' package (Ed25519/ECDSA signature checks)...");
  try {
    await pyodide.loadPackage("cryptography");
  } catch (err) {
    console.warn("cryptography package failed to load; verify.py will use its pure-Python Ed25519 fallback:", err);
  }

  setStatus("Mounting actaseal_verify_bundle/verify.py into Pyodide's filesystem...");
  const verifierResponse = await fetch(BUNDLE_PATH);
  const verifierSource = await verifierResponse.text();
  pyodide.FS.mkdirTree("/verify_bundle");
  pyodide.FS.writeFile("/verify_bundle/verify.py", verifierSource);

  // Imported as a module (not exec'd as __main__), so verify.py's own
  // `if __name__ == "__main__": sys.exit(main(sys.argv))` guard never
  // fires here -- we call verify.main(argv) ourselves and read its
  // return value directly, exactly like conformance/run_conformance.py
  // does via subprocess, just in-process instead.
  pyodide.runPython(`
import sys, io, contextlib
if "/verify_bundle" not in sys.path:
    sys.path.insert(0, "/verify_bundle")
import verify

def run_verify_on_dir(packet_dir):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = verify.main(["verify.py", packet_dir])
    return {"returncode": code, "stdout": buf.getvalue()}
`);
  runVerifyFixture = pyodide.globals.get("run_verify_on_dir");

  setStatus("Ready.");
  verifyBtn.disabled = false;
  verifyBtn.textContent = "Verify packet";
  return pyodide;
}

function materializeFixture(pyodide, fixture, dir) {
  pyodide.FS.mkdirTree(dir);
  const write = (name, content) => pyodide.FS.writeFile(`${dir}/${name}`, content);
  write("manifest.json", JSON.stringify(fixture.manifest, null, 2));
  write("receipt.json", JSON.stringify(fixture.receipt, null, 2));
  write("acquisition.json", JSON.stringify(fixture.acquisition, null, 2));
  write("custody.json", JSON.stringify(fixture.custody, null, 2));
  write("authentication.json", JSON.stringify(fixture.authentication, null, 2));
  write("ledger_slice.ndjson", fixture.ledger_slice_lines.map((line) => line + "\n").join(""));
}

function renderIntegrity(returncode, stdout) {
  const pass = returncode === 0;
  const lines = stdout
    .split("\n")
    .slice(1)
    .map((line) => line.trim())
    .filter((line) => line.length > 0);

  let html = `<div class="verdict ${pass ? "pass" : "fail"}">${pass ? "PASS" : "FAIL"}</div>`;
  html += `<div class="field"><span class="k">exit code</span><span class="v">${returncode}</span></div>`;
  if (pass) {
    html += `<div class="field"><span class="k">summary</span><span class="v">${escapeHtml(lines[0] || "verified")}</span></div>`;
  } else {
    html += `<ul class="detail">${lines.map((line) => `<li>${escapeHtml(line)}</li>`).join("")}</ul>`;
  }
  panelIntegrity.innerHTML = html;
}

function setPanelTwoTrust(trusted) {
  panelTwo.classList.toggle("untrusted", !trusted);
  panelRecordedWarning.classList.toggle("visible", !trusted);
}

function renderRecorded(fixture) {
  const decision = fixture.receipt && fixture.receipt.decision;
  const reasonCode = fixture.receipt && fixture.receipt.reason_code;
  const headline = fixture.manifest && fixture.manifest.scope_conformance_headline;

  const html = `
    <div class="verdict neutral">${escapeHtml(decision ?? "unknown")}</div>
    <div class="field"><span class="k">reason_code</span><span class="v">${escapeHtml(reasonCode ?? "-")}</span></div>
    <div class="field"><span class="k">scope</span><span class="v">${escapeHtml(headline ?? "-")}</span></div>
    <div class="field"><span class="k">action_id</span><span class="v">${escapeHtml((fixture.manifest && fixture.manifest.action_id) ?? "-")}</span></div>
  `;
  panelRecorded.innerHTML = html;
}

function renderError(message) {
  const html = `<div class="verdict fail">ERROR</div><div class="field"><span class="k">detail</span><span class="v">${escapeHtml(message)}</span></div>`;
  panelIntegrity.innerHTML = html;
  panelRecorded.innerHTML = `<div class="verdict neutral">--</div>`;
  setPanelTwoTrust(true);
}

async function verifyPacket(jsonText) {
  let fixture;
  try {
    fixture = JSON.parse(jsonText);
  } catch (err) {
    renderError(`input is not valid JSON: ${err.message}`);
    return;
  }
  const required = ["manifest", "receipt", "acquisition", "custody", "authentication", "ledger_slice_lines"];
  const missing = required.filter((key) => !(key in fixture));
  if (missing.length > 0) {
    renderError(`packet fixture is missing required field(s): ${missing.join(", ")}`);
    return;
  }

  const pyodide = await pyodideReady;
  callCounter += 1;
  const dir = `/packets/call-${callCounter}`;
  materializeFixture(pyodide, fixture, dir);

  let result;
  try {
    const pyResult = runVerifyFixture(dir);
    result = pyResult.toJs({ dict_converter: Object.fromEntries });
    pyResult.destroy();
  } catch (err) {
    renderError(`verifier crashed: ${err.message}`);
    return;
  }

  renderIntegrity(result.returncode, result.stdout);
  renderRecorded(fixture);
  setPanelTwoTrust(result.returncode === 0);
}
window.verifyPacket = verifyPacket;

verifyBtn.addEventListener("click", () => {
  const text = inputEl.value.trim();
  if (!text) {
    renderError("paste a packet fixture, or select a vector from the dropdown, first");
    return;
  }
  verifyBtn.disabled = true;
  const originalLabel = verifyBtn.textContent;
  verifyBtn.textContent = "Verifying...";
  verifyPacket(text).finally(() => {
    verifyBtn.disabled = false;
    verifyBtn.textContent = originalLabel;
  });
});

pyodideReady = initPyodide().catch((err) => {
  setStatus(`Failed to initialize Pyodide: ${err.message}`);
  throw err;
});
loadVectorDropdown().catch((err) => {
  setStatus(`Failed to load vector list: ${err.message}`);
});
