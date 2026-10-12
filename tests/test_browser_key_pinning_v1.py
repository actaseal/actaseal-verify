"""The browser verifier: key pinning, stated limits, and the same verdicts
as the command line.

Two layers. The first runs in plain Python and pins the only Python the
page adds (browser/glue.py) to the CLI. The second opens the real page
in a real browser, served from a local static server with every other
host blocked, and checks what a person would see.
"""
from __future__ import annotations

import functools
import http.server
import importlib
import json
import socket
import subprocess
import sys
import threading
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
BROWSER = ROOT / "browser"
VECTORS = ROOT / "conformance" / "vectors"
DEMO_ZIP = ROOT / "demo" / "demo-packet-anchored.zip"
KEYRING = ROOT / ".well-known" / "actaseal-keys.json"
PACKET_VECTORS = ["valid", "tampered_chain", "tampered_payload", "wrong_signature"]


def _cli(*args):
    return subprocess.run([sys.executable, str(ROOT / "verify.py"), *map(str, args)], capture_output=True, text=True)


def _packet_key(zip_path: Path) -> str:
    with zipfile.ZipFile(zip_path) as z:
        return json.loads(z.read("manifest.json"))["receipt_public_key_hex"]


def _zip_vector(name: str, out_dir: Path) -> Path:
    out = out_dir / f"{name}.zip"
    with zipfile.ZipFile(out, "w") as z:
        for path in sorted((VECTORS / name).iterdir()):
            if path.is_file() and path.name != "expected.json":
                z.write(path, path.name)
    return out


@pytest.fixture()
def glue(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT))
    monkeypatch.syspath_prepend(str(BROWSER))
    sys.modules.pop("glue", None)
    return importlib.import_module("glue")


# --- layer 1: glue is the CLI ----------------------------------------------

def test_glue_passes_a_pinned_key_exactly_as_the_cli_flag(glue):
    key = _packet_key(DEMO_ZIP)
    code, output, argv = glue.run(str(DEMO_ZIP), receipt_public_key_hex=key)
    cli = _cli(DEMO_ZIP, "--receipt-public-key", key)
    assert argv == [str(DEMO_ZIP), "--receipt-public-key", key]
    assert (code, output) == (cli.returncode, cli.stdout)
    assert code == 0 and "checked against the key you supplied" in output


def test_glue_fails_a_packet_whose_key_is_not_the_pinned_one(glue):
    wrong = "ab" * 32
    code, output, _ = glue.run(str(DEMO_ZIP), receipt_public_key_hex=wrong)
    cli = _cli(DEMO_ZIP, "--receipt-public-key", wrong)
    assert (code, output) == (cli.returncode, cli.stdout)
    assert code == 1 and "RECEIPT_KEY_NOT_TRUSTED" in output


def test_glue_passes_a_keyring_exactly_as_the_cli_flag(glue):
    code, output, argv = glue.run(str(DEMO_ZIP), receipt_keyring_path=str(KEYRING))
    cli = _cli(DEMO_ZIP, "--receipt-keyring", KEYRING)
    assert argv == [str(DEMO_ZIP), "--receipt-keyring", str(KEYRING)]
    assert (code, output) == (cli.returncode, cli.stdout)
    assert code == 0 and "RECEIPT_KEY_CURRENT" in output


@pytest.mark.parametrize("name", PACKET_VECTORS)
def test_glue_gives_the_cli_verdict_on_conformance_vectors(glue, tmp_path, name):
    packet = _zip_vector(name, tmp_path)
    code, output, _ = glue.run(str(packet))
    cli = _cli(packet)
    assert (code, output) == (cli.returncode, cli.stdout)
    assert (code == 0) == (name == "valid")


def test_published_demo_keyring_is_loadable_and_names_the_demo_key():
    sys.path.insert(0, str(ROOT))
    try:
        import verify
    finally:
        sys.path.remove(str(ROOT))
    keyring = verify.load_receipt_keyring(KEYRING)
    with zipfile.ZipFile(DEMO_ZIP) as z:
        kid = json.loads(z.read("receipt.json"))["key_id"]
    assert keyring[kid]["public_key_hex"] == _packet_key(DEMO_ZIP)
    assert json.loads(KEYRING.read_text(encoding="utf-8"))["issuer"] == "demo"


def test_dot_directories_are_published():
    # Without this marker the host skips /.well-known/ entirely.
    assert (ROOT / ".nojekyll").is_file()


def test_page_states_what_it_does_not_cover_and_how_to_run_it_offline():
    html = (BROWSER / "index.html").read_text(encoding="utf-8")
    assert 'id="not-covered"' in html and 'id="offline-note"' in html
    low = " ".join(html.split()).lower()
    assert "does not check" in low
    assert "whether the decision itself was right" in low
    assert "python -m http.server" in low  # the offline steps are concrete


# --- layer 2: the real page in a real browser ------------------------------

class _Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):  # noqa: D102
        pass


@pytest.fixture(scope="module")
def site():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), functools.partial(_Quiet, directory=str(ROOT)))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()
    thread.join(timeout=5)


@pytest.fixture(scope="module")
def browser():
    sync_api = pytest.importorskip("playwright.sync_api")
    with sync_api.sync_playwright() as p:
        try:
            b = p.chromium.launch(args=["--no-sandbox"])
        except Exception as exc:  # browser binary not installed
            pytest.skip(f"no chromium for playwright: {exc}")
        yield b
        b.close()


@pytest.fixture()
def page(browser, site):
    context = browser.new_context()
    blocked: list[str] = []

    def _route(route):
        if route.request.url.startswith(site):
            route.continue_()
        else:
            blocked.append(route.request.url)
            route.abort()

    context.route("**/*", _route)
    pg = context.new_page()
    pg.goto(f"{site}/browser/", wait_until="load")
    pg.wait_for_selector("#engine[data-state=ready]", timeout=120_000)
    pg.blocked = blocked
    yield pg
    context.close()


def _verify(pg, packet: Path):
    pg.set_input_files("#packet", str(packet))
    pg.click("#run")
    pg.wait_for_selector("#result:not([hidden])")
    return pg.inner_text("#verdict"), pg.inner_text("#output")


@pytest.mark.parametrize("name", PACKET_VECTORS)
def test_browser_gives_the_cli_verdict_and_output_on_conformance_vectors(page, tmp_path, name):
    packet = _zip_vector(name, tmp_path)
    cli = _cli(packet)
    verdict, output = _verify(page, packet)
    assert f"exit {cli.returncode}" in verdict
    assert output.strip() == cli.stdout.strip()
    assert ("VERIFICATION FAILED" in verdict) == (name != "valid")
    assert page.blocked == [], "the page reached for another host"


def test_tampered_packet_fails_in_the_browser(page, tmp_path):
    tampered = tmp_path / "tampered.zip"
    with zipfile.ZipFile(DEMO_ZIP) as src, zipfile.ZipFile(tampered, "w") as dst:
        for item in src.infolist():
            data = src.read(item.filename)
            if item.filename == "receipt.json":
                receipt = json.loads(data)
                receipt["decision"] = "BLOCK" if receipt.get("decision") != "BLOCK" else "ALLOW"
                data = json.dumps(receipt).encode()
            dst.writestr(item, data)
    assert _cli(tampered).returncode == 1
    verdict, _output = _verify(page, tampered)
    assert "VERIFICATION FAILED" in verdict and "exit 1" in verdict


def test_unpinned_key_shows_a_warning(page):
    verdict, _ = _verify(page, DEMO_ZIP)
    assert "VERIFIED" in verdict
    status = page.locator("#key-status")
    assert status.get_attribute("data-state") == "unpinned"
    assert status.is_visible()
    text = status.inner_text()
    assert "NOT PINNED" in text
    assert "re-signed" in text


def test_pasted_key_is_shown_as_pinned(page):
    page.fill("#receiptkey", _packet_key(DEMO_ZIP))
    verdict, output = _verify(page, DEMO_ZIP)
    assert "VERIFIED" in verdict and "checked against the key you supplied" in output
    status = page.locator("#key-status")
    assert status.get_attribute("data-state") == "pinned"
    assert "PINNED" in status.inner_text() and "NOT PINNED" not in status.inner_text()


def test_pasted_wrong_key_fails(page):
    page.fill("#receiptkey", "ab" * 32)
    verdict, output = _verify(page, DEMO_ZIP)
    assert "VERIFICATION FAILED" in verdict and "RECEIPT_KEY_NOT_TRUSTED" in output


def test_keyring_file_is_shown_as_pinned(page):
    page.set_input_files("#keyring", str(KEYRING))
    verdict, output = _verify(page, DEMO_ZIP)
    assert "VERIFIED" in verdict and "RECEIPT_KEY_CURRENT" in output
    assert page.locator("#key-status").get_attribute("data-state") == "pinned"


def test_keyring_served_by_the_site_is_labelled_same_origin_not_pinned(page):
    page.click("#sameorigin")
    page.wait_for_selector("#sameorigin-state[data-state=loaded]")
    verdict, output = _verify(page, DEMO_ZIP)
    assert "VERIFIED" in verdict and "RECEIPT_KEY_CURRENT" in output
    status = page.locator("#key-status")
    assert status.get_attribute("data-state") == "same-origin"
    text = status.inner_text()
    assert "SAME-ORIGIN" in text and "only as trustworthy as this site" in text
