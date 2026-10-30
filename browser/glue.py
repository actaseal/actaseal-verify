"""Run verify.py's own main() on files the browser page wrote into Pyodide's
filesystem. No check lives here: this only builds the same argv a person
would type and captures what verify.py prints."""

import contextlib
import io


def run(packet_path, sth_public_key_hex=None, tsa_ca_cert_paths=(), anchors_path=None,
        receipt_public_key_hex=None, receipt_keyring_path=None):
    import verify

    argv = ["verify.py", packet_path]
    if sth_public_key_hex:
        argv += ["--sth-public-key", sth_public_key_hex]
    for path in tsa_ca_cert_paths:
        argv += ["--tsa-ca-cert", path]
    if anchors_path:
        argv += ["--anchors", anchors_path]
    if receipt_public_key_hex:
        argv += ["--receipt-public-key", receipt_public_key_hex]
    if receipt_keyring_path:
        argv += ["--receipt-keyring", receipt_keyring_path]
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = verify.main(argv)
    return code, out.getvalue(), argv[1:]


def kind(path):
    """"share_pack" for a share pack (tenant_export.v1: seal.json + events.ndjson), else
    "packet". Only picks which checker runs; each checker does its own checks."""
    import json
    import zipfile

    try:
        with zipfile.ZipFile(path) as archive:
            names = set(archive.namelist())
            if {"manifest.json", "seal.json", "events.ndjson"} <= names:
                if json.loads(archive.read("manifest.json")).get("schema_version") == "tenant_export.v1":
                    return "share_pack"
    except Exception:
        pass
    return "packet"


def run_share_pack(pack_path, public_key_hex=None):
    """Run verify_tenant_export.py's own main() on a share pack, as a person would type it."""
    import verify_tenant_export

    argv = [pack_path]
    if public_key_hex:
        argv += ["--public-key", public_key_hex]
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = verify_tenant_export.main(argv)
    return code, out.getvalue(), argv
