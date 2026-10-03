"""Run verify.py's own main() on files the browser page wrote into Pyodide's
filesystem. No check lives here: this only builds the same argv a person
would type and captures what verify.py prints."""

import contextlib
import io


def run(packet_path, sth_public_key_hex=None, tsa_ca_cert_paths=(), anchors_path=None):
    import verify

    argv = ["verify.py", packet_path]
    if sth_public_key_hex:
        argv += ["--sth-public-key", sth_public_key_hex]
    for path in tsa_ca_cert_paths:
        argv += ["--tsa-ca-cert", path]
    if anchors_path:
        argv += ["--anchors", anchors_path]
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = verify.main(argv)
    return code, out.getvalue(), argv[1:]
