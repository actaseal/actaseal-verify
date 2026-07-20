#!/usr/bin/env python3
"""Opt-in wrapper around verify.py that sends a count-only telemetry
ping after verification (PROD11l).

**Deliberately NOT built into verify.py itself.** verify.py's own test
suite asserts it makes zero network calls and has zero imports beyond
`cryptography` (tests/test_verify_demo_packet.py::
test_verify_has_no_external_imports_beyond_cryptography) -- that is a
real, load-bearing promise this repo's README already makes ("Nothing
is sent anywhere"). A telemetry feature that requires `urllib` would
directly break that promise for every user of verify.py, not just the
ones who opt in. This wrapper is the opt-in surface instead: it
imports and calls verify.py's `main()` UNCHANGED, and only after that
call returns does it (optionally) send a ping -- verify.py itself
never knows telemetry exists.

OFF by default: this script only pings if you pass --telemetry AND
TELEMETRY_ENDPOINT below is non-empty (it is empty as shipped, so
--telemetry is currently an inert no-op regardless). When it does
ping, it sends exactly three fields: this wrapper's version, the
verification outcome (PASS/FAIL), and the failure count -- never
packet content, never a filename. Best-effort only: any network
failure is silently swallowed and never affects the exit code.

Usage: python verify_with_telemetry.py [--telemetry] <packet_dir>
(all other arguments are passed through to verify.py's main() unchanged)
"""
from __future__ import annotations

import contextlib
import io
import json
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import verify  # noqa: E402 -- the real, unmodified verifier

WRAPPER_VERSION = "1.0.0"
TELEMETRY_ENDPOINT = ""  # deliberately empty -- see module docstring


def _send_telemetry_ping(*, result: str, failure_count: int) -> None:
    if not TELEMETRY_ENDPOINT:
        return
    try:
        body = json.dumps(
            {"wrapper_version": WRAPPER_VERSION, "result": result, "failure_count": failure_count}
        ).encode("utf-8")
        request = urllib.request.Request(
            TELEMETRY_ENDPOINT, data=body, headers={"Content-Type": "application/json"}, method="POST"
        )
        urllib.request.urlopen(request, timeout=3)
    except Exception:
        pass  # best-effort only -- never affects the verify result


def main(argv: list[str]) -> int:
    telemetry_enabled = "--telemetry" in argv
    inner_argv = [a for a in argv if a != "--telemetry"]

    # Tee verify.py's real stdout through to the terminal AND capture it,
    # so this wrapper can count failure lines for the ping without
    # altering verify.py's own output or behavior at all.
    captured = io.StringIO()
    with contextlib.redirect_stdout(_Tee(sys.stdout, captured)):
        exit_code = verify.main(inner_argv)

    if telemetry_enabled:
        # verify.py prints each failure as its own "  CODE: ..." line
        # (two-space indent) under "VERIFICATION FAILED" -- counting
        # those lines is the failure count, without parsing anything
        # packet-content-specific.
        failure_count = sum(1 for line in captured.getvalue().splitlines() if line.startswith("  "))
        _send_telemetry_ping(result="PASS" if exit_code == 0 else "FAIL", failure_count=failure_count)

    return exit_code


class _Tee:
    def __init__(self, *streams):
        self._streams = streams

    def write(self, data):
        for stream in self._streams:
            stream.write(data)

    def flush(self):
        for stream in self._streams:
            stream.flush()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
