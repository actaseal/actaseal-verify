#!/usr/bin/env python3
"""Fetch the pinned Pyodide runtime that browser/ runs verify.py on.

Writes browser/runtime/: the Pyodide core files plus the prebuilt wheels
`cryptography` needs (resolved from Pyodide's own lock file). Every file
is checked against a pinned SHA-256 -- the release tarball's here, each
wheel's against pyodide-lock.json -- so a re-run reproduces the committed
files byte for byte. Standard library only.

Usage:  python scripts/fetch_browser_runtime.py [--tarball PATH]
"""

import argparse
import hashlib
import json
import shutil
import sys
import tarfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "browser" / "runtime"

PYODIDE_VERSION = "314.0.7"
PYODIDE_URL = ("https://github.com/pyodide/pyodide/releases/download/"
               "%s/pyodide-%s.tar.bz2" % (PYODIDE_VERSION, PYODIDE_VERSION))
PYODIDE_SHA256 = "192b5864e6e6d30ab074861af800cb8b4acb0998ef0f9342c3367448aeb86645"
CORE_FILES = ["pyodide.mjs", "pyodide.asm.mjs", "pyodide.asm.wasm",
              "python_stdlib.zip", "pyodide-lock.json"]
PACKAGES = ["cryptography"]


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def lock_closure(lock, roots):
    pkgs = lock["packages"]
    by_norm = {k.lower().replace("_", "-"): k for k in pkgs}
    seen, stack = [], list(roots)
    while stack:
        name = by_norm[stack.pop().lower().replace("_", "-")]
        if name not in seen:
            seen.append(name)
            stack.extend(pkgs[name]["depends"])
    return sorted(seen)


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--tarball", help="an already-downloaded pyodide-%s.tar.bz2" % PYODIDE_VERSION)
    args = ap.parse_args(argv[1:])

    tarball = Path(args.tarball) if args.tarball else ROOT / ".cache" / Path(PYODIDE_URL).name
    if not tarball.exists():
        tarball.parent.mkdir(parents=True, exist_ok=True)
        print("downloading %s" % PYODIDE_URL)
        urllib.request.urlretrieve(PYODIDE_URL, str(tarball))
    if sha256_file(tarball) != PYODIDE_SHA256:
        print("sha256 mismatch for %s" % tarball)
        return 1

    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True)
    with tarfile.open(str(tarball), "r:bz2") as tf:
        lock = json.load(tf.extractfile("pyodide/pyodide-lock.json"))
        names = lock_closure(lock, PACKAGES)
        wanted = CORE_FILES + [lock["packages"][n]["file_name"] for n in names]
        for member in tf:
            fname = member.name[len("pyodide/"):]
            if fname in wanted:
                (OUT / fname).write_bytes(tf.extractfile(member).read())
    for n in names:
        meta = lock["packages"][n]
        if sha256_file(OUT / meta["file_name"]) != meta["sha256"]:
            print("sha256 mismatch for %s" % meta["file_name"])
            return 1
    print("wrote %s: Pyodide %s core + %s" % (OUT, PYODIDE_VERSION, ", ".join(names)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
