"""verify_seal.py: standalone, offline verification of an ActaSeal file seal
(format actaseal.file-seal.v1), checked against seals ActaSeal itself wrote
(conformance/vectors/file_seal_v1), then against tampered copies of them.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
VEC = ROOT / "conformance" / "vectors" / "file_seal_v1"
sys.path.insert(0, str(ROOT))

import verify_seal as vs  # noqa: E402

EXPECTED = json.loads((VEC / "expected.json").read_text())
PUB = EXPECTED["public_key_hex"]
CA = str(VEC / "test_tsa_ca.pem")

def _needs_asn1crypto():
    pytest.importorskip("asn1crypto")


def _load(name):
    return json.loads((VEC / name).read_text(encoding="utf-8"))


@pytest.fixture
def files(tmp_path):
    dst = tmp_path / "files"
    shutil.copytree(VEC / "files", dst)
    return dst


def _codes(result):
    return [f.split(":")[0] for f in result.failures]


def test_seal_hash_matches_what_actaseal_computed():
    assert vs.seal_hash(_load("seal_day1.json")) == EXPECTED["day1"]["seal_sha256"]
    assert vs.seal_hash(_load("seal_day2.json")) == EXPECTED["day2_with_previous"]["seal_sha256"]


def test_vectors_verify_exactly_as_actaseal_reported(files):
    _needs_asn1crypto()
    day1, day2 = _load("seal_day1.json"), _load("seal_day2.json")
    r1 = vs.verify_seal(day1, base=files, expected_public_key_hex=PUB, tsa_ca_paths=[CA], require_timestamp=True)
    r2 = vs.verify_seal(day2, base=files, previous=day1, expected_public_key_hex=PUB, tsa_ca_paths=[CA],
                        require_timestamp=True)
    assert r1.to_dict() == EXPECTED["day1"]
    assert r2.to_dict() == EXPECTED["day2_with_previous"]


def test_changed_file(files):
    (files / "app/2026-10-05.log").write_bytes(b"rewritten\n")
    r = vs.verify_seal(_load("seal_day2.json"), base=files, expected_public_key_hex=PUB, skip_timestamp=True)
    assert r.failures == ["FILE_CHANGED: app/2026-10-05.log"]


def test_missing_file(files):
    (files / "audit/submission.txt").unlink()
    r = vs.verify_seal(_load("seal_day2.json"), base=files, skip_timestamp=True)
    assert r.failures == ["FILE_MISSING: audit/submission.txt"]


def test_edited_seal(files):
    seal = _load("seal_day2.json")
    seal["label"] = "edited"
    assert "SEAL_HASH_MISMATCH" in _codes(vs.verify_seal(seal, base=files, skip_timestamp=True))


def test_wrong_signer(files):
    r = vs.verify_seal(_load("seal_day2.json"), base=files, expected_public_key_hex="00" * 32, skip_timestamp=True)
    assert _codes(r) == ["SIGNER_MISMATCH"]


def test_tampered_signature(files):
    seal = _load("seal_day2.json")
    sig = bytearray(bytes.fromhex(seal["signature"]["signature_hex"]))
    sig[5] ^= 1
    seal["signature"]["signature_hex"] = sig.hex()
    assert _codes(vs.verify_seal(seal, base=files, expected_public_key_hex=PUB, skip_timestamp=True)) == [
        "SIGNATURE_INVALID"]


def test_signer_not_pinned_is_a_warning(files):
    r = vs.verify_seal(_load("seal_day2.json"), base=files, previous=_load("seal_day1.json"), skip_timestamp=True)
    assert r.ok and "SIGNER_NOT_PINNED" in r.warnings


def test_chain(files):
    day1, day2 = _load("seal_day1.json"), _load("seal_day2.json")
    assert vs.verify_seal(day2, base=files, previous=day1, skip_timestamp=True).ok
    assert "CHAIN_NOT_CHECKED" in vs.verify_seal(day2, base=files, skip_timestamp=True).warnings
    edited = dict(day1, label="rewritten")
    assert _codes(vs.verify_seal(day2, base=files, previous=edited, skip_timestamp=True)) == ["PREVIOUS_SEAL_INVALID"]
    assert _codes(vs.verify_seal(day1, base=files, previous=day2, skip_timestamp=True)) == ["CHAIN_BROKEN"]


@pytest.mark.parametrize("bad", ["../outside", "/etc/passwd", "a/../../b", "", "C:/x", "a\\b"])
def test_unsafe_paths_refused(files, bad):
    seal = _load("seal_day1.json")
    seal["files"][0]["path"] = bad
    seal["seal_sha256"] = vs.seal_hash(seal)
    assert "SEAL_PATH_INVALID" in _codes(vs.verify_seal(seal, base=files, skip_timestamp=True))


def test_unknown_format(files):
    assert _codes(vs.verify_seal({"format": "x"}, base=files)) == ["SEAL_FORMAT_UNKNOWN"]


def test_timestamp_needs_a_trusted_ca(files):
    _needs_asn1crypto()
    r = vs.verify_seal(_load("seal_day2.json"), base=files)
    assert _codes(r) == ["TSA_CA_UNKNOWN"]


def test_timestamp_against_the_wrong_ca(files, tmp_path):
    _needs_asn1crypto()
    wrong = tmp_path / "freetsa.pem"
    wrong.write_bytes(vs.FREETSA_CA_PEM)
    r = vs.verify_seal(_load("seal_day2.json"), base=files, tsa_ca_paths=[str(wrong)])
    assert _codes(r) == ["TSA_INVALID"]


def test_timestamp_from_another_seal_does_not_transfer(files):
    _needs_asn1crypto()
    day1, day2 = _load("seal_day1.json"), _load("seal_day2.json")
    day2["tsa_anchor"] = day1["tsa_anchor"]
    r = vs.verify_seal(day2, base=files, tsa_ca_paths=[CA])
    assert "TSA_INVALID" in _codes(r) and r.timestamp_status == "INVALID"


def test_require_timestamp_when_skipped_is_refused(files):
    with pytest.raises(ValueError):
        vs.verify_seal(_load("seal_day2.json"), base=files, skip_timestamp=True, require_timestamp=True)


def test_skipped_timestamp_is_reported(files):
    r = vs.verify_seal(_load("seal_day2.json"), base=files, previous=_load("seal_day1.json"),
                       expected_public_key_hex=PUB, skip_timestamp=True)
    assert r.ok and r.timestamp_status == "NOT_CHECKED" and "TIMESTAMP_NOT_CHECKED" in r.warnings


def test_bundled_freetsa_ca_is_pinned():
    import hashlib

    assert hashlib.sha256(vs.FREETSA_CA_PEM).hexdigest() == vs.FREETSA_CA_SHA256
    pinned = ROOT / "conformance/vectors/archive_attestation_v1/freetsa_root_ca.pem"
    assert vs.FREETSA_CA_PEM == pinned.read_bytes()


# ---------------------------------------------------------------- CLI

def _cli(*args):
    return subprocess.run([sys.executable, str(ROOT / "verify_seal.py"), *map(str, args)],
                          capture_output=True, text=True)


def test_cli_pass_and_fail(files):
    _needs_asn1crypto()
    ok = _cli(VEC / "seal_day2.json", "--base", files, "--previous", VEC / "seal_day1.json",
              "--public-key", PUB, "--tsa-ca", CA, "--require-timestamp")
    assert ok.returncode == 0, ok.stdout + ok.stderr
    assert ok.stdout.startswith("VERIFIED")
    assert "2026-10-05T10:00:00+00:00" in ok.stdout
    (files / "app/2026-10-05.log").write_bytes(b"x")
    bad = _cli(VEC / "seal_day2.json", "--base", files, "--public-key", PUB, "--tsa-ca", CA, "--json")
    assert bad.returncode == 1
    assert json.loads(bad.stdout)["failures"] == ["FILE_CHANGED: app/2026-10-05.log"]


def test_cli_unreadable_seal_exits_two(tmp_path):
    r = _cli(tmp_path / "nope.json", "--base", tmp_path)
    assert r.returncode == 2 and "cannot read" in r.stderr
