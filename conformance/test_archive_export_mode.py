"""Smoke test for verify.py's --archive-export mode (the AS 1215
engagement-archive verification path, distinct from the dispute-packet
flow the rest of this repo's fixtures cover). The full, real-fixture
proof (a genuine inspection-pack export verified with the server
stopped and no network) lives in the private ActaSeal repo's
tests/test_export_offline_verifier_v1.py -- this test only confirms
the new functions import and run correctly in THIS repo's own
environment, since a full inspection-pack fixture needs the private
repo's archive engine to generate (ProofLedger, ArchiveAttestation,
FileTransparencyLog) and isn't duplicated here.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def _load_verify_module():
    spec = importlib.util.spec_from_file_location("verify", REPO_ROOT / "verify.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_archive_export_functions_are_importable_and_named_consistently():
    verify = _load_verify_module()
    assert callable(verify.verify_archive_export)
    assert callable(verify.load_archive_export)
    assert callable(verify.verify_archive_export_ledger_slice)
    assert verify.ARCHIVE_EXPORT_SCHEMA_VERSION == "inspection_pack.v1"


def test_merkle_root_helpers_match_the_leaf_hash_construction_used_elsewhere():
    """_merkle_root_from_leaves/_compute_workpaper_set_hashes must use
    THIS file's own _leaf_hash/_node_hash (the same domain-separated
    construction the SCITT-receipt inclusion-proof check already uses),
    not a second hashing scheme."""
    verify = _load_verify_module()
    single_leaf_root = verify._merkle_root_from_leaves([verify._leaf_hash(b"only-leaf")])
    assert single_leaf_root == verify._leaf_hash(b"only-leaf")  # single-leaf tree: root IS the leaf

    subject = verify._compute_workpaper_set_hashes(["a" * 64, "b" * 64])
    assert set(subject.keys()) == {"sha256", "sha3-256"}
    assert len(subject["sha256"]) == 64
    assert len(subject["sha3-256"]) == 64


def test_verify_archive_export_reports_unreadable_for_a_missing_directory(tmp_path):
    verify = _load_verify_module()
    ok, failures = verify.verify_archive_export(tmp_path / "does-not-exist")
    assert not ok
    assert any("UNREADABLE_ARCHIVE_EXPORT" in f for f in failures)


def test_verify_archive_export_workpaper_set_tampered_by_name(tmp_path):
    """Minimal, self-built export directory (not a real ActaSeal
    fixture) -- enough to exercise the workpaper-set-vs-attestation
    mismatch path standalone in this repo."""
    verify = _load_verify_module()
    events = [{
        "event_type": "ArchiveAttestationIssued", "tenant_id": "t", "workspace_id": "w", "actor_id": "a",
        "action_id": "eng-1", "action_type": "engagement_archive", "timestamp": "2026-01-01T00:00:00+00:00",
        "schema_version": "ledger_event.v1", "payload": {"engagement_id": "eng-1"},
    }]
    material = {f: events[0][f] for f in verify.EVENT_MATERIAL_FIELDS if f in events[0]}
    events[0]["payload_hash"] = verify.canonical_hash(events[0]["payload"])
    material = {f: events[0].get(f) for f in verify.EVENT_MATERIAL_FIELDS}
    events[0]["event_id"] = verify.canonical_hash(dict(material, event_id_basis=verify.EVENT_ID_BASIS))
    events[0]["event_hash"] = verify.canonical_hash(dict(material, event_id=events[0]["event_id"]))
    events[0]["previous_event_hash"] = None

    manifest = {
        "schema_version": "inspection_pack.v1", "engagement_id": "eng-1", "workpaper_count": 1,
        "event_count": 1, "chain_start_previous_event_hash": None,
    }
    workpaper_index = {"workpapers": [{"workpaper_id": "wp-1", "content_hash": "9" * 64}]}
    attestation = {
        "engagement_id": "eng-1", "workpaper_hashes": ["a" * 64],
        "evidence_record": {"subject_hashes": verify._compute_workpaper_set_hashes(["a" * 64]), "chains": []},
    }

    (tmp_path / "manifest.json").write_text(json.dumps(manifest))
    (tmp_path / "workpaper_index.json").write_text(json.dumps(workpaper_index))
    (tmp_path / "archive_attestation.json").write_text(json.dumps(attestation))
    (tmp_path / "ledger_slice.ndjson").write_text(json.dumps(events[0]) + "\n")

    ok, failures = verify.verify_archive_export(tmp_path)
    assert not ok
    assert verify.ARCHIVE_EXPORT_WORKPAPER_SET_TAMPERED in failures
