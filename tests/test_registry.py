from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest

from boule.canonical import digest_object
from boule.crypto import generate_private_key, public_key_text, verify_object
from boule.errors import ProtocolError
from boule.registry import Registry


def ref_manifest(main: str = "d") -> dict[str, object]:
    return {
        "schema": "boule-git-ref-manifest/0.1",
        "refs": [{"name": "refs/heads/main", "object_id": main * 40}],
    }


def problem(commitment: str = "a") -> dict[str, object]:
    return {
        "case_id": "case-registry-001",
        "problem": {
            "problem_id": "conjectures:fc-registry-formalized-v1",
            "problem": {"title": "A pinned problem"},
            "source": {
                "provider": "conjectures.io",
                "canonical_problem_url": "https://conjectures.io/problems/registry",
            },
            "task": {
                "mode": "formalized",
                "task_id": "fc-registry-formalized-v1",
                "task_commitment": "sha256:" + commitment * 64,
                "formal_repository_pin": "1" * 40,
                "pinned_source_url": "https://github.com/x/y/blob/" + "1" * 40 + "/A.lean",
            },
        },
    }


def test_registry_replays_state_machine_and_signed_snapshot(tmp_path) -> None:
    clerk = generate_private_key()
    registry = Registry.create(tmp_path / "registry.jsonl", clerk, "2026-01-01T00:00:00Z")
    registry.record_proposal(problem(), "2026-01-01T00:00:01Z")
    registry.admit("case-registry-001", "2026-01-01T00:00:02Z")
    registry.start_provisioning("case-registry-001", "2026-01-01T00:00:03Z")
    registry.mark_provision_failed(
        "case-registry-001", "worker unavailable", "2026-01-01T00:00:04Z"
    )
    registry.retry_provisioning("case-registry-001", "2026-01-01T00:00:05Z")
    case_clerk = generate_private_key()
    registry.record_repository(
        "case-registry-001",
        "https://github.com/boule/case-registry-001",
        public_key_text(case_clerk),
        "c" * 64,
        "d" * 40,
        101,
        "R_registry101",
        "2026-01-01T00:00:06Z",
    )
    registry.mark_live(
        "case-registry-001",
        "https://clerk.example/case-registry-001",
        "b" * 64,
        4,
        "2026-01-01T00:00:07Z",
    )

    loaded = Registry.open(tmp_path / "registry.jsonl", clerk)
    record = loaded.problem("case-registry-001")
    assert set(record) == {
        "case_id",
        "problem_id",
        "title",
        "source_name",
        "source_url",
        "task_id",
        "task_commitment",
        "task_mode",
        "formal_repository_pin",
        "pinned_source_url",
        "repo_url",
        "clerk_url",
        "clerk_key",
        "marker_digest",
        "repository_commit",
        "repository_id",
        "repository_node_id",
        "marker_repository_id",
        "marker_repository_node_id",
        "repository_migrations",
        "status",
        "head_event_hash",
        "event_count",
        "updated_at",
    }
    assert record["status"] == "LIVE"
    assert record["repo_url"] == "https://github.com/boule/case-registry-001"
    assert record["repository_id"] == 101
    assert record["marker_repository_id"] == 101
    assert record["marker_repository_node_id"] == "R_registry101"
    assert record["repository_migrations"] == []
    assert record["head_event_hash"] == "b" * 64
    snapshot = loaded.signed_snapshot(generated_at="2026-01-01T00:00:08Z")
    signature = snapshot.pop("signature")
    verify_object(
        loaded.clerk_key, {"domain": "boule-problem-registry-snapshot/0.6", **snapshot}, signature
    )


def test_registry_records_signed_live_repository_migration_without_rebinding_marker(
    tmp_path: Path,
) -> None:
    clerk = generate_private_key()
    registry = Registry.create(tmp_path / "registry.jsonl", clerk, "2026-01-01T00:00:00Z")
    registry.record_proposal(problem(), "2026-01-01T00:00:01Z")
    registry.admit("case-registry-001", "2026-01-01T00:00:02Z")
    registry.start_provisioning("case-registry-001", "2026-01-01T00:00:03Z")
    registry.record_repository(
        "case-registry-001",
        "https://staging.example/case-registry-001",
        public_key_text(generate_private_key()),
        "c" * 64,
        "d" * 40,
        "local:" + "1" * 32,
        None,
        "2026-01-01T00:00:04Z",
    )
    registry.mark_live(
        "case-registry-001",
        "https://clerk.example/case-registry-001",
        None,
        0,
        "2026-01-01T00:00:05Z",
    )

    expected_head = registry.head
    manifest = {
        "schema": "boule-git-ref-manifest/0.1",
        "refs": [
            {"name": "refs/heads/agent/private-method", "object_id": "a" * 40},
            {"name": "refs/heads/main", "object_id": "d" * 40},
        ],
    }
    manifest_digest = "sha256:" + digest_object(manifest)
    observed_count = registry.count
    with pytest.raises(ProtocolError, match="registry head changed"):
        registry.migrate_repository(
            "case-registry-001",
            "0" * 64,
            "https://github.com/BouleProtocol/case-registry-001",
            "d" * 40,
            202,
            "R_registry202",
            "sha256:" + "f" * 64,
            manifest,
            manifest_digest,
            None,
            0,
            "2026-01-01T00:00:06Z",
        )
    assert registry.count == observed_count
    pre_migration_bytes = (tmp_path / "registry.jsonl").read_bytes()
    migrated = registry.migrate_repository(
        "case-registry-001",
        str(expected_head),
        "https://github.com/BouleProtocol/case-registry-001",
        "d" * 40,
        202,
        "R_registry202",
        "sha256:" + "f" * 64,
        manifest,
        manifest_digest,
        "a" * 64,
        3,
        "2026-01-01T00:00:06Z",
    )

    assert migrated["status"] == "LIVE"
    assert migrated["repo_url"] == "https://github.com/BouleProtocol/case-registry-001"
    assert migrated["repository_id"] == 202
    assert migrated["repository_node_id"] == "R_registry202"
    assert migrated["marker_repository_id"] == "local:" + "1" * 32
    assert migrated["marker_repository_node_id"] is None
    assert len(migrated["repository_migrations"]) == 1
    transition = migrated["repository_migrations"][0]
    assert transition["marker_digest"] == "c" * 64
    assert transition["from_repository_id"] == "local:" + "1" * 32
    assert transition["to_repository_id"] == 202
    assert transition["marker_blob_sha256"] == "sha256:" + "f" * 64
    assert transition["ref_manifest_schema"] == "boule-git-ref-manifest/0.1"
    assert transition["ref_manifest_count"] == 2
    assert transition["ref_manifest_main"] == "d" * 40
    assert transition["ref_manifest_sha256"] == manifest_digest
    assert transition["case_head_event_hash"] == "a" * 64
    assert transition["case_event_count"] == 3
    assert transition["registry_seq"] == 6
    assert transition["registry_entry_hash"] == registry.head
    assert transition["received_at"] == "2026-01-01T00:00:06Z"
    assert migrated["head_event_hash"] == "a" * 64
    assert migrated["event_count"] == 3
    assert "private-method" not in json.dumps(migrated)

    observed_count = registry.count
    retried = registry.migrate_repository(
        "case-registry-001",
        str(expected_head),
        migrated["repo_url"],
        migrated["repository_commit"],
        migrated["repository_id"],
        migrated["repository_node_id"],
        "sha256:" + "f" * 64,
        manifest,
        transition["ref_manifest_sha256"],
        "b" * 64,
        4,
        "2026-01-01T00:00:07Z",
    )
    assert registry.count == observed_count
    assert retried == migrated
    assert Registry.read(tmp_path / "registry.jsonl").problem("case-registry-001") == migrated

    stale = Registry.open(tmp_path / "registry.jsonl", clerk)
    writer = Registry.open(tmp_path / "registry.jsonl", clerk)
    concurrent = problem("b")
    concurrent["case_id"] = "case-registry-002"
    writer.record_proposal(concurrent, "2026-01-01T00:00:08Z")
    refreshed_retry = stale.migrate_repository(
        "case-registry-001",
        str(expected_head),
        migrated["repo_url"],
        migrated["repository_commit"],
        migrated["repository_id"],
        migrated["repository_node_id"],
        "sha256:" + "f" * 64,
        manifest,
        transition["ref_manifest_sha256"],
        "b" * 64,
        4,
        "2026-01-01T00:00:09Z",
    )
    assert refreshed_retry == migrated
    assert stale.count == writer.count

    (tmp_path / "registry.jsonl").write_bytes(pre_migration_bytes)
    with pytest.raises(ProtocolError, match="truncated"):
        stale.migrate_repository(
            "case-registry-001",
            str(expected_head),
            migrated["repo_url"],
            migrated["repository_commit"],
            migrated["repository_id"],
            migrated["repository_node_id"],
            "sha256:" + "f" * 64,
            manifest,
            transition["ref_manifest_sha256"],
            "b" * 64,
            4,
            "2026-01-01T00:00:10Z",
        )


def test_registry_detects_tampering_and_commitment_deduplication(tmp_path) -> None:
    clerk = generate_private_key()
    registry = Registry.create(tmp_path / "registry.jsonl", clerk, "2026-01-01T00:00:00Z")
    registry.record_proposal(problem(), "2026-01-01T00:00:01Z")
    duplicate = problem()
    duplicate["case_id"] = "case-registry-002"
    with pytest.raises(ProtocolError, match="task commitment"):
        registry.record_proposal(duplicate, "2026-01-01T00:00:02Z")

    entries = deepcopy(list(registry.entries))
    entries[1]["event"]["payload"]["case_id"] = "case-registry-999"
    with pytest.raises(ProtocolError, match="hash mismatch"):
        Registry(entries)


def test_registry_retries_are_bounded(tmp_path) -> None:
    clerk = generate_private_key()
    registry = Registry.create(
        tmp_path / "registry.jsonl", clerk, "2026-01-01T00:00:00Z", max_retries=1
    )
    registry.record_proposal(problem(), "2026-01-01T00:00:01Z")
    registry.admit("case-registry-001", "2026-01-01T00:00:02Z")
    registry.start_provisioning("case-registry-001", "2026-01-01T00:00:03Z")
    registry.mark_provision_failed("case-registry-001", "no worker", "2026-01-01T00:00:04Z")
    registry.retry_provisioning("case-registry-001", "2026-01-01T00:00:05Z")
    registry.mark_provision_failed("case-registry-001", "still no worker", "2026-01-01T00:00:06Z")
    with pytest.raises(ProtocolError, match="invalid registry state transition"):
        registry.retry_provisioning("case-registry-001", "2026-01-01T00:00:07Z")


def test_refresh_rejects_a_longer_signed_fork(tmp_path: Path) -> None:
    clerk = generate_private_key()
    observed_path = tmp_path / "observed.jsonl"
    fork_path = tmp_path / "fork.jsonl"
    observed = Registry.create(observed_path, clerk, "2026-01-01T00:00:00Z")
    observed.record_proposal(problem("a"), "2026-01-01T00:00:01Z")

    fork = Registry.create(fork_path, clerk, "2026-01-01T00:00:00Z")
    alternate = problem("b")
    alternate["case_id"] = "case-registry-fork"
    fork.record_proposal(alternate, "2026-01-01T00:00:01Z")
    fork.admit("case-registry-fork", "2026-01-01T00:00:02Z")
    observed_path.write_bytes(fork_path.read_bytes())

    with pytest.raises(ProtocolError, match="conflicts at the observed length"):
        observed.refresh()


def test_registry_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    clerk = generate_private_key()
    path = tmp_path / "registry.jsonl"
    Registry.create(path, clerk, "2026-01-01T00:00:00Z")
    raw = path.read_bytes().replace(b'"seq":0', b'"seq":0,"seq":0')
    path.write_bytes(raw)

    with pytest.raises(ProtocolError, match="strict JSON"):
        Registry.read(path)


def test_append_rejects_rollback_or_fork_after_observation(tmp_path: Path) -> None:
    clerk = generate_private_key()
    path = tmp_path / "registry.jsonl"
    observed = Registry.create(path, clerk, "2026-01-01T00:00:00Z")
    genesis = path.read_bytes()
    observed.record_proposal(problem("a"), "2026-01-01T00:00:01Z")
    path.write_bytes(genesis)

    with pytest.raises(ProtocolError, match="truncated after observation"):
        observed.admit("case-registry-001", "2026-01-01T00:00:02Z")


def test_signed_snapshot_rejects_records_from_an_obsolete_head(tmp_path: Path) -> None:
    clerk = generate_private_key()
    registry = Registry.create(tmp_path / "registry.jsonl", clerk)
    expected_head = registry.head
    records = registry.problems()
    registry.record_proposal(problem())

    with pytest.raises(ProtocolError, match="changed while snapshot"):
        registry.signed_snapshot(records, expected_head=expected_head)
