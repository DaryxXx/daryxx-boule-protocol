from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from boule.crypto import generate_private_key, public_key_text, verify_object
from boule.errors import ProtocolError
from boule.registry import Registry


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
        "status",
        "head_event_hash",
        "event_count",
        "updated_at",
    }
    assert record["status"] == "LIVE"
    assert record["repo_url"] == "https://github.com/boule/case-registry-001"
    assert record["repository_id"] == 101
    assert record["head_event_hash"] == "b" * 64
    snapshot = loaded.signed_snapshot(generated_at="2026-01-01T00:00:08Z")
    signature = snapshot.pop("signature")
    verify_object(
        loaded.clerk_key, {"domain": "boule-problem-registry-snapshot/0.6", **snapshot}, signature
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
