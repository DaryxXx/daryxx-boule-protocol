from __future__ import annotations

import multiprocessing
from pathlib import Path

import pytest

from boule.crypto import generate_private_key, public_key_text
from boule.errors import ProtocolError
from boule.registry import Registry
from boule.trust_store import TRUST_SCHEMA, read_registry_trust, trust_registry_snapshot


def key() -> str:
    return public_key_text(generate_private_key())


def _competing_pin(path: str, origin: str, presented: str, results) -> None:
    try:
        results.put(
            (
                "ok",
                trust_registry_snapshot(path, origin, presented, 1, "a" * 64),
            )
        )
    except ProtocolError:
        results.put(("changed", None))


def test_first_use_is_canonical_and_idempotent(tmp_path: Path) -> None:
    path = tmp_path / "state" / "registry-trust.json"
    origin = "https://registry.example"
    presented = key()

    assert trust_registry_snapshot(path, origin, presented, 1, "a" * 64) == "first_use"
    assert trust_registry_snapshot(path, origin, presented, 1, "a" * 64) == "pinned"
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.parent.stat().st_mode & 0o777 == 0o700
    assert path.read_bytes() == (
        b'{"origins":{"https://registry.example":{"count":1,"head":"'
        + b"a" * 64
        + b'","key":"'
        + presented.encode()
        + b'"}},'
        + b'"schema":"'
        + TRUST_SCHEMA.encode()
        + b'"}'
    )
    assert read_registry_trust(path, origin) == {
        "key": presented,
        "count": 1,
        "head": "a" * 64,
    }


def test_key_change_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "registry-trust.json"
    trust_registry_snapshot(path, "https://registry.example", key(), 1, "a" * 64)

    with pytest.raises(ProtocolError, match="key changed"):
        trust_registry_snapshot(path, "https://registry.example", key(), 1, "a" * 64)


def test_rejects_malformed_and_unsafe_store(tmp_path: Path) -> None:
    path = tmp_path / "registry-trust.json"
    path.write_bytes(b'{"schema":"boule-registry-trust/0.2","schema":"x","origins":{}}')
    path.chmod(0o600)
    with pytest.raises(ProtocolError, match="strict JSON"):
        trust_registry_snapshot(path, "https://registry.example", key(), 1, "a" * 64)

    path.write_bytes(b"{}")
    path.chmod(0o644)
    with pytest.raises(ProtocolError, match="permissions"):
        trust_registry_snapshot(path, "https://registry.example", key(), 1, "a" * 64)


def test_rejects_non_loopback_http_and_symlink_store(tmp_path: Path) -> None:
    with pytest.raises(ProtocolError, match="loopback"):
        trust_registry_snapshot(tmp_path / "trust.json", "http://example.com", key(), 1, "a" * 64)

    target = tmp_path / "target.json"
    target.write_bytes(b"{}")
    path = tmp_path / "trust.json"
    path.symlink_to(target)
    with pytest.raises(ProtocolError, match="regular file"):
        trust_registry_snapshot(path, "https://registry.example", key(), 1, "a" * 64)


def test_existing_parent_permissions_are_rejected_without_mutation(tmp_path: Path) -> None:
    parent = tmp_path / "shared"
    parent.mkdir(mode=0o755)

    with pytest.raises(ProtocolError, match="parent permissions"):
        trust_registry_snapshot(
            parent / "trust.json", "https://registry.example", key(), 1, "a" * 64
        )
    assert parent.stat().st_mode & 0o777 == 0o755


def test_loopback_http_is_allowed(tmp_path: Path) -> None:
    assert (
        trust_registry_snapshot(
            tmp_path / "trust.json", "http://127.0.0.1:8040", key(), 1, "a" * 64
        )
        == "first_use"
    )


def test_high_water_advances_only_with_a_complete_registry_extension(tmp_path: Path) -> None:
    clerk = generate_private_key()
    registry = Registry.create(tmp_path / "registry.jsonl", clerk)
    trust_path = tmp_path / "client" / "trust.json"
    origin = "https://registry.example"
    first_count = registry.count
    first_head = registry.head
    trust_registry_snapshot(trust_path, origin, registry.clerk_key, first_count, first_head)
    registry.record_proposal(
        {
            "case_id": "case-trust-001",
            "problem": {
                "problem_id": "conjectures:trust",
                "problem": {"title": "Trust extension"},
                "source": {
                    "provider": "conjectures.io",
                    "canonical_problem_url": "https://conjectures.io/problems/trust",
                },
                "task": {
                    "mode": "formalized",
                    "task_id": "trust-formalized-v1",
                    "task_commitment": "sha256:" + "b" * 64,
                    "formal_repository_pin": "1" * 40,
                    "pinned_source_url": "https://github.com/x/y/blob/" + "1" * 40 + "/T.lean",
                },
            },
        }
    )
    proof = registry.chain_proof(first_count, registry.count)

    with pytest.raises(ProtocolError, match="no complete proof"):
        trust_registry_snapshot(
            trust_path, origin, registry.clerk_key, registry.count, registry.head
        )
    assert (
        trust_registry_snapshot(
            trust_path,
            origin,
            registry.clerk_key,
            registry.count,
            registry.head,
            [proof],
        )
        == "advanced"
    )
    with pytest.raises(ProtocolError, match="rolled back"):
        trust_registry_snapshot(trust_path, origin, registry.clerk_key, first_count, first_head)
    with pytest.raises(ProtocolError, match="forks"):
        trust_registry_snapshot(trust_path, origin, registry.clerk_key, registry.count, "f" * 64)


def test_concurrent_different_keys_cannot_both_pin(tmp_path: Path) -> None:
    context = multiprocessing.get_context("fork")
    results = context.Queue()
    path = str(tmp_path / "trust.json")
    origin = "https://registry.example"
    processes = [
        context.Process(target=_competing_pin, args=(path, origin, key(), results))
        for _ in range(2)
    ]
    for process in processes:
        process.start()
    for process in processes:
        process.join(timeout=5)
        assert process.exitcode == 0
    assert sorted(results.get(timeout=1) for _ in processes) == [
        ("changed", None),
        ("ok", "first_use"),
    ]
