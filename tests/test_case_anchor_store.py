from __future__ import annotations

import multiprocessing
from pathlib import Path

import pytest

from boule.case_anchor_store import CASE_ANCHOR_STORE_SCHEMA, CaseAnchorStore
from boule.crypto import generate_private_key, public_key_text
from boule.errors import ProtocolError


def _record(
    *, count: int = 3, head: str | None = "a" * 64, commitment: str = "b"
) -> dict[str, object]:
    return {
        "case_id": "case-anchor-001",
        "problem_id": "conjectures:anchor-v1",
        "task_commitment": "sha256:" + commitment * 64,
        "clerk_key": public_key_text(generate_private_key()),
        "event_count": count,
        "head_event_hash": head,
    }


def _advance(path: str, record: dict[str, object], count: int, head: str, results) -> None:
    try:
        CaseAnchorStore(path).advance(record, count, head)
        results.put(("ok", None))
    except ProtocolError as exc:
        results.put(("error", str(exc)))


def test_missing_store_uses_activation_anchor_and_persists_canonical_high_water(
    tmp_path: Path,
) -> None:
    path = tmp_path / "private" / "case-anchors.json"
    record = _record()
    store = CaseAnchorStore(path)

    assert store.anchor_for(record) == (3, "a" * 64)
    assert store.advance(record, 5, "c" * 64) is None
    assert store.anchor_for(record) == (5, "c" * 64)
    assert path.parent.stat().st_mode & 0o777 == 0o700
    assert path.stat().st_mode & 0o777 == 0o600
    assert (path.parent / ".case-anchors.json.lock").stat().st_mode & 0o777 == 0o600
    assert path.read_bytes().startswith(
        b'{"anchors":{"case-anchor-001":{"case_id":"case-anchor-001",'
    )
    assert b'"schema":"' + CASE_ANCHOR_STORE_SCHEMA.encode() + b'"}' in path.read_bytes()


def test_restart_retains_high_water_and_validates_record_identity(tmp_path: Path) -> None:
    path = tmp_path / "case-anchors.json"
    record = _record()
    CaseAnchorStore(path).advance(record, 4, "b" * 64)

    assert CaseAnchorStore(path).anchor_for(record) == (4, "b" * 64)
    changed = {**record, "problem_id": "conjectures:replacement-v1"}
    with pytest.raises(ProtocolError, match="identity changed"):
        CaseAnchorStore(path).anchor_for(changed)


def test_rejects_rollback_same_height_fork_and_activation_conflict(tmp_path: Path) -> None:
    store = CaseAnchorStore(tmp_path / "case-anchors.json")
    record = _record()
    store.advance(record, 5, "c" * 64)

    with pytest.raises(ProtocolError, match="rolled back"):
        store.advance(record, 4, "b" * 64)
    with pytest.raises(ProtocolError, match="forks at the stored"):
        store.advance(record, 5, "d" * 64)
    with pytest.raises(ProtocolError, match="activation"):
        store.advance(record, 3, "e" * 64)
    with pytest.raises(ProtocolError, match="activation"):
        store.anchor_for({**record, "event_count": 5, "head_event_hash": "f" * 64})


def test_rejects_noncanonical_or_unsafe_store_and_symlink(tmp_path: Path) -> None:
    path = tmp_path / "case-anchors.json"
    record = _record()
    path.write_bytes(b'{"schema":"boule-case-anchor-store/0.1","schema":"x","anchors":{}}')
    path.chmod(0o600)
    with pytest.raises(ProtocolError, match="strict JSON"):
        CaseAnchorStore(path).anchor_for(record)

    path.unlink()
    target = tmp_path / "target.json"
    target.write_bytes(b"{}")
    path.symlink_to(target)
    with pytest.raises(ProtocolError, match="regular file"):
        CaseAnchorStore(path).anchor_for(record)


def test_rejects_existing_parent_with_wrong_permissions(tmp_path: Path) -> None:
    parent = tmp_path / "shared"
    parent.mkdir(mode=0o755)
    with pytest.raises(ProtocolError, match="parent permissions"):
        CaseAnchorStore(parent / "case-anchors.json").anchor_for(_record())
    assert parent.stat().st_mode & 0o777 == 0o755


def test_concurrent_advances_are_serialized(tmp_path: Path) -> None:
    record = _record()
    context = multiprocessing.get_context("fork")
    results = context.Queue()
    path = str(tmp_path / "case-anchors.json")
    processes = [
        context.Process(target=_advance, args=(path, record, 5, "c" * 64, results)),
        context.Process(target=_advance, args=(path, record, 5, "d" * 64, results)),
    ]
    for process in processes:
        process.start()
    for process in processes:
        process.join(timeout=5)
        assert process.exitcode == 0
    outcomes = [results.get(timeout=1) for _ in processes]
    assert sorted(kind for kind, _ in outcomes) == ["error", "ok"]
    assert CaseAnchorStore(path).anchor_for(record) in {(5, "c" * 64), (5, "d" * 64)}
