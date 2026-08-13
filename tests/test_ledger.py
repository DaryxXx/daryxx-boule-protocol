from __future__ import annotations

from copy import deepcopy

import pytest

from boule.demo import build_demo_session
from boule.errors import ProtocolError
from boule.ledger import Ledger
from boule.protocol import replay_ledger


def test_demo_ledger_round_trip_and_replay(tmp_path) -> None:
    session = build_demo_session()
    path = session.ledger.write(tmp_path / "ledger.jsonl")

    loaded = Ledger.read(path)
    replayed = replay_ledger(loaded)

    assert replayed.summary() == session.state.summary()
    assert replayed.phase == "provisional"


def test_ledger_write_is_append_only_at_the_file_boundary(tmp_path) -> None:
    ledger = build_demo_session().ledger
    path = ledger.write(tmp_path / "ledger.jsonl")

    with pytest.raises(FileExistsError):
        ledger.write(path)


def test_tampered_payload_is_rejected() -> None:
    entries = deepcopy(list(build_demo_session().ledger.entries))
    entries[1]["event"]["payload"]["summary"] = "retrospectively rewritten"

    with pytest.raises(ProtocolError, match="signature verification failed"):
        Ledger(entries).verify()


def test_truncated_ledger_does_not_masquerade_as_final() -> None:
    entries = deepcopy(list(build_demo_session().ledger.entries[:-1]))

    state = replay_ledger(Ledger(entries))

    assert state.phase == "reviewing"
    assert state.decision is None
    assert state.summary()["transcript_status"] == "partial"


def test_receipt_times_cannot_move_backwards() -> None:
    entries = deepcopy(list(build_demo_session().ledger.entries))
    entries[2]["received_at"] = "2029-12-31T23:59:00Z"

    with pytest.raises(ProtocolError, match="receipt time moved backwards"):
        Ledger(entries).verify()
