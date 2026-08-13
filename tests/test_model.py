from __future__ import annotations

from copy import deepcopy

import pytest

from boule.demo import build_demo_session
from boule.errors import ProtocolError
from boule.model import validate_case, validate_technical_receipt


def test_case_rejects_two_agents_with_one_declared_controller() -> None:
    case = deepcopy(build_demo_session().state.case)
    case["agent_controllers"]["agent_b"] = case["agent_controllers"]["agent_a"]

    with pytest.raises(ProtocolError, match="distinct controllers"):
        validate_case(case)


def test_receipt_is_bound_to_the_frozen_environment() -> None:
    session = build_demo_session()
    case = session.state.case
    receipt = deepcopy(session.state.technical_receipt)
    receipt["environment_digest"] = "00" * 32

    with pytest.raises(ProtocolError, match="wrong frozen environment"):
        validate_technical_receipt(receipt, case)
