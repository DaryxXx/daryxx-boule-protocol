from __future__ import annotations

import pytest

from boule.canonical import canonical_bytes, digest_object
from boule.crypto import (
    generate_private_key,
    load_private_key,
    public_key_text,
    sign_object,
    verify_object,
    write_private_key,
)
from boule.errors import ProtocolError


def test_canonical_encoding_is_stable_under_key_order() -> None:
    left = {"z": [3, 2, 1], "a": {"beta": True, "alpha": "ñ"}}
    right = {"a": {"alpha": "ñ", "beta": True}, "z": [3, 2, 1]}

    assert canonical_bytes(left) == canonical_bytes(right)
    assert digest_object(left) == digest_object(right)


def test_canonical_encoding_rejects_non_finite_numbers() -> None:
    with pytest.raises(ValueError, match="JSON compliant"):
        canonical_bytes({"score": float("nan")})


def test_signature_binds_the_complete_object() -> None:
    private_key = generate_private_key()
    public_key = public_key_text(private_key)
    payload = {"case_id": "case-001", "allocation_bps": {"a": 6000, "b": 4000}}
    signature = sign_object(private_key, payload)

    verify_object(public_key, payload, signature)
    with pytest.raises(ProtocolError, match="signature verification failed"):
        verify_object(
            public_key,
            {"case_id": "case-001", "allocation_bps": {"a": 4000, "b": 6000}},
            signature,
        )


def test_private_key_file_round_trip_and_permissions(tmp_path) -> None:
    key = generate_private_key()
    path = write_private_key(tmp_path / "private" / "session.pem", key)

    assert path.stat().st_mode & 0o777 == 0o600
    assert path.parent.stat().st_mode & 0o777 == 0o700
    assert public_key_text(load_private_key(path)) == public_key_text(key)

    path.chmod(0o644)
    with pytest.raises(ProtocolError, match="permissions"):
        load_private_key(path)
