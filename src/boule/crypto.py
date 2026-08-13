from __future__ import annotations

import base64
import binascii
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .canonical import canonical_bytes
from .errors import ProtocolError

PUBLIC_PREFIX = "ed25519:"
SIGNATURE_PREFIX = "ed25519sig:"


def generate_private_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def _encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _decode(text: str) -> bytes:
    try:
        padded = text + "=" * (-len(text) % 4)
        return base64.b64decode(padded, altchars=b"-_", validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ProtocolError("invalid base64 encoding") from exc


def public_key_text(key: Ed25519PrivateKey | Ed25519PublicKey) -> str:
    public = key.public_key() if isinstance(key, Ed25519PrivateKey) else key
    raw = public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return PUBLIC_PREFIX + _encode(raw)


def load_public_key(text: str) -> Ed25519PublicKey:
    if not isinstance(text, str) or not text.startswith(PUBLIC_PREFIX):
        raise ProtocolError("public key must use the ed25519: prefix")
    raw = _decode(text.removeprefix(PUBLIC_PREFIX))
    if len(raw) != 32:
        raise ProtocolError("Ed25519 public key must be 32 bytes")
    return Ed25519PublicKey.from_public_bytes(raw)


def sign_object(private_key: Ed25519PrivateKey, value: Any) -> str:
    return SIGNATURE_PREFIX + _encode(private_key.sign(canonical_bytes(value)))


def verify_object(public_key: str, value: Any, signature: str) -> None:
    if not isinstance(signature, str) or not signature.startswith(SIGNATURE_PREFIX):
        raise ProtocolError("signature must use the ed25519sig: prefix")
    raw = _decode(signature.removeprefix(SIGNATURE_PREFIX))
    if len(raw) != 64:
        raise ProtocolError("Ed25519 signature must be 64 bytes")
    try:
        load_public_key(public_key).verify(raw, canonical_bytes(value))
    except InvalidSignature as exc:
        raise ProtocolError("signature verification failed") from exc
