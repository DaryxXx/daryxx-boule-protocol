"""Small display/log redaction layer for bounded untrusted text projections."""

from __future__ import annotations

import re

ASSIGNMENT = re.compile(
    r"(?i)\b("
    r"(?:[A-Z][A-Z0-9_]{1,80}(?:API_KEY|TOKEN|SECRET|PASSWORD|PASSWD|PRIVATE_KEY))"
    r"|AUTHORIZATION"
    r")\s*([:=])\s*(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)"
)
BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}")
KNOWN_TOKENS = (
    re.compile(r"\bsk-[A-Za-z0-9_-]{8,}"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{8,}"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{8,}"),
    re.compile(r"\bAKIA[A-Z0-9]{16}\b"),
)
PRIVATE_KEY_BLOCK = re.compile(
    r"-----BEGIN [^-\r\n]{0,48}PRIVATE KEY-----.*?"
    r"(?:-----END [^-\r\n]{0,48}PRIVATE KEY-----|$)",
    re.IGNORECASE | re.DOTALL,
)
URL_USERINFO = re.compile(r"(?i)(https?://)[^/\s:@]+:[^@\s/]+@")


def redact_sensitive_text(value: str) -> str:
    """Redact common credential forms without treating ordinary hashes as secrets."""

    value = PRIVATE_KEY_BLOCK.sub("[redacted-private-key-material]", value)
    value = URL_USERINFO.sub(r"\1[redacted]@", value)
    value = ASSIGNMENT.sub(lambda match: f"{match.group(1)}{match.group(2)}[redacted]", value)
    value = BEARER.sub("Bearer [redacted]", value)
    for pattern in KNOWN_TOKENS:
        value = pattern.sub("[redacted-token]", value)
    return value
