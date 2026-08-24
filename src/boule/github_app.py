"""Small, dependency-free GitHub App client used by case provisioning.

The client deliberately exposes only the endpoints needed to create a private
repository and to read/write committed files.  Authentication material is
never included in exception text.
"""

from __future__ import annotations

import base64
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from .canonical import canonical_bytes
from .errors import ProtocolError
from .remote_protocol import strict_json_bytes


@dataclass(frozen=True)
class HttpResponse:
    status: int
    body: bytes
    headers: Mapping[str, str]
    url: str


class GitHubAppError(ProtocolError):
    """A sanitized GitHub App transport or API failure."""


Transport = Callable[[str, str, Mapping[str, str], bytes | None], HttpResponse]


# GitHub responses used here are small JSON documents.  Keep transport failures
# bounded too: an installation token must never cause an unbounded response body
# to be buffered in memory.
MAX_RESPONSE_BYTES = 1_048_576


class _NoRedirect(HTTPRedirectHandler):
    """Turn every redirect into a response error before urllib can replay headers."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001, ANN201
        return None


def _read_response(response: Any, requested_url: str) -> bytes:
    if response.geturl() != requested_url:
        raise GitHubAppError("GitHub API response URL did not match the request")
    body = response.read(MAX_RESPONSE_BYTES + 1)
    if len(body) > MAX_RESPONSE_BYTES:
        raise GitHubAppError("GitHub API response exceeded the size limit")
    return body


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def build_app_jwt(
    app_id: str | int,
    private_key_pem: bytes,
    *,
    now: Callable[[], float] = time.time,
) -> str:
    """Build a short-lived RS256 GitHub App JWT without a JWT dependency."""
    try:
        key = serialization.load_pem_private_key(private_key_pem, password=None)
    except (TypeError, ValueError) as exc:
        raise GitHubAppError("GitHub App private key could not be loaded") from exc
    if not isinstance(key, rsa.RSAPrivateKey):
        raise GitHubAppError("GitHub App private key must be RSA")
    issued = int(now()) - 60
    header = _b64url(canonical_bytes({"alg": "RS256", "typ": "JWT"}))
    payload = _b64url(canonical_bytes({"exp": issued + 540, "iat": issued, "iss": str(app_id)}))
    signed = f"{header}.{payload}".encode("ascii")
    signature = key.sign(signed, padding.PKCS1v15(), hashes.SHA256())
    return f"{header}.{payload}.{_b64url(signature)}"


def urllib_transport(
    method: str, url: str, headers: Mapping[str, str], body: bytes | None
) -> HttpResponse:
    request = Request(url, data=body, headers=dict(headers), method=method)
    try:
        # Do not use urlopen's default opener: its redirect handler may replay an
        # Authorization header at a different origin.
        with build_opener(_NoRedirect()).open(request, timeout=20) as response:  # noqa: S310
            return HttpResponse(
                response.status,
                _read_response(response, url),
                dict(response.headers.items()),
                response.geturl(),
            )
    except HTTPError as exc:
        if 300 <= exc.code < 400:
            raise GitHubAppError("GitHub API redirects are not permitted") from exc
        return HttpResponse(
            exc.code,
            _read_response(exc, url),
            dict(exc.headers.items()) if exc.headers else {},
            exc.geturl(),
        )
    except URLError as exc:
        raise GitHubAppError("GitHub API request failed") from exc


class GitHubAppClient:
    """GitHub App installation client with cached installation credentials."""

    def __init__(
        self,
        *,
        app_id: str | int,
        installation_id: str | int,
        private_key_pem: bytes,
        api_url: str = "https://api.github.com",
        transport: Transport | None = None,
        now: Callable[[], float] = time.time,
    ) -> None:
        if not str(app_id) or not str(installation_id):
            raise ProtocolError("GitHub App and installation identifiers are required")
        parsed_api = urlsplit(api_url)
        if (
            parsed_api.scheme != "https"
            or not parsed_api.hostname
            or parsed_api.username
            or parsed_api.password
            or parsed_api.query
            or parsed_api.fragment
        ):
            raise ProtocolError(
                "GitHub API URL must be credential-free HTTPS without query or fragment"
            )
        self.app_id = str(app_id)
        self.installation_id = str(installation_id)
        self._private_key_pem = private_key_pem
        self.api_url = api_url.rstrip("/")
        self._transport = transport or urllib_transport
        self._now = now
        self._token: str | None = None
        self._token_until = 0.0

    def _json(
        self, method: str, path: str, *, headers: Mapping[str, str], value: Any | None = None
    ) -> tuple[int, Any]:
        body = canonical_bytes(value) if value is not None else None
        request_headers = {"Accept": "application/vnd.github+json", **headers}
        if body is not None:
            request_headers["Content-Type"] = "application/json"
        response = self._transport(
            method,
            self.api_url + path,
            request_headers,
            body,
        )
        if response.url != self.api_url + path:
            raise GitHubAppError("GitHub API response URL did not match the request")
        media_type = response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if response.body and media_type != "application/json" and not media_type.endswith("+json"):
            raise GitHubAppError("GitHub API returned an invalid content type")
        try:
            decoded = strict_json_bytes(response.body) if response.body else None
        except ProtocolError as exc:
            raise GitHubAppError("GitHub API returned invalid JSON") from exc
        return response.status, decoded

    def _installation_token(self) -> str:
        if self._token is not None and self._now() < self._token_until:
            return self._token
        jwt = build_app_jwt(self.app_id, self._private_key_pem, now=self._now)
        status, payload = self._json(
            "POST",
            f"/app/installations/{self.installation_id}/access_tokens",
            headers={"Authorization": f"Bearer {jwt}"},
        )
        if (
            status not in {200, 201}
            or not isinstance(payload, dict)
            or not isinstance(payload.get("token"), str)
        ):
            raise GitHubAppError("GitHub App installation token request was rejected")
        self._token = payload["token"]
        # GitHub tokens normally last an hour.  A bounded cache avoids parsing untrusted timestamps.
        self._token_until = self._now() + 45 * 60
        return self._token

    def request(self, method: str, path: str, value: Any | None = None) -> tuple[int, Any]:
        token = self._installation_token()
        return self._json(method, path, headers={"Authorization": f"Bearer {token}"}, value=value)
