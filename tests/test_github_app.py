from __future__ import annotations

import base64
import json
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from boule.cli import _private_key_file
from boule.errors import ProtocolError
from boule.github_app import (
    MAX_RESPONSE_BYTES,
    GitHubAppClient,
    GitHubAppError,
    HttpResponse,
    build_app_jwt,
    urllib_transport,
)


def _key() -> bytes:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def test_build_app_jwt_is_rs256_and_short_lived() -> None:
    private = _key()
    token = build_app_jwt("123", private, now=lambda: 1_000.0)
    header, payload, signature = token.split(".")

    def decoded(value: str) -> dict[str, object]:
        return json.loads(base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)))

    assert decoded(header) == {"alg": "RS256", "typ": "JWT"}
    assert decoded(payload) == {"exp": 1_480, "iat": 940, "iss": "123"}
    public = serialization.load_pem_private_key(private, password=None).public_key()
    public.verify(
        base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4)),
        f"{header}.{payload}".encode(),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )


def test_client_caches_installation_token_and_sanitizes_rejection() -> None:
    calls: list[tuple[str, str, dict[str, str]]] = []

    def transport(method, url, headers, body):
        calls.append((method, url, dict(headers)))
        if url.endswith("/access_tokens"):
            return HttpResponse(
                201,
                b'{"token":"installation-secret"}',
                {"Content-Type": "application/json"},
                url,
            )
        return HttpResponse(200, b'{"ok":true}', {"Content-Type": "application/json"}, url)

    client = GitHubAppClient(
        app_id="7",
        installation_id="8",
        private_key_pem=_key(),
        transport=transport,
        now=lambda: 1_000.0,
    )
    assert client.request("GET", "/user") == (200, {"ok": True})
    assert client.request("GET", "/user") == (200, {"ok": True})
    assert sum(url.endswith("/access_tokens") for _, url, _ in calls) == 1
    assert any(
        headers["Authorization"].startswith("Bearer installation-secret") for _, _, headers in calls
    )

    rejected = GitHubAppClient(
        app_id="7",
        installation_id="8",
        private_key_pem=_key(),
        transport=lambda method, url, headers, body: HttpResponse(
            401,
            b'{"message":"leaked-token"}',
            {"Content-Type": "application/json"},
            url,
        ),
    )
    with pytest.raises(GitHubAppError, match="token request was rejected") as error:
        rejected.request("GET", "/user")
    assert "leaked-token" not in str(error.value)


@pytest.mark.parametrize(
    "url",
    [
        "http://api.github.example",
        "https://token@api.github.example",
        "https://api.github.example?token=secret",
        "https://api.github.example/#fragment",
    ],
)
def test_client_rejects_unsafe_api_origins(url: str) -> None:
    with pytest.raises(ProtocolError, match="credential-free HTTPS"):
        GitHubAppClient(
            app_id="7",
            installation_id="8",
            private_key_pem=_key(),
            api_url=url,
        )


def test_client_rejects_a_transport_response_from_a_different_url() -> None:
    client = GitHubAppClient(
        app_id="7",
        installation_id="8",
        private_key_pem=_key(),
        transport=lambda method, url, headers, body: HttpResponse(
            201,
            b'{"token":"installation-secret"}',
            {"Content-Type": "application/json"},
            "https://other.example/redirected",
        ),
    )

    with pytest.raises(GitHubAppError, match="response URL did not match"):
        client.request("GET", "/user")


def test_cli_private_key_loader_rejects_symlinks_and_unsafe_modes(tmp_path) -> None:
    key_path = tmp_path / "app.pem"
    key_path.write_bytes(_key())
    key_path.chmod(0o600)
    assert _private_key_file(str(key_path)).startswith(b"-----BEGIN PRIVATE KEY-----")

    alias = tmp_path / "alias.pem"
    alias.symlink_to(key_path)
    with pytest.raises(ProtocolError, match="non-symlink"):
        _private_key_file(str(alias))

    key_path.chmod(0o640)
    with pytest.raises(ProtocolError, match="permissions"):
        _private_key_file(str(key_path))


@contextmanager
def _http_server(handler):  # noqa: ANN001, ANN201
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_urllib_transport_rejects_redirect_without_forwarding_authorization() -> None:
    received_authorization: list[str | None] = []

    class ReceivingHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            received_authorization.append(self.headers.get("Authorization"))
            self.send_response(200)
            self.end_headers()

        def log_message(self, format, *args) -> None:  # noqa: A002, ANN001, ANN201
            return

    with _http_server(ReceivingHandler) as receiving_origin:

        class RedirectingHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                self.send_response(302)
                self.send_header("Location", receiving_origin + "/captured")
                self.end_headers()

            def log_message(self, format, *args) -> None:  # noqa: A002, ANN001, ANN201
                return

        with _http_server(RedirectingHandler) as github_origin:
            with pytest.raises(GitHubAppError, match="redirects are not permitted"):
                urllib_transport(
                    "GET", github_origin + "/v1", {"Authorization": "Bearer test"}, None
                )

    assert received_authorization == []


def test_client_rejects_duplicate_json_keys_and_non_json_content() -> None:
    duplicate = GitHubAppClient(
        app_id="7",
        installation_id="8",
        private_key_pem=_key(),
        transport=lambda method, url, headers, body: HttpResponse(
            201,
            b'{"token":"first","token":"second"}',
            {"Content-Type": "application/json"},
            url,
        ),
    )
    with pytest.raises(GitHubAppError, match="invalid JSON"):
        duplicate.request("GET", "/user")

    wrong_type = GitHubAppClient(
        app_id="7",
        installation_id="8",
        private_key_pem=_key(),
        transport=lambda method, url, headers, body: HttpResponse(
            201,
            b'{"token":"secret"}',
            {"Content-Type": "text/plain"},
            url,
        ),
    )
    with pytest.raises(GitHubAppError, match="content type"):
        wrong_type.request("GET", "/user")


def test_urllib_transport_bounds_response_reads() -> None:
    class OversizedHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"x" * (MAX_RESPONSE_BYTES + 1))

        def log_message(self, format, *args) -> None:  # noqa: A002, ANN001, ANN201
            return

    with _http_server(OversizedHandler) as origin:
        with pytest.raises(GitHubAppError, match="size limit"):
            urllib_transport("GET", origin + "/v1", {}, None)
