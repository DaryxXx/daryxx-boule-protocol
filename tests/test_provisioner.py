from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from boule.canonical import canonical_bytes, digest_object
from boule.crypto import generate_private_key, public_key_text, sign_object
from boule.errors import ProtocolError
from boule.problem_import import FetchResponse
from boule.provisioner import (
    MARKER_PATH,
    CaseProvisioner,
    GitHubAppRepositoryProvider,
    LocalRepositoryProvider,
)

URL = "https://conjectures.io/problems/erdos686"
CONFIG = {
    "lease_seconds": 3600,
    "absolute_lease_seconds": 14400,
    "stale_seconds": 900,
    "max_renewals": 3,
}


def _fetch(url: str) -> FetchResponse:
    assert url == URL
    body = (Path(__file__).parent / "fixtures/conjectures/erdos686-formalized.html").read_bytes()
    return FetchResponse(body, url)


def test_local_provider_provisions_one_public_scaffold_and_retries(tmp_path: Path) -> None:
    provider = LocalRepositoryProvider(tmp_path / "staging")
    provisioner = CaseProvisioner(provider, tmp_path / "cases")
    first = provisioner.provision(URL, case_id="case-1", config=CONFIG, fetcher=_fetch)
    second = provisioner.provision(URL, case_id="case-1", config=CONFIG, fetcher=_fetch)

    assert first.repository_name == "boule-case-erdos686-bd2f52489d97"
    assert first.repository_created is True
    assert second.repository_created is False
    assert isinstance(first.repository_id, str)
    assert first.repository_id.startswith("local:")
    assert second.repository_id == first.repository_id
    assert first.repository_node_id is None
    assert second.marker_digest == first.marker_digest
    assert first.local_path == second.local_path
    repository = provider.ensure_repository(first.repository_name)
    assert provider.read_file(repository, MARKER_PATH) is not None
    assert provider.read_file(repository, "problem.json") is not None
    assert provider.read_file(repository, ".boule/config.json") is not None
    assert provider.read_file(repository, ".boule/private/maintainer.pem") is None


def test_existing_name_requires_matching_signed_case_marker(tmp_path: Path) -> None:
    provider = LocalRepositoryProvider(tmp_path / "staging")
    provisioner = CaseProvisioner(provider, tmp_path / "cases")
    provisioner.provision(URL, case_id="case-1", config=CONFIG, fetcher=_fetch)
    with pytest.raises(ProtocolError, match="different case"):
        provisioner.provision(URL, case_id="case-2", config=CONFIG, fetcher=_fetch)


def test_preexisting_empty_repository_is_not_silently_claimed(tmp_path: Path) -> None:
    provider = LocalRepositoryProvider(tmp_path / "staging")
    provider.ensure_repository("boule-case-erdos686-bd2f52489d97")
    provisioner = CaseProvisioner(provider, tmp_path / "cases")

    with pytest.raises(ProtocolError, match="no valid Boule case marker"):
        provisioner.provision(URL, case_id="case-1", config=CONFIG, fetcher=_fetch)


def test_repository_name_is_commitment_bound() -> None:
    assert CaseProvisioner.repository_name("example", "sha256:" + "a" * 64) == (
        "boule-case-example-aaaaaaaaaaaa"
    )
    with pytest.raises(ProtocolError):
        CaseProvisioner.repository_name("../example", "sha256:" + "a" * 64)


def test_github_provider_uses_fake_http_and_idempotent_file_create() -> None:
    files: dict[str, bytes] = {}
    created = False

    class FakeClient:
        def request(self, method, path, value=None):
            nonlocal created
            name = "boule-case-example-aaaaaaaaaaaa"
            repository = {
                "id": 101,
                "node_id": "R_kgDOexample",
                "name": name,
                "full_name": f"acme/{name}",
                "owner": {"login": "acme"},
                "private": True,
                "default_branch": "main",
                "html_url": f"https://github.example/acme/{name}",
            }
            if method == "GET" and path == "/repos/acme/boule-case-example-aaaaaaaaaaaa":
                if created:
                    return 200, repository
                return 404, {}
            if method == "POST" and path == "/orgs/acme/repos":
                created = True
                return 201, repository
            if method == "GET" and path.endswith("/git/ref/heads/main"):
                return 200, {"object": {"sha": "c" * 40}}
            if "/contents/" in path:
                location = path.split("/contents/", 1)[1].split("?", 1)[0]
                if method == "GET":
                    if location not in files:
                        return 404, {}
                    return 200, {
                        "encoding": "base64",
                        "content": base64.b64encode(files[location]).decode(),
                    }
                if method == "PUT":
                    files[location] = base64.b64decode(value["content"])
                    return 201, {"commit": {"sha": "cafe"}}
            raise AssertionError((method, path, value))

    provider = GitHubAppRepositoryProvider("acme", client=FakeClient())
    repo = provider.ensure_repository("boule-case-example-aaaaaaaaaaaa")
    assert repo.created is True
    assert provider.write_files(repo, {".boule/case-marker.json": b"marker"}, "bind") == ("c" * 40)
    assert provider.write_files(repo, {".boule/case-marker.json": b"marker"}, "bind") == ("c" * 40)
    assert provider.read_file(repo, ".boule/case-marker.json") == b"marker"


def test_github_same_name_replacement_is_rejected_on_provision_retry(tmp_path: Path) -> None:
    files: dict[str, bytes] = {}

    class MutableRepositoryClient:
        created = False
        repository_id = 101

        def request(self, method, path, value=None):  # noqa: ANN001, ANN201
            name = "boule-case-erdos686-bd2f52489d97"
            repository = {
                "id": self.repository_id,
                "node_id": f"R_kgDO{self.repository_id}",
                "name": name,
                "full_name": f"acme/{name}",
                "owner": {"login": "acme"},
                "private": True,
                "default_branch": "main",
                "html_url": f"https://github.example/acme/{name}",
            }
            base = f"/repos/acme/{name}"
            if method == "GET" and path == base:
                return (200, repository) if self.created else (404, {})
            if method == "POST" and path == "/orgs/acme/repos":
                self.created = True
                return 201, repository
            if method == "GET" and path == base + "/git/ref/heads/main":
                return 200, {"object": {"sha": "c" * 40}}
            if path.startswith(base + "/contents/"):
                location = path.split("/contents/", 1)[1].split("?", 1)[0]
                if method == "GET":
                    if location not in files:
                        return 404, {}
                    return 200, {
                        "encoding": "base64",
                        "content": base64.b64encode(files[location]).decode("ascii"),
                    }
                if method == "PUT":
                    files[location] = base64.b64decode(value["content"])
                    return 201, {"commit": {"sha": "c" * 40}}
            raise AssertionError((method, path, value))

    client = MutableRepositoryClient()
    provisioner = CaseProvisioner(
        GitHubAppRepositoryProvider("acme", client=client), tmp_path / "cases"
    )
    first = provisioner.provision(URL, case_id="case-1", config=CONFIG, fetcher=_fetch)
    marker = json.loads(files[MARKER_PATH])
    assert first.repository_id == 101
    assert first.repository_node_id == "R_kgDO101"
    assert marker["repository_id"] == 101
    assert marker["repository_node_id"] == "R_kgDO101"

    client.repository_id = 202
    with pytest.raises(ProtocolError, match="different case"):
        provisioner.provision(URL, case_id="case-1", config=CONFIG, fetcher=_fetch)


def test_github_provider_rejects_repository_outside_requested_boundary() -> None:
    class WrongRepositoryClient:
        def request(self, method, path, value=None):  # noqa: ANN001, ANN201
            return 200, {
                "id": 101,
                "node_id": "R_kgDOexample",
                "name": "boule-case-example-aaaaaaaaaaaa",
                "full_name": "attacker/boule-case-example-aaaaaaaaaaaa",
                "owner": {"login": "attacker"},
                "private": True,
                "default_branch": "main",
                "html_url": "https://github.example/attacker/boule-case-example-aaaaaaaaaaaa",
            }

    provider = GitHubAppRepositoryProvider("acme", client=WrongRepositoryClient())
    with pytest.raises(ProtocolError, match="requested boundary"):
        provider.ensure_repository("boule-case-example-aaaaaaaaaaaa")


def test_github_provider_rejects_visibility_mismatch() -> None:
    class PublicRepositoryClient:
        def request(self, method, path, value=None):  # noqa: ANN001, ANN201
            name = "boule-case-example-aaaaaaaaaaaa"
            return 200, {
                "id": 101,
                "node_id": "R_kgDOexample",
                "name": name,
                "full_name": f"acme/{name}",
                "owner": {"login": "acme"},
                "private": False,
                "default_branch": "main",
                "html_url": f"https://github.example/acme/{name}",
            }

    provider = GitHubAppRepositoryProvider("acme", client=PublicRepositoryClient())
    with pytest.raises(ProtocolError, match="requested boundary"):
        provider.ensure_repository("boule-case-example-aaaaaaaaaaaa")


def test_case_marker_must_be_signed_by_the_bound_maintainer() -> None:
    maintainer = generate_private_key()
    attacker = generate_private_key()
    expected = {
        "schema": "boule-case-marker/0.2",
        "case_id": "case-1",
        "problem_id": "conjectures:example",
        "task_commitment": "sha256:" + "a" * 64,
        "formal_repository_pin": "b" * 40,
        "policy_digest": "c" * 64,
        "maintainer_key": public_key_text(maintainer),
    }
    marker = {
        **expected,
        "identity_digest": digest_object(expected),
        "signer": public_key_text(attacker),
        "signature": sign_object(attacker, expected),
    }

    with pytest.raises(ProtocolError, match="wrong clerk"):
        CaseProvisioner._verify_marker(canonical_bytes(marker), expected)

    with pytest.raises(ProtocolError, match="invalid fields"):
        CaseProvisioner._verify_marker(canonical_bytes({**marker, "unexpected": True}), expected)
