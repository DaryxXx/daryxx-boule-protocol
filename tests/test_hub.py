from __future__ import annotations

import base64
import json
import shutil
import threading
from contextlib import contextmanager
from pathlib import Path
from urllib.request import urlopen

import pytest

from boule.clerk_api import build_server as build_clerk_server
from boule.crypto import generate_private_key, public_key_text, verify_object
from boule.errors import ProtocolError
from boule.hub import DEFAULT_CASE_CONFIG, Hub
from boule.problem_import import FetchResponse
from boule.provisioner import MARKER_PATH, GitHubAppRepositoryProvider
from boule.remote_protocol import verify_snapshot
from boule.session_store import load_maintainer_key

URL = "https://conjectures.io/problems/erdos686-erdos-686-variants-four"
FIXTURE = Path(__file__).parent / "fixtures/conjectures/erdos686-formalized.html"


def fetch_problem(url: str) -> FetchResponse:
    assert url == URL
    return FetchResponse(FIXTURE.read_bytes(), URL)


class FakeGitHubClient:
    """In-memory HTTPS GitHub API surface used by the hub integration path."""

    def __init__(self) -> None:
        self.created = False
        self.files: dict[str, bytes] = {}
        self.requests: list[tuple[str, str]] = []

    def request(self, method: str, path: str, value=None):  # noqa: ANN001, ANN201
        self.requests.append((method, path))
        name = "boule-case-erdos686-erdos-686-variants-four-bd2f52489d97"
        repository = f"/repos/acme/{name}"
        payload = {
            "id": 1,
            "node_id": "R_kgDOBoule",
            "name": name,
            "full_name": f"acme/{name}",
            "owner": {"login": "acme"},
            "private": True,
            "default_branch": "main",
            "html_url": f"https://github.example/acme/{name}",
        }
        if method == "GET" and path == repository:
            return (200, payload) if self.created else (404, {})
        if method == "POST" and path == "/orgs/acme/repos":
            assert value == {
                "name": "boule-case-erdos686-erdos-686-variants-four-bd2f52489d97",
                "private": True,
            }
            self.created = True
            return 201, payload
        if method == "GET" and path == repository + "/git/ref/heads/main":
            return 200, {"object": {"sha": "c" * 40}}
        if path.startswith(repository + "/contents/"):
            location = path.split("/contents/", 1)[1].split("?", 1)[0]
            if method == "GET":
                if location not in self.files:
                    return 404, {}
                return 200, {
                    "encoding": "base64",
                    "content": base64.b64encode(self.files[location]).decode("ascii"),
                }
            if method == "PUT":
                assert value is not None
                self.files[location] = base64.b64decode(value["content"])
                return 201, {"commit": {"sha": "c" * 40}}
        raise AssertionError((method, path, value))


def provisioned_hub(tmp_path: Path) -> tuple[Hub, str, FakeGitHubClient]:
    hub = Hub.initialize(tmp_path / "hub")
    proposal, created = hub.propose(URL, fetcher=fetch_problem)
    assert created is True
    admitted = hub.admit(proposal["case_id"], fetcher=fetch_problem)
    client = FakeGitHubClient()
    result = hub.provision(
        admitted["case_id"],
        GitHubAppRepositoryProvider("acme", client=client),
        fetcher=fetch_problem,
    )
    assert result.repository_url.startswith("https://")
    return hub, admitted["case_id"], client


@contextmanager
def running_clerk(hub: Hub, case_id: str):
    workspace = hub.case_workspace(case_id)
    server = build_clerk_server(workspace, load_maintainer_key(workspace), host="127.0.0.1", port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_initialize_creates_private_control_plane_and_signed_registry(tmp_path: Path) -> None:
    hub = Hub.initialize(tmp_path / "hub")

    assert hub.registry.count == 1
    assert hub.config["case_config"] == DEFAULT_CASE_CONFIG
    assert (hub.root / "intake").is_dir()
    assert (hub.root / "cases").is_dir()
    assert (hub.control / "config.json").stat().st_mode & 0o777 == 0o644
    assert hub.key_path.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        Hub.initialize(hub.root)


def test_propose_deduplicates_by_commitment_and_admit_reimports_independently(
    tmp_path: Path,
) -> None:
    hub = Hub.initialize(tmp_path / "hub")
    proposal, created = hub.propose(URL, fetcher=fetch_problem)
    repeated, created_again = hub.propose(URL, fetcher=fetch_problem)

    assert created is True
    assert created_again is False
    assert repeated == proposal
    assert hub.registry.count == 2

    changed = FIXTURE.read_bytes().replace(
        b"sha256:bd2f52489d971db4ae4a8c79e106c7fd3080827a8d4dc72f3154e395da098528",
        b"sha256:" + b"b" * 64,
    )
    with pytest.raises(ProtocolError, match="no longer matches"):
        hub.admit(proposal["case_id"], fetcher=lambda _: FetchResponse(changed, URL))
    assert hub.registry.problem(proposal["case_id"])["status"] == "PROPOSED"

    admitted = hub.admit(proposal["case_id"], fetcher=fetch_problem)
    assert admitted["status"] == "ADMITTED"


def test_tick_recovers_provisioning_case_without_repository_identity(tmp_path: Path) -> None:
    hub = Hub.initialize(tmp_path / "hub")
    proposal, _ = hub.propose(URL, fetcher=fetch_problem)
    hub.admit(proposal["case_id"], fetcher=fetch_problem)
    hub.registry.start_provisioning(proposal["case_id"])

    actions = hub.tick()["actions"]

    assert actions["provision"] == [proposal["case_id"]]
    assert actions["activate"] == []


def test_provision_binds_signed_marker_to_case_clerk_and_is_idempotent(tmp_path: Path) -> None:
    hub, case_id, client = provisioned_hub(tmp_path)
    record = hub.registry.problem(case_id)
    marker = json.loads(client.files[MARKER_PATH])
    identity = {
        key: marker[key] for key in marker if key not in {"identity_digest", "signer", "signature"}
    }

    assert record["status"] == "PROVISIONING"
    assert (
        record["repo_url"]
        == "https://github.example/acme/boule-case-erdos686-erdos-686-variants-four-bd2f52489d97"
    )
    assert marker["case_id"] == case_id
    assert marker["maintainer_key"] == record["clerk_key"]
    assert marker["signer"] == record["clerk_key"]
    verify_object(marker["signer"], identity, marker["signature"])
    assert hub.case_workspace(case_id).config["maintainer_key"] == record["clerk_key"]

    class RepositorySubstitute:
        calls = 0

        def ensure_repository(self, name: str):  # noqa: ANN201
            self.calls += 1
            raise AssertionError(f"provider was called for {name}")

    substitute = RepositorySubstitute()
    retry = hub.provision(case_id, substitute, fetcher=fetch_problem)
    assert retry.repository_created is False
    assert retry.repository_url == record["repo_url"]
    assert retry.commit == record["repository_commit"]
    assert substitute.calls == 0
    assert hub.registry.problem(case_id)["marker_digest"] == record["marker_digest"]


def test_case_workspace_ignores_duplicate_commitment_shadow_and_uses_registry_clerk(
    tmp_path: Path,
) -> None:
    hub, case_id, _ = provisioned_hub(tmp_path)
    canonical = hub.case_workspace(case_id)
    shadow = hub.cases_root / "000-shadow"
    shutil.copytree(canonical.root, shadow)
    shadow_config = json.loads((shadow / ".boule" / "config.json").read_text())
    shadow_config["maintainer_key"] = public_key_text(generate_private_key())
    (shadow / ".boule" / "config.json").write_text(json.dumps(shadow_config))

    assert hub.case_workspace(case_id).root == canonical.root
    record = hub.registry.problem(case_id)

    def fetcher(provisional: dict[str, object]) -> dict[str, object]:
        assert provisional["clerk_key"] == record["clerk_key"]
        return {"snapshot": {"head_event_hash": None, "event_count": 0}}

    hub.activate(case_id, "https://clerk.example/cases/erdos686", fetcher=fetcher)


def test_case_workspace_rejects_symlinked_canonical_workspace(tmp_path: Path) -> None:
    hub, case_id, _ = provisioned_hub(tmp_path)
    workspace = hub.case_workspace(case_id)
    replacement = tmp_path / "replacement"
    workspace.root.rename(replacement)
    workspace.root.symlink_to(replacement, target_is_directory=True)

    with pytest.raises(ProtocolError, match="must not be a symlink"):
        hub.case_workspace(case_id)


def test_case_workspace_rejects_changed_import_projection(tmp_path: Path) -> None:
    hub, case_id, _ = provisioned_hub(tmp_path)
    workspace = hub.case_workspace(case_id)
    problem_path = workspace.root / "problem.json"
    problem = json.loads(problem_path.read_text())
    problem["problem"]["title"] = "An altered imported projection"
    problem_path.write_text(json.dumps(problem))

    with pytest.raises(ProtocolError, match="problem does not match"):
        hub.case_workspace(case_id)


def test_activate_uses_verified_bundle_from_a_real_local_clerk(tmp_path: Path) -> None:
    hub, case_id, _ = provisioned_hub(tmp_path)
    with running_clerk(hub, case_id) as local_origin:

        def verified_local_fetcher(record: dict[str, object]) -> dict[str, object]:
            assert record["clerk_url"] == "https://clerk.example/cases/erdos686"
            with urlopen(local_origin + "/v1/state", timeout=5) as response:
                bundle = json.loads(response.read())
            verify_snapshot(
                bundle["snapshot"],
                bundle["state"],
                problem_id=record["problem_id"],
                clerk_key=record["clerk_key"],
            )
            return bundle

        live = hub.activate(
            case_id,
            "https://clerk.example/cases/erdos686",
            fetcher=verified_local_fetcher,
        )

    assert live["status"] == "LIVE"
    assert live["clerk_url"] == "https://clerk.example/cases/erdos686"
    assert live["event_count"] == 0
    assert live["head_event_hash"] is None
