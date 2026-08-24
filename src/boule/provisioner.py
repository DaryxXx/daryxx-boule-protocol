"""Idempotent case repository provisioning.

Private maintainer material stays in the local initialized workspace.  The
remote repository receives only public, committed case files and a signed case
marker that makes a name collision safe to inspect and retry.
"""

from __future__ import annotations

import base64
import re
import secrets
import subprocess
import tempfile
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, runtime_checkable
from urllib.parse import quote, urlsplit

from .canonical import canonical_bytes, digest_object
from .case_scaffold import PUBLIC_SUPPORT_PATHS, write_case_support_files
from .crypto import (
    generate_private_key,
    public_key_text,
    sign_object,
    verify_object,
    write_private_key,
)
from .errors import ProtocolError
from .github_app import GitHubAppClient, Transport
from .policy import build_case_policy
from .problem_import import FetchResponse, ImportResult, fetch_problem, import_problem
from .remote_protocol import strict_json_bytes
from .session_store import maintainer_key_path
from .workspace import Workspace

MARKER_PATH = ".boule/case-marker.json"
MARKER_SCHEMA = "boule-case-marker/0.2"
NAME_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,96}[a-z0-9])?\Z")


@dataclass(frozen=True)
class Repository:
    name: str
    url: str
    local_path: Path | None
    created: bool
    repository_id: int | str
    repository_node_id: str | None


@runtime_checkable
class RepositoryProvider(Protocol):
    def ensure_repository(self, name: str) -> Repository: ...

    def read_file(self, repository: Repository, path: str) -> bytes | None: ...

    def write_files(
        self, repository: Repository, files: Mapping[str, bytes], message: str
    ) -> str: ...


class LocalRepositoryProvider:
    """A real bare-Git provider for staging and deterministic end-to-end tests."""

    def __init__(self, root: str | Path, *, public_base_url: str | None = None) -> None:
        self.root = Path(root)
        self.remotes = self.root / "remotes"
        self.public_base_url = public_base_url.rstrip("/") if public_base_url else None
        if self.public_base_url is not None and not self.public_base_url.startswith("https://"):
            raise ProtocolError("local repository public base URL must use HTTPS")
        self._lock = threading.RLock()

    @staticmethod
    def _run(args: list[str], *, cwd: Path | None = None) -> subprocess.CompletedProcess[bytes]:
        try:
            return subprocess.run(args, cwd=cwd, check=True, capture_output=True)
        except (OSError, subprocess.CalledProcessError) as exc:
            raise ProtocolError("local repository operation failed") from exc

    @staticmethod
    def _name(name: str) -> str:
        if not isinstance(name, str) or NAME_RE.fullmatch(name) is None:
            raise ProtocolError("repository name is unsafe")
        return name

    def ensure_repository(self, name: str) -> Repository:
        name = self._name(name)
        with self._lock:
            self.remotes.mkdir(parents=True, exist_ok=True)
            remote = self.remotes / f"{name}.git"
            created = not remote.exists()
            if created:
                self._run(["git", "init", "--bare", "--initial-branch=main", str(remote)])
                repository_id = f"local:{secrets.token_hex(16)}"
                self._run(
                    [
                        "git",
                        "--git-dir",
                        str(remote),
                        "config",
                        "boule.repository-id",
                        repository_id,
                    ]
                )
            elif not remote.is_dir():
                raise ProtocolError("local repository target is not a directory")
            else:
                repository_id = (
                    self._run(
                        [
                            "git",
                            "--git-dir",
                            str(remote),
                            "config",
                            "--get",
                            "boule.repository-id",
                        ]
                    )
                    .stdout.decode("ascii")
                    .strip()
                )
                if re.fullmatch(r"local:[0-9a-f]{32}", repository_id) is None:
                    raise ProtocolError("local repository has no immutable identity")
            url = (
                f"{self.public_base_url}/{name}"
                if self.public_base_url is not None
                else remote.resolve().as_uri()
            )
        return Repository(name, url, remote.resolve(), created, repository_id, None)

    def read_file(self, repository: Repository, path: str) -> bytes | None:
        self._safe_path(path)
        if repository.local_path is None:
            raise ProtocolError("local repository path is unavailable")
        result = subprocess.run(
            ["git", "--git-dir", str(repository.local_path), "show", f"main:{path}"],
            capture_output=True,
        )
        if result.returncode == 0:
            return result.stdout
        return None

    def write_files(self, repository: Repository, files: Mapping[str, bytes], message: str) -> str:
        if not files:
            raise ProtocolError("repository write requires files")
        if repository.local_path is None:
            raise ProtocolError("local repository path is unavailable")
        for path, value in files.items():
            self._safe_path(path)
            if not isinstance(value, bytes):
                raise ProtocolError("repository file content must be bytes")
        with self._lock, tempfile.TemporaryDirectory(prefix="boule-provision-") as temporary:
            work = Path(temporary) / "work"
            self._run(["git", "clone", str(repository.local_path), str(work)])
            self._run(["git", "config", "user.name", "Boule Provisioner"], cwd=work)
            self._run(["git", "config", "user.email", "provisioner@boule.local"], cwd=work)
            for path, value in sorted(files.items()):
                target = work / path
                target.parent.mkdir(parents=True, exist_ok=True)
                if target.exists() and target.read_bytes() != value:
                    raise ProtocolError("repository file conflicts with requested scaffold")
                if not target.exists():
                    target.write_bytes(value)
            self._run(["git", "add", "--", *sorted(files)], cwd=work)
            changed = self._run(["git", "status", "--porcelain"], cwd=work).stdout
            if changed:
                self._run(["git", "commit", "-m", message], cwd=work)
                self._run(["git", "push", "origin", "main"], cwd=work)
            head = (
                self._run(
                    ["git", "--git-dir", str(repository.local_path), "rev-parse", "refs/heads/main"]
                )
                .stdout.decode()
                .strip()
            )
            for path, expected in files.items():
                actual = self._run(
                    ["git", "--git-dir", str(repository.local_path), "show", f"{head}:{path}"]
                ).stdout
                if actual != expected:
                    raise ProtocolError("local repository head does not contain the scaffold")
            return head

    @staticmethod
    def _safe_path(path: str) -> None:
        candidate = Path(path)
        if (
            not isinstance(path, str)
            or candidate.is_absolute()
            or ".." in candidate.parts
            or not candidate.parts
        ):
            raise ProtocolError("repository path is unsafe")


class GitHubAppRepositoryProvider:
    """Repository provider backed by a narrowly-scoped GitHub App installation."""

    def __init__(
        self,
        organization: str,
        client: GitHubAppClient | None = None,
        *,
        app_id: str | int | None = None,
        installation_id: str | int | None = None,
        private_key_pem: bytes | None = None,
        api_url: str = "https://api.github.com",
        transport: Transport | None = None,
        private: bool = True,
    ) -> None:
        if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?", organization):
            raise ProtocolError("GitHub organization is invalid")
        if client is None:
            if app_id is None or installation_id is None or private_key_pem is None:
                raise ProtocolError("GitHub App credentials are required")
            client = GitHubAppClient(
                app_id=app_id,
                installation_id=installation_id,
                private_key_pem=private_key_pem,
                api_url=api_url,
                transport=transport,
            )
        self.organization = organization
        self.client = client
        self.private = private

    def _path(self, name: str) -> str:
        if NAME_RE.fullmatch(name) is None:
            raise ProtocolError("repository name is unsafe")
        return f"/repos/{quote(self.organization, safe='')}/{quote(name, safe='')}"

    def _repo(self, name: str, payload: Any, created: bool) -> Repository:
        if not isinstance(payload, dict):
            raise ProtocolError("GitHub API returned an invalid repository")
        url = payload.get("html_url")
        owner = payload.get("owner")
        repository_id = payload.get("id")
        node_id = payload.get("node_id")
        parsed = urlsplit(url) if isinstance(url, str) else None
        if (
            payload.get("name") != name
            or not isinstance(payload.get("full_name"), str)
            or payload["full_name"].casefold() != f"{self.organization}/{name}".casefold()
            or not isinstance(owner, dict)
            or not isinstance(owner.get("login"), str)
            or owner["login"].casefold() != self.organization.casefold()
            or payload.get("private") is not self.private
            or payload.get("default_branch") != "main"
            or not isinstance(repository_id, int)
            or isinstance(repository_id, bool)
            or repository_id <= 0
            or not isinstance(node_id, str)
            or not node_id
            or parsed is None
            or parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise ProtocolError("GitHub repository does not match the requested boundary")
        return Repository(name, url, None, created, repository_id, node_id)

    def _assert_repository_identity(self, repository: Repository) -> None:
        if not isinstance(repository.repository_id, int) or isinstance(
            repository.repository_id, bool
        ):
            raise ProtocolError("GitHub repository has no immutable identity")
        if repository.repository_node_id is None:
            raise ProtocolError("GitHub repository has no immutable identity")
        status, payload = self.client.request("GET", self._path(repository.name))
        if status != 200:
            raise ProtocolError("GitHub repository identity lookup failed")
        current = self._repo(repository.name, payload, False)
        if (
            current.repository_id != repository.repository_id
            or current.repository_node_id != repository.repository_node_id
        ):
            raise ProtocolError("GitHub repository identity changed")

    def ensure_repository(self, name: str) -> Repository:
        path = self._path(name)
        status, payload = self.client.request("GET", path)
        if status == 200:
            return self._repo(name, payload, False)
        if status != 404:
            raise ProtocolError("GitHub repository lookup failed")
        status, payload = self.client.request(
            "POST",
            f"/orgs/{quote(self.organization, safe='')}/repos",
            {"name": name, "private": self.private},
        )
        if status in {200, 201}:
            return self._repo(name, payload, True)
        # A concurrent creator is a collision, not evidence it belongs to this case.
        if status in {409, 422}:
            status, payload = self.client.request("GET", path)
            if status == 200:
                return self._repo(name, payload, False)
        raise ProtocolError("GitHub repository creation failed")

    def _read_file_at_ref(self, repository: Repository, path: str, ref: str) -> bytes | None:
        LocalRepositoryProvider._safe_path(path)
        content_path = quote(path, safe="/")
        encoded_ref = quote(ref, safe="")
        self._assert_repository_identity(repository)
        try:
            status, payload = self.client.request(
                "GET", f"{self._path(repository.name)}/contents/{content_path}?ref={encoded_ref}"
            )
            if status == 404:
                return None
            if (
                status != 200
                or not isinstance(payload, dict)
                or payload.get("encoding") != "base64"
            ):
                raise ProtocolError("GitHub repository file lookup failed")
            content = payload.get("content")
            if not isinstance(content, str):
                raise ProtocolError("GitHub repository returned invalid file content")
            try:
                return base64.b64decode(content.replace("\n", "").encode("ascii"), validate=True)
            except (UnicodeEncodeError, ValueError) as exc:
                raise ProtocolError("GitHub repository returned invalid base64 content") from exc
        finally:
            self._assert_repository_identity(repository)

    def read_file(self, repository: Repository, path: str) -> bytes | None:
        return self._read_file_at_ref(repository, path, "main")

    def _head(self, repository: Repository) -> str:
        self._assert_repository_identity(repository)
        status, payload = self.client.request(
            "GET", f"{self._path(repository.name)}/git/ref/heads/main"
        )
        sha = payload.get("object", {}).get("sha") if isinstance(payload, dict) else None
        if (
            status != 200
            or not isinstance(sha, str)
            or re.fullmatch(r"[0-9a-f]{40,64}", sha) is None
        ):
            raise ProtocolError("GitHub repository main head is unavailable")
        self._assert_repository_identity(repository)
        return sha

    def write_files(self, repository: Repository, files: Mapping[str, bytes], message: str) -> str:
        for path, content in sorted(files.items()):
            LocalRepositoryProvider._safe_path(path)
            existing = self.read_file(repository, path)
            if existing == content:
                continue
            if existing is not None:
                raise ProtocolError("repository file conflicts with requested scaffold")
            self._assert_repository_identity(repository)
            status, payload = self.client.request(
                "PUT",
                f"{self._path(repository.name)}/contents/{quote(path, safe='/')}",
                {
                    "branch": "main",
                    "content": base64.b64encode(content).decode("ascii"),
                    "message": message,
                },
            )
            self._assert_repository_identity(repository)
            if status not in {200, 201} or not isinstance(payload, dict):
                # A retry may race with our previous successful request.  Accept only an
                # identical remote file.
                if self.read_file(repository, path) != content:
                    raise ProtocolError("GitHub repository file creation failed")
        head = self._head(repository)
        for path, expected in files.items():
            if self._read_file_at_ref(repository, path, head) != expected:
                raise ProtocolError("GitHub repository head does not contain the scaffold")
        return head


@dataclass(frozen=True)
class ProvisionResult:
    case_id: str
    repository_name: str
    repository_url: str
    local_path: Path
    marker_digest: str
    repository_created: bool
    repository_id: int | str
    repository_node_id: str | None
    problem_id: str
    task_commitment: str
    clerk_key: str
    commit: str


class CaseProvisioner:
    def __init__(self, provider: RepositoryProvider, workspace_root: str | Path) -> None:
        self.provider = provider
        self.workspace_root = Path(workspace_root)

    @staticmethod
    def repository_name(slug: str, task_commitment: str) -> str:
        safe_slug = slug.lower()
        if NAME_RE.fullmatch(safe_slug) is None or not task_commitment.startswith("sha256:"):
            raise ProtocolError("case slug or task commitment is invalid")
        suffix = task_commitment.removeprefix("sha256:")
        if len(suffix) != 64 or any(char not in "0123456789abcdef" for char in suffix):
            raise ProtocolError("task commitment is invalid")
        name = f"boule-case-{safe_slug}-{suffix[:12]}"
        if len(name) > 100:
            raise ProtocolError("derived repository name is too long")
        return name

    def provision(
        self,
        problem_url: str,
        *,
        case_id: str,
        config: Mapping[str, Any],
        fetcher: Callable[[str], FetchResponse] = fetch_problem,
        mode: str | None = None,
        disclosure: str = "commitment_only",
    ) -> ProvisionResult:
        if not isinstance(case_id, str) or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", case_id
        ):
            raise ProtocolError("case_id must be a safe identifier")
        imported: ImportResult = import_problem(
            problem_url, self.workspace_root, mode=mode, fetcher=fetcher
        )
        workspace = self._initialize(imported, dict(config), disclosure)
        write_case_support_files(imported.path)
        problem = workspace.problem
        task = problem["task"]
        if not isinstance(task, dict):  # guarded by Workspace, retained for type narrowing
            raise ProtocolError("problem task identity is invalid")
        repo_name = self.repository_name(imported.path.name, str(task["task_commitment"]))
        repository = self.provider.ensure_repository(repo_name)
        identity = self._marker_identity(case_id, workspace, repository)
        marker = self._signed_marker(identity, workspace)
        marker_bytes = canonical_bytes(marker) + b"\n"
        existing = self.provider.read_file(repository, MARKER_PATH)
        if existing is not None:
            self._verify_marker(existing, identity)
        elif not repository.created:
            raise ProtocolError("existing repository has no valid Boule case marker")
        else:
            # The marker is always the first committed remote object.  Thus a name collision
            # cannot be accepted merely because a later scaffold file happens to match.
            self.provider.write_files(
                repository, {MARKER_PATH: marker_bytes}, "boule: bind case identity"
            )
        files = {MARKER_PATH: marker_bytes, **self._public_scaffold(imported.path)}
        commit = self.provider.write_files(repository, files, "boule: initialize case scaffold")
        return ProvisionResult(
            case_id=case_id,
            repository_name=repository.name,
            repository_url=repository.url,
            local_path=imported.path.resolve(),
            marker_digest=digest_object(identity),
            repository_created=repository.created,
            repository_id=repository.repository_id,
            repository_node_id=repository.repository_node_id,
            problem_id=str(problem["problem_id"]),
            task_commitment=str(task["task_commitment"]),
            clerk_key=str(workspace.config["maintainer_key"]),
            commit=commit,
        )

    @staticmethod
    def _initialize(imported: ImportResult, config: dict[str, Any], disclosure: str) -> Workspace:
        control = imported.path / ".boule"
        if control.exists():
            return Workspace(imported.path)
        private_key = generate_private_key()
        workspace = Workspace.initialize(
            imported.path,
            {**config, "maintainer_key": public_key_text(private_key)},
            policy=build_case_policy(imported.manifest, disclosure),
        )
        write_private_key(maintainer_key_path(workspace), private_key)
        return workspace

    @staticmethod
    def _marker_identity(
        case_id: str, workspace: Workspace, repository: Repository
    ) -> dict[str, Any]:
        task = workspace.problem["task"]
        assert isinstance(task, dict)
        identity: dict[str, Any] = {
            "schema": MARKER_SCHEMA,
            "case_id": case_id,
            "problem_id": str(workspace.problem["problem_id"]),
            "task_commitment": str(task["task_commitment"]),
            "formal_repository_pin": str(task["formal_repository_pin"]),
            "policy_digest": str(workspace.config["policy_digest"]),
            "maintainer_key": str(workspace.config["maintainer_key"]),
            "repository_id": repository.repository_id,
            "repository_node_id": repository.repository_node_id,
        }
        return identity

    @staticmethod
    def _signed_marker(identity: dict[str, Any], workspace: Workspace) -> dict[str, Any]:
        from .session_store import load_maintainer_key

        key = load_maintainer_key(workspace)
        return {
            **identity,
            "identity_digest": digest_object(identity),
            "signer": public_key_text(key),
            "signature": sign_object(key, identity),
        }

    @staticmethod
    def _verify_marker(raw: bytes, expected: dict[str, Any]) -> None:
        try:
            marker = strict_json_bytes(raw)
        except ProtocolError as exc:
            raise ProtocolError("existing repository case marker is invalid") from exc
        if not isinstance(marker, dict):
            raise ProtocolError("existing repository case marker is invalid")
        expected_fields = set(expected) | {"identity_digest", "signer", "signature"}
        if set(marker) != expected_fields:
            raise ProtocolError("existing repository case marker has invalid fields")
        identity = {key: marker.get(key) for key in expected}
        if identity != expected or marker.get("identity_digest") != digest_object(expected):
            raise ProtocolError("repository name is already bound to a different case")
        signature = marker.get("signature")
        signer = marker.get("signer")
        if not isinstance(signature, str) or not isinstance(signer, str):
            raise ProtocolError("existing repository case marker lacks a signature")
        if signer != expected["maintainer_key"]:
            raise ProtocolError("existing repository marker was signed by the wrong clerk")
        verify_object(signer, expected, signature)

    @staticmethod
    def _public_scaffold(root: Path) -> dict[str, bytes]:
        files: dict[str, bytes] = {}
        allowed = (
            root / "problem.json",
            root / ".boule" / "policy.json",
            root / ".boule" / "config.json",
            *(root / path for path in PUBLIC_SUPPORT_PATHS),
        )
        for path in allowed:
            if not path.exists():
                raise ProtocolError("initialized case scaffold is incomplete")
            files[str(path.relative_to(root))] = path.read_bytes()
        snapshots = root / "snapshots"
        for path in sorted(snapshots.glob("*.json")):
            files[str(path.relative_to(root))] = path.read_bytes()
        return files
