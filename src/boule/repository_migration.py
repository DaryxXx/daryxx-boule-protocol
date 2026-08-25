"""Read-only evidence checks for one local-to-GitHub case-repository migration."""

from __future__ import annotations

import re
import subprocess
import tempfile
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .canonical import canonical_bytes, digest_bytes, digest_object
from .errors import ProtocolError
from .provisioner import MARKER_PATH, CaseProvisioner, Repository
from .remote_protocol import strict_json_bytes
from .workspace import Workspace

REF_MANIFEST_SCHEMA = "boule-git-ref-manifest/0.1"
MAX_MIGRATION_REFS = 256
OBJECT_ID_RE = re.compile(r"[0-9a-f]{40,64}\Z")
GITHUB_NAME_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,98}[A-Za-z0-9])?\Z")


@dataclass(frozen=True)
class MigrationEvidence:
    """Evidence derived from two independently inspected Git repositories."""

    destination: Repository
    destination_commit: str
    marker_blob_sha256: str
    ref_manifest: dict[str, Any]
    ref_manifest_sha256: str


@dataclass(frozen=True)
class GitHubRepositoryInspection:
    """Pinned metadata plus a fresh mirror and a final read-only recheck."""

    repository: Repository
    revalidate: Callable[[], None]


def _run(args: list[str], *, cwd: Path | None = None) -> bytes:
    try:
        result = subprocess.run(args, cwd=cwd, check=True, capture_output=True)
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ProtocolError("repository migration inspection failed") from exc
    return result.stdout


def _git(git_dir: Path, *args: str) -> bytes:
    return _run(["git", "--git-dir", str(git_dir), *args])


def _checked_git_dir(path: str | Path, name: str) -> Path:
    candidate = Path(path)
    try:
        if candidate.is_symlink():
            raise ProtocolError(f"{name} Git directory must not be a symlink")
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise ProtocolError(f"{name} Git directory is unavailable") from exc
    if not resolved.is_dir():
        raise ProtocolError(f"{name} Git directory is unavailable")
    if _git(resolved, "rev-parse", "--is-bare-repository").strip() != b"true":
        raise ProtocolError(f"{name} repository must be a bare Git repository")
    _git(resolved, "fsck", "--strict")
    return resolved


def validate_ref_manifest(value: Any) -> dict[str, Any]:
    """Validate the canonical, bounded set of user-controlled branches and tags."""
    if not isinstance(value, dict) or set(value) != {"schema", "refs"}:
        raise ProtocolError("repository ref manifest has invalid fields")
    refs = value.get("refs")
    if value.get("schema") != REF_MANIFEST_SCHEMA or not isinstance(refs, list):
        raise ProtocolError("repository ref manifest is unsupported")
    if not refs or len(refs) > MAX_MIGRATION_REFS:
        raise ProtocolError("repository ref manifest has an invalid size")
    normalized: list[dict[str, str]] = []
    names: set[str] = set()
    object_lengths: set[int] = set()
    for item in refs:
        if not isinstance(item, dict) or set(item) != {"name", "object_id"}:
            raise ProtocolError("repository ref manifest entry has invalid fields")
        name = item.get("name")
        object_id = item.get("object_id")
        if (
            not isinstance(name, str)
            or len(name) > 1_024
            or not name.isascii()
            or not name.startswith(("refs/heads/", "refs/tags/"))
            or name in {"refs/heads/", "refs/tags/"}
            or "\n" in name
            or "\r" in name
            or "\t" in name
            or ".." in name
            or "@{" in name
            or "//" in name
            or name.endswith(("/", "."))
            or any(
                component.startswith(".") or component.endswith(".lock")
                for component in name.split("/")
            )
            or any(character in name for character in " \\~^:?*[")
            or name in names
            or not isinstance(object_id, str)
            or OBJECT_ID_RE.fullmatch(object_id) is None
        ):
            raise ProtocolError("repository ref manifest entry is invalid")
        names.add(name)
        object_lengths.add(len(object_id))
        normalized.append({"name": name, "object_id": object_id})
    if normalized != sorted(normalized, key=lambda item: item["name"]):
        raise ProtocolError("repository ref manifest is not canonically ordered")
    if "refs/heads/main" not in names:
        raise ProtocolError("repository ref manifest has no main branch")
    if len(object_lengths) != 1:
        raise ProtocolError("repository ref manifest mixes object-id formats")
    return {"schema": REF_MANIFEST_SCHEMA, "refs": normalized}


def ref_manifest(git_dir: str | Path) -> dict[str, Any]:
    repository = _checked_git_dir(git_dir, "inspected")
    try:
        text = _git(
            repository,
            "for-each-ref",
            f"--count={MAX_MIGRATION_REFS + 1}",
            "--format=%(objectname)%09%(refname)",
        ).decode("ascii")
    except UnicodeDecodeError as exc:
        raise ProtocolError("repository refs are not ASCII") from exc
    refs: list[dict[str, str]] = []
    for line in text.splitlines():
        try:
            object_id, name = line.split("\t", 1)
        except ValueError as exc:
            raise ProtocolError("repository ref listing is invalid") from exc
        refs.append({"name": name, "object_id": object_id})
    return validate_ref_manifest(
        {"schema": REF_MANIFEST_SCHEMA, "refs": sorted(refs, key=lambda item: item["name"])}
    )


def _manifest_digest(manifest: dict[str, Any]) -> str:
    return "sha256:" + digest_bytes(canonical_bytes(validate_ref_manifest(manifest)))


def _main_commit(git_dir: Path, manifest: dict[str, Any]) -> str:
    main = next(item["object_id"] for item in manifest["refs"] if item["name"] == "refs/heads/main")
    try:
        commit = _git(git_dir, "rev-parse", "refs/heads/main^{commit}").decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise ProtocolError("repository main commit is invalid") from exc
    if commit != main or OBJECT_ID_RE.fullmatch(commit) is None:
        raise ProtocolError("repository main ref is not a commit")
    return commit


def _read_at(git_dir: Path, commit: str, path: str) -> bytes:
    if OBJECT_ID_RE.fullmatch(commit) is None:
        raise ProtocolError("repository marker commit is invalid")
    try:
        return _git(git_dir, "show", f"{commit}:{path}")
    except ProtocolError as exc:
        raise ProtocolError("repository marker is missing at the pinned commit") from exc


def verify_local_to_github_mirror(
    *,
    case_id: str,
    record: dict[str, Any],
    workspace: Workspace,
    source_git_dir: str | Path,
    destination: Repository,
) -> MigrationEvidence:
    """Prove exact refs and the original signed marker before registry mutation."""
    source = _checked_git_dir(source_git_dir, "source")
    if destination.local_path is None:
        raise ProtocolError("destination inspection has no Git mirror")
    target = _checked_git_dir(destination.local_path, "destination")
    marker_repository_id = record.get("marker_repository_id")
    marker_repository_node_id = record.get("marker_repository_node_id")
    if (
        not isinstance(marker_repository_id, str)
        or re.fullmatch(r"local:[0-9a-f]{32}", marker_repository_id) is None
        or marker_repository_node_id is not None
    ):
        raise ProtocolError("case marker is not bound to a staging-local repository")
    try:
        local_id = _git(source, "config", "--get", "boule.repository-id").decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise ProtocolError("source repository identity is invalid") from exc
    if local_id != marker_repository_id:
        raise ProtocolError("source repository identity does not match the case marker")
    if (
        isinstance(destination.repository_id, bool)
        or not isinstance(destination.repository_id, int)
        or destination.repository_id <= 0
        or not isinstance(destination.repository_node_id, str)
        or not destination.repository_node_id
    ):
        raise ProtocolError("destination has no immutable GitHub identity")
    expected_name = CaseProvisioner.repository_name(
        workspace.root.name, str(record["task_commitment"])
    )
    if destination.name != expected_name:
        raise ProtocolError("destination repository name does not match the case")
    parsed_destination = urlsplit(destination.url)
    if (
        parsed_destination.scheme != "https"
        or parsed_destination.hostname != "github.com"
        or parsed_destination.username
        or parsed_destination.password
        or parsed_destination.query
        or parsed_destination.fragment
        or not parsed_destination.path.endswith("/" + destination.name)
    ):
        raise ProtocolError("destination repository URL is invalid")
    try:
        origin = _git(target, "config", "--get", "remote.origin.url").decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise ProtocolError("destination Git remote URL is invalid") from exc
    owner_and_name = parsed_destination.path.strip("/")
    if origin != f"git@github.com:{owner_and_name}.git":
        raise ProtocolError("destination Git mirror is not bound to the inspected repository")

    migrations = record.get("repository_migrations")
    if not isinstance(migrations, list):
        raise ProtocolError("case repository migration history is invalid")
    source_before = ref_manifest(source)
    if migrations:
        transition = migrations[0]
        if not isinstance(transition, dict):
            raise ProtocolError("case repository migration history is invalid")
        expected_destination = {
            "to_repo_url": destination.url,
            "to_repository_id": destination.repository_id,
            "to_repository_node_id": destination.repository_node_id,
        }
        if any(transition.get(key) != value for key, value in expected_destination.items()):
            raise ProtocolError("inspected destination differs from the recorded migration")
        source_digest = _manifest_digest(source_before)
        source_main = _main_commit(source, source_before)
        if (
            transition.get("ref_manifest_schema") != REF_MANIFEST_SCHEMA
            or transition.get("ref_manifest_count") != len(source_before["refs"])
            or transition.get("ref_manifest_main") != source_main
            or transition.get("ref_manifest_sha256") != source_digest
        ):
            raise ProtocolError("source refs no longer match the recorded migration evidence")
        destination_commit = transition.get("to_repository_commit")
        marker_commit = transition.get("from_repository_commit")
    else:
        destination_manifest = ref_manifest(target)
        source_after = ref_manifest(source)
        if source_before != destination_manifest or source_after != destination_manifest:
            raise ProtocolError("source and destination Git refs are not identical")
        destination_commit = _main_commit(target, destination_manifest)
        marker_commit = record.get("repository_commit")
    if not isinstance(destination_commit, str) or OBJECT_ID_RE.fullmatch(
        destination_commit
    ) is None:
        raise ProtocolError("destination repository commit is invalid")
    if not isinstance(marker_commit, str) or OBJECT_ID_RE.fullmatch(marker_commit) is None:
        raise ProtocolError("case marker commit is invalid")
    source_marker = _read_at(source, marker_commit, MARKER_PATH)
    destination_marker = _read_at(target, marker_commit, MARKER_PATH)
    if source_marker != destination_marker:
        raise ProtocolError("destination does not preserve the original marker bytes")
    original_repository = Repository(
        expected_name,
        str(record["repo_url"]),
        source,
        False,
        marker_repository_id,
        marker_repository_node_id,
    )
    identity = CaseProvisioner._marker_identity(case_id, workspace, original_repository)
    CaseProvisioner._verify_marker(source_marker, identity)
    if identity["maintainer_key"] != record.get("clerk_key"):
        raise ProtocolError("repository marker clerk does not match the registry")
    if record.get("marker_digest") != digest_object(identity):
        raise ProtocolError("repository marker identity does not match the registry")

    return MigrationEvidence(
        destination=destination,
        destination_commit=destination_commit,
        marker_blob_sha256="sha256:" + digest_bytes(source_marker),
        ref_manifest=source_before,
        ref_manifest_sha256=_manifest_digest(source_before),
    )


def _github_name(value: str, name: str) -> str:
    if not isinstance(value, str) or GITHUB_NAME_RE.fullmatch(value) is None:
        raise ProtocolError(f"GitHub {name} is invalid")
    return value


def _github_boundary(
    organization: str,
    repository_name: str,
    *,
    private: bool,
) -> tuple[str, str, int, str]:
    try:
        payload = strict_json_bytes(
            _run(
                [
                    "gh",
                    "api",
                    "--hostname",
                    "github.com",
                    f"repos/{organization}/{repository_name}",
                ]
            )
        )
    except ProtocolError as exc:
        raise ProtocolError("GitHub repository lookup failed") from exc
    if not isinstance(payload, dict):
        raise ProtocolError("GitHub repository lookup returned invalid metadata")
    owner = payload.get("owner")
    html_url = payload.get("html_url")
    ssh_url = payload.get("ssh_url")
    parsed = urlsplit(html_url) if isinstance(html_url, str) else None
    repository_id = payload.get("id")
    node_id = payload.get("node_id")
    if (
        payload.get("name") != repository_name
        or payload.get("full_name") != f"{organization}/{repository_name}"
        or not isinstance(owner, dict)
        or owner.get("login") != organization
        or payload.get("private") is not private
        or payload.get("default_branch") != "main"
        or html_url != f"https://github.com/{organization}/{repository_name}"
        or ssh_url != f"git@github.com:{organization}/{repository_name}.git"
        or parsed is None
        or parsed.scheme != "https"
        or parsed.hostname != "github.com"
        or isinstance(repository_id, bool)
        or not isinstance(repository_id, int)
        or repository_id <= 0
        or not isinstance(node_id, str)
        or not node_id
    ):
        raise ProtocolError("GitHub repository does not match the migration boundary")
    return html_url, ssh_url, repository_id, node_id


@contextmanager
def inspect_github_repository(
    organization: str,
    repository_name: str,
    *,
    expected_account: str,
    private: bool = True,
) -> Iterator[GitHubRepositoryInspection]:
    """Look up, never create, a GitHub repository and clone its refs read-only."""
    organization = _github_name(organization, "organization")
    repository_name = _github_name(repository_name, "repository name")
    expected_account = _github_name(expected_account, "account")
    try:
        actor = strict_json_bytes(
            _run(["gh", "api", "--hostname", "github.com", "user"])
        )
    except ProtocolError as exc:
        raise ProtocolError("GitHub account lookup failed") from exc
    if not isinstance(actor, dict) or actor.get("login") != expected_account:
        raise ProtocolError("active GitHub account does not match the requested account")
    boundary = _github_boundary(organization, repository_name, private=private)
    html_url, ssh_url, repository_id, node_id = boundary

    def revalidate() -> None:
        if _github_boundary(organization, repository_name, private=private) != boundary:
            raise ProtocolError("GitHub repository identity changed during migration")

    with tempfile.TemporaryDirectory(prefix="boule-migration-target-") as temporary:
        mirror = Path(temporary) / f"{repository_name}.git"
        _run(["git", "clone", "--mirror", ssh_url, str(mirror)])
        yield GitHubRepositoryInspection(
            Repository(
                repository_name,
                html_url,
                mirror,
                False,
                repository_id,
                node_id,
            ),
            revalidate,
        )
