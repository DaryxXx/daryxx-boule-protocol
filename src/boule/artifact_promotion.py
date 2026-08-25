"""Private evidence retention and human-gated Git promotion for supervised runs."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
import subprocess
import tempfile
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

from .canonical import canonical_bytes, digest_bytes
from .errors import ProtocolError
from .remote_client import RemoteClient
from .remote_protocol import strict_json_bytes
from .run_store import RunStore
from .text_safety import redact_sensitive_text
from .workspace import Workspace

CAPTURE_SCHEMA = "boule-run-evidence/0.1"
PROMOTION_SCHEMA = "boule-git-evidence/0.1"
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 128 * 1024 * 1024
SHA256 = re.compile(r"sha256:[0-9a-f]{64}\Z")
SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}\Z")
StateFetcher = Callable[[Workspace, str], dict[str, Any]]
SENSITIVE_NAMES = frozenset(
    {
        ".env",
        ".netrc",
        ".npmrc",
        ".pypirc",
        "credentials",
        "credentials.json",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
        "id_rsa",
        "secrets.json",
        "secrets.txt",
        "wallet.dat",
    }
)
SENSITIVE_DIRECTORIES = frozenset({".aws", ".azure", ".gnupg", ".kube", ".ssh", "gcloud"})


def _stamp() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _safe_id(value: Any, name: str) -> str:
    if not isinstance(value, str) or SAFE_ID.fullmatch(value) is None:
        raise ProtocolError(f"{name} is invalid")
    return value


def _relative_artifact(value: Any) -> PurePosixPath | None:
    if not isinstance(value, str) or not value or len(value) > 1000 or "\x00" in value:
        raise ProtocolError("handoff evidence reference is invalid")
    if ":" in value or "\\" in value:
        return None
    relative = PurePosixPath(value)
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        raise ProtocolError("handoff evidence path is unsafe")
    if relative.parts[0] in {".boule", ".git"}:
        raise ProtocolError("private Boule or Git state cannot be promoted")
    if relative.parts[:2] == ("artifacts", "boule"):
        raise ProtocolError("a promoted snapshot cannot recursively promote itself")
    return relative


def _regular_source(root: Path, relative: PurePosixPath) -> Path:
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise ProtocolError("handoff artifact paths must not contain symlinks")
    try:
        resolved = current.resolve(strict=True)
        metadata = current.stat()
    except OSError as exc:
        raise ProtocolError(f"signed local artifact is unavailable: {relative.as_posix()}") from exc
    if not resolved.is_relative_to(root.resolve()) or not stat.S_ISREG(metadata.st_mode):
        raise ProtocolError("handoff artifact must be a regular file inside the run workspace")
    if metadata.st_size > MAX_ARTIFACT_BYTES:
        raise ProtocolError("one handoff artifact exceeds the 64 MiB retention limit")
    return current


def _copy_and_hash(source: Path, destination: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    total = 0
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    destination.parent.chmod(0o700)
    with source.open("rb") as reader, destination.open("xb") as writer:
        os.chmod(destination, 0o600)
        while chunk := reader.read(1024 * 1024):
            total += len(chunk)
            digest.update(chunk)
            writer.write(chunk)
        writer.flush()
        os.fsync(writer.fileno())
    return f"sha256:{digest.hexdigest()}", total


def _capture_summary(manifest: dict[str, Any], run_directory: Path) -> dict[str, Any]:
    files = manifest.get("files") if isinstance(manifest.get("files"), list) else []
    external = (
        manifest.get("external_evidence")
        if isinstance(manifest.get("external_evidence"), list)
        else []
    )
    path = run_directory / "evidence" / str(manifest["handoff_id"]) / "manifest.json"
    return {
        "schema": CAPTURE_SCHEMA,
        "status": "captured" if files else "no_local_artifacts",
        "handoff_id": manifest["handoff_id"],
        "artifact_count": len(files),
        "external_reference_count": len(external),
        "manifest": path.relative_to(run_directory).as_posix(),
        "captured_at": manifest["captured_at"],
    }


def capture_run_evidence(
    store: RunStore,
    run_id: str,
    config: dict[str, Any],
    handoff: dict[str, Any],
) -> dict[str, Any]:
    """Copy exact local handoff bytes into the private run record once."""

    handoff_id = _safe_id(handoff.get("handoff_id"), "handoff id")
    session_id = _safe_id(config.get("session_id"), "session id")
    if handoff.get("session_id") not in {None, session_id}:
        raise ProtocolError("handoff does not belong to the supervised session")
    evidence = handoff.get("evidence")
    if not isinstance(evidence, list) or len(evidence) > 16:
        raise ProtocolError("handoff evidence is invalid")

    run_directory = store.directory(run_id)
    evidence_root = run_directory / "evidence"
    evidence_root.mkdir(mode=0o700, exist_ok=True)
    evidence_root.chmod(0o700)
    final = evidence_root / handoff_id
    manifest_path = final / "manifest.json"
    if manifest_path.exists():
        try:
            if manifest_path.stat().st_mode & 0o077:
                raise ProtocolError("private evidence manifest permissions are unsafe")
            manifest = strict_json_bytes(manifest_path.read_bytes())
        except OSError as exc:
            raise ProtocolError("private evidence manifest cannot be read") from exc
        if (
            not isinstance(manifest, dict)
            or manifest.get("schema") != CAPTURE_SCHEMA
            or manifest.get("run_id") != run_id
            or manifest.get("session_id") != session_id
            or manifest.get("handoff_id") != handoff_id
        ):
            raise ProtocolError("existing private evidence capture conflicts with this run")
        return _capture_summary(manifest, run_directory)
    if final.exists():
        raise ProtocolError("private evidence capture is incomplete; inspect it manually")

    workspace = Workspace(config["workspace"])
    temporary = Path(tempfile.mkdtemp(prefix=f".{handoff_id}.", dir=evidence_root))
    temporary.chmod(0o700)
    files: list[dict[str, Any]] = []
    external: list[dict[str, str]] = []
    total_bytes = 0
    try:
        for item in evidence:
            if not isinstance(item, dict) or set(item) != {"ref", "sha256"}:
                raise ProtocolError("handoff evidence item is invalid")
            reference = item["ref"]
            expected = item["sha256"]
            if not isinstance(expected, str) or SHA256.fullmatch(expected) is None:
                raise ProtocolError("handoff evidence digest is invalid")
            relative = _relative_artifact(reference)
            if relative is None:
                external.append({"ref": reference, "sha256": expected})
                continue
            source = _regular_source(workspace.root, relative)
            snapshot = PurePosixPath("files") / relative
            actual, size = _copy_and_hash(source, temporary / Path(snapshot.as_posix()))
            if actual != expected:
                raise ProtocolError(
                    f"handoff artifact no longer matches its signed digest: {relative.as_posix()}"
                )
            total_bytes += size
            if total_bytes > MAX_TOTAL_BYTES:
                raise ProtocolError("handoff artifacts exceed the 128 MiB retention limit")
            files.append(
                {
                    "source_ref": relative.as_posix(),
                    "snapshot_ref": snapshot.as_posix(),
                    "sha256": actual,
                    "bytes": size,
                    "executable": bool(source.stat().st_mode & stat.S_IXUSR),
                }
            )
        manifest = {
            "schema": CAPTURE_SCHEMA,
            "run_id": run_id,
            "problem_id": config.get("problem_id"),
            "task_id": config.get("task_id"),
            "session_id": session_id,
            "agent_name": config.get("agent_name"),
            "handoff_id": handoff_id,
            "handoff_event_id": handoff.get("event_id"),
            "captured_at": _stamp(),
            "files": files,
            "external_evidence": external,
        }
        with (temporary / "manifest.json").open("xb") as handle:
            os.chmod(temporary / "manifest.json", 0o600)
            handle.write(canonical_bytes(manifest) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, final)
        directory = os.open(evidence_root, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        return _capture_summary(manifest, run_directory)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)


def _git_environment(
    *,
    index: Path | None = None,
    stamp: str | None = None,
    author_name: str = "Boule Maintainer",
    author_email: str = "boule-maintainer@localhost",
) -> dict[str, str]:
    environment = {
        key: value
        for key, value in os.environ.items()
        if key in {"LANG", "LANGUAGE", "LC_ALL", "PATH", "TZ"}
    }
    environment.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_SYSTEM": "/dev/null",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_PROTOCOL_FROM_USER": "0",
            "GIT_SSH_COMMAND": "/bin/false",
            "GIT_AUTHOR_NAME": author_name,
            "GIT_AUTHOR_EMAIL": author_email,
            "GIT_COMMITTER_NAME": author_name,
            "GIT_COMMITTER_EMAIL": author_email,
        }
    )
    if index is not None:
        environment["GIT_INDEX_FILE"] = str(index)
    if stamp is not None:
        environment["GIT_AUTHOR_DATE"] = stamp
        environment["GIT_COMMITTER_DATE"] = stamp
    return environment


def _git(
    repository: Path,
    arguments: list[str],
    *,
    environment: dict[str, str] | None = None,
    input_bytes: bytes | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    try:
        result = subprocess.run(
            [
                "git",
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "commit.gpgSign=false",
                "-C",
                str(repository),
                *arguments,
            ],
            input=input_bytes,
            capture_output=True,
            timeout=120,
            env=environment or _git_environment(),
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ProtocolError("Git could not prepare the reviewed handoff branch") from exc
    if check and result.returncode != 0:
        raise ProtocolError("Git could not prepare the reviewed handoff branch")
    return result


def _git_text(repository: Path, arguments: list[str]) -> str:
    return _git(repository, arguments).stdout.decode("utf-8", errors="strict").strip()


def _configured_identity(repository: Path, key: str) -> str:
    """Read the human maintainer identity without inheriting Git command rewrites."""

    environment = {
        key: value
        for key, value in os.environ.items()
        if key in {"HOME", "LANG", "LANGUAGE", "LC_ALL", "PATH", "XDG_CONFIG_HOME"}
    }
    environment["GIT_CONFIG_NOSYSTEM"] = "1"
    try:
        result = subprocess.run(
            ["git", "-C", str(repository), "config", "--get", key],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=15,
            env=environment,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ProtocolError("Git maintainer identity could not be inspected") from exc
    try:
        value = result.stdout.decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError as exc:
        raise ProtocolError("Git maintainer identity is invalid") from exc
    if (
        result.returncode != 0
        or not value
        or len(value) > 200
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
        or (
            key == "user.email"
            and ("@" not in value or value.startswith("@") or value.endswith("@"))
        )
    ):
        raise ProtocolError(
            "configure a valid Git user.name and user.email before preparing a promotion"
        )
    return value


def _load_capture(store: RunStore, run_id: str, capture: dict[str, Any]) -> dict[str, Any]:
    relative = capture.get("manifest")
    handoff_id = _safe_id(capture.get("handoff_id"), "captured handoff id")
    expected = (PurePosixPath("evidence") / handoff_id / "manifest.json").as_posix()
    if not isinstance(relative, str) or relative != expected:
        raise ProtocolError("run evidence capture has no manifest")
    path = store.directory(run_id) / relative
    try:
        if path.is_symlink() or not path.resolve(strict=True).is_relative_to(
            store.directory(run_id).resolve(strict=True)
        ):
            raise ProtocolError("private evidence manifest path is unsafe")
        if path.stat().st_mode & 0o077:
            raise ProtocolError("private evidence manifest permissions are unsafe")
        value = strict_json_bytes(path.read_bytes())
    except OSError as exc:
        raise ProtocolError("private evidence manifest is unavailable") from exc
    if not isinstance(value, dict) or value.get("schema") != CAPTURE_SCHEMA:
        raise ProtocolError("private evidence manifest is invalid")
    return value


def _reject_sensitive_artifact(data: bytes, reference: str) -> None:
    relative = PurePosixPath(reference)
    parts = tuple(part.casefold() for part in relative.parts)
    name = parts[-1]
    if (
        name in SENSITIVE_NAMES
        or name.startswith(".env.")
        or PurePosixPath(name).suffix in {".key", ".pem", ".p12", ".pfx", ".keystore"}
        or any(part in SENSITIVE_DIRECTORIES for part in parts)
    ):
        raise ProtocolError("reviewed Git promotion refuses credential-shaped artifact paths")
    if b"PRIVATE KEY-----" in data or b"OPENSSH PRIVATE KEY" in data:
        raise ProtocolError("reviewed Git promotion refuses private-key material")
    text = data.decode("utf-8", errors="ignore")
    if redact_sensitive_text(text) != text:
        raise ProtocolError("reviewed Git promotion found credential-shaped text")


def _default_state_fetcher(workspace: Workspace, server: str) -> dict[str, Any]:
    response = RemoteClient(workspace, server).fetch_state()
    state = response.get("state")
    if not isinstance(state, dict):
        raise ProtocolError("trusted clerk returned no case state")
    return state


def _select_handoff(
    state: dict[str, Any], session_id: str, expected_id: str | None
) -> dict[str, Any]:
    values = state.get("handoffs")
    if not isinstance(values, list):
        raise ProtocolError("trusted clerk returned invalid handoff state")
    matches = [
        item
        for item in values
        if isinstance(item, dict)
        and item.get("session_id") == session_id
        and (expected_id is None or item.get("handoff_id") == expected_id)
    ]
    if not matches:
        raise ProtocolError("the completed run has no matching signed clerk handoff")
    return matches[-1]


def _promotion_manifest(
    workspace: Workspace,
    config: dict[str, Any],
    handoff: dict[str, Any],
    capture: dict[str, Any],
    capture_root: Path,
) -> tuple[dict[str, Any], list[tuple[bytes, str, int]]]:
    handoff_id = _safe_id(capture.get("handoff_id"), "captured handoff id")
    files = capture.get("files")
    external = capture.get("external_evidence")
    signed_evidence = handoff.get("evidence")
    if (
        not isinstance(files, list)
        or not files
        or not isinstance(external, list)
        or not isinstance(signed_evidence, list)
        or len(files) + len(external) > 16
        or len(signed_evidence) != len(files) + len(external)
    ):
        raise ProtocolError("handoff declared no local artifact bytes to promote")
    signed_local: dict[str, str] = {}
    signed_external: dict[str, str] = {}
    for item in signed_evidence:
        if not isinstance(item, dict) or set(item) != {"ref", "sha256"}:
            raise ProtocolError("signed handoff evidence is invalid")
        reference = item.get("ref")
        digest = item.get("sha256")
        if (
            not isinstance(reference, str)
            or reference in signed_local
            or reference in signed_external
            or not isinstance(digest, str)
            or SHA256.fullmatch(digest) is None
        ):
            raise ProtocolError("signed handoff evidence is invalid")
        destination = signed_external if _relative_artifact(reference) is None else signed_local
        destination[reference] = digest
    prepared: list[tuple[bytes, str, int]] = []
    public_files = []
    seen: set[str] = set()
    total_bytes = 0
    for item in files:
        if not isinstance(item, dict) or set(item) != {
            "source_ref",
            "snapshot_ref",
            "sha256",
            "bytes",
            "executable",
        }:
            raise ProtocolError("private evidence manifest has an invalid file entry")
        source_ref = item.get("source_ref")
        snapshot_ref = item.get("snapshot_ref")
        digest = item.get("sha256")
        size = item.get("bytes")
        if (
            not isinstance(source_ref, str)
            or not isinstance(snapshot_ref, str)
            or not isinstance(digest, str)
            or SHA256.fullmatch(digest) is None
            or isinstance(size, bool)
            or not isinstance(size, int)
            or size < 0
            or not isinstance(item.get("executable"), bool)
        ):
            raise ProtocolError("private evidence manifest has invalid file metadata")
        source = _relative_artifact(source_ref)
        if source is None or source.as_posix() != source_ref or source_ref in seen:
            raise ProtocolError("private evidence manifest has a non-canonical source path")
        if signed_local.get(source_ref) != digest:
            raise ProtocolError("private evidence manifest differs from the signed handoff")
        expected_snapshot = PurePosixPath("files") / source
        if snapshot_ref != expected_snapshot.as_posix():
            raise ProtocolError("private evidence manifest has a non-canonical snapshot path")
        snapshot = _regular_source(capture_root, expected_snapshot)
        data = snapshot.read_bytes()
        actual = f"sha256:{hashlib.sha256(data).hexdigest()}"
        if len(data) != size or actual != digest:
            raise ProtocolError("retained artifact no longer matches its signed digest")
        total_bytes += len(data)
        if total_bytes > MAX_TOTAL_BYTES:
            raise ProtocolError("retained artifacts exceed the 128 MiB promotion limit")
        seen.add(source_ref)
        target = f"artifacts/boule/{handoff_id}/{source.as_posix()}"
        _reject_sensitive_artifact(data, target)
        mode = 0o100644
        prepared.append((data, target, mode))
        public_files.append(
            {
                "source_ref": source.as_posix(),
                "artifact_ref": target,
                "sha256": actual,
                "bytes": len(data),
            }
        )
    public_external: list[dict[str, str]] = []
    for item in external:
        if not isinstance(item, dict) or set(item) != {"ref", "sha256"}:
            raise ProtocolError("private evidence manifest has an invalid external reference")
        reference = item.get("ref")
        digest = item.get("sha256")
        if (
            not isinstance(reference, str)
            or _relative_artifact(reference) is not None
            or reference in seen
            or not isinstance(digest, str)
            or SHA256.fullmatch(digest) is None
        ):
            raise ProtocolError("private evidence manifest has invalid external metadata")
        if signed_external.get(reference) != digest:
            raise ProtocolError("private evidence manifest differs from the signed handoff")
        seen.add(reference)
        public_external.append({"ref": reference, "sha256": digest})
    if seen != set(signed_local) | set(signed_external):
        raise ProtocolError("private evidence manifest differs from the signed handoff")
    manifest = {
        "schema": PROMOTION_SCHEMA,
        "problem_id": config.get("problem_id"),
        "task_id": config.get("task_id"),
        "task_commitment": workspace.problem["task"]["task_commitment"],
        "base_commit": config.get("repository_commit"),
        "session_id": config.get("session_id"),
        "agent_name": config.get("agent_name"),
        "handoff_id": handoff_id,
        "handoff_event_id": handoff.get("event_id"),
        "outcome": handoff.get("outcome"),
        "provenance": handoff.get("provenance"),
        "depends_on": handoff.get("depends_on", []),
        "disclosure": workspace.policy.get("disclosure"),
        "event_visibility": workspace.policy.get("event_visibility"),
        "captured_at": capture.get("captured_at"),
        "artifacts": public_files,
        "external_evidence": public_external,
        "review_status": "UNREVIEWED",
        "notice": (
            "Git retention only; not mathematical verification, causal credit, or acceptance."
        ),
    }
    return manifest, prepared


def _prepare_branch(
    repository: Path,
    base_commit: str,
    branch: str,
    handoff_id: str,
    manifest: dict[str, Any],
    files: list[tuple[bytes, str, int]],
    stamp: str,
    author_name: str,
    author_email: str,
) -> str:
    branch_exists = _git(
        repository,
        ["show-ref", "--verify", "--quiet", f"refs/heads/{branch}"],
        check=False,
    ).returncode
    if branch_exists == 0:
        raise ProtocolError("the deterministic handoff branch already exists without a run receipt")
    descriptor, index_name = tempfile.mkstemp(prefix="boule-promotion-index-")
    os.close(descriptor)
    os.unlink(index_name)
    index = Path(index_name)
    environment = _git_environment(
        index=index,
        stamp=stamp,
        author_name=author_name,
        author_email=author_email,
    )
    try:
        _git(repository, ["read-tree", base_commit], environment=environment)
        for data, target, mode in files:
            blob = (
                _git(
                    repository,
                    ["hash-object", "-w", "--stdin"],
                    environment=environment,
                    input_bytes=data,
                )
                .stdout.decode("ascii")
                .strip()
            )
            _git(
                repository,
                ["update-index", "--add", "--cacheinfo", f"{mode:o}", blob, target],
                environment=environment,
            )
        manifest_path = f"artifacts/boule/{handoff_id}/manifest.json"
        manifest_bytes = canonical_bytes(manifest) + b"\n"
        manifest_blob = (
            _git(
                repository,
                ["hash-object", "-w", "--stdin"],
                environment=environment,
                input_bytes=manifest_bytes,
            )
            .stdout.decode("ascii")
            .strip()
        )
        _git(
            repository,
            ["update-index", "--add", "--cacheinfo", "100644", manifest_blob, manifest_path],
            environment=environment,
        )
        tree = (
            _git(repository, ["write-tree"], environment=environment).stdout.decode("ascii").strip()
        )
        message = (
            f"Preserve Boule handoff {handoff_id} evidence\n\n"
            "Prepared for human review; not verified, accepted, or awarded.\n"
        ).encode()
        commit = (
            _git(
                repository,
                ["commit-tree", tree, "-p", base_commit],
                environment=environment,
                input_bytes=message,
            )
            .stdout.decode("ascii")
            .strip()
        )
        _git(
            repository,
            ["update-ref", f"refs/heads/{branch}", commit, "0" * 40],
            environment=environment,
        )
        return commit
    finally:
        if index.exists():
            index.unlink()


def promote_run_artifacts(
    run_id: str,
    *,
    run_root: str | Path | None = None,
    confirm: bool = False,
    state_fetcher: StateFetcher | None = None,
) -> dict[str, Any]:
    """Prepare one isolated local Git branch from exact signed handoff artifacts."""

    store = RunStore(run_root)
    status = store.status(run_id)
    protocol = status.get("protocol")
    if (
        status.get("state") != "completed"
        or not isinstance(protocol, dict)
        or not protocol.get("complete")
    ):
        raise ProtocolError("only a run closed with a signed handoff can be promoted")
    config = store.config(run_id)
    repository_url = config.get("repository_url")
    base_commit = config.get("repository_commit")
    if (
        not isinstance(repository_url, str)
        or not repository_url.startswith("https://")
        or not isinstance(base_commit, str)
        or re.fullmatch(r"[0-9a-f]{40}", base_commit) is None
    ):
        raise ProtocolError("only a signed registry-backed run can prepare a Git promotion")
    workspace = Workspace(config["workspace"])
    repository = workspace.root.resolve(strict=True)
    if Path(config["workspace"]).is_symlink():
        raise ProtocolError("run workspace must not be a symlink")
    if Path(_git_text(repository, ["rev-parse", "--show-toplevel"])).resolve() != repository:
        raise ProtocolError("run workspace is not the expected Git root")
    if _git_text(repository, ["config", "--local", "--get", "remote.origin.url"]) != repository_url:
        raise ProtocolError("run workspace Git origin differs from the signed registry")
    _git(repository, ["cat-file", "-e", f"{base_commit}^{{commit}}"])

    protocol_handoff = protocol.get("handoff")
    if not isinstance(protocol_handoff, dict):
        raise ProtocolError("completed run has no retained handoff identity")
    expected_id = protocol_handoff.get("handoff_id")
    state = (state_fetcher or _default_state_fetcher)(workspace, str(config["server"]))
    handoff = _select_handoff(state, str(config["session_id"]), expected_id)
    capture = capture_run_evidence(store, run_id, config, handoff)
    status = store.update(run_id, artifact_capture=capture)
    private_manifest = _load_capture(store, run_id, capture)
    if capture["status"] != "captured":
        raise ProtocolError("handoff declared no local artifact bytes to promote")
    if private_manifest.get("handoff_id") != handoff.get("handoff_id"):
        raise ProtocolError("private evidence capture does not match the signed handoff")
    disclosure = workspace.policy.get("disclosure")
    if confirm and disclosure != "public":
        raise ProtocolError(
            "case disclosure policy does not authorize a Git artifact release; "
            "the exact bytes remain in Boule's private run record"
        )

    handoff_id = _safe_id(handoff.get("handoff_id"), "handoff id")
    branch = f"boule/handoff/{handoff_id}"
    capture_root = store.directory(run_id) / "evidence" / handoff_id
    if (
        private_manifest.get("run_id") != run_id
        or private_manifest.get("session_id") != config.get("session_id")
        or private_manifest.get("handoff_id") != handoff.get("handoff_id")
        or private_manifest.get("problem_id") != config.get("problem_id")
        or private_manifest.get("task_id") != config.get("task_id")
    ):
        raise ProtocolError("private evidence capture does not match the signed run")
    manifest, files = _promotion_manifest(
        workspace, config, handoff, private_manifest, capture_root
    )
    manifest_digest = f"sha256:{digest_bytes(canonical_bytes(manifest))}"
    existing = status.get("promotion")
    if isinstance(existing, dict):
        if (
            existing.get("handoff_id") != handoff_id
            or existing.get("branch") != branch
            or existing.get("manifest_sha256") != manifest_digest
        ):
            raise ProtocolError("run already has a conflicting artifact promotion")
        commit = existing.get("commit")
        if not isinstance(commit, str) or _git_text(repository, ["rev-parse", branch]) != commit:
            raise ProtocolError("prepared promotion branch no longer matches its run receipt")
        return {
            **existing,
            "status": "prepared_for_human_push",
            "idempotent": True,
            "published": False,
        }

    preview = {
        "schema": PROMOTION_SCHEMA,
        "status": "review_required",
        "run_id": run_id,
        "handoff_id": handoff_id,
        "branch": branch,
        "base_commit": base_commit,
        "artifact_count": len(files),
        "artifacts": manifest["artifacts"],
        "manifest_sha256": manifest_digest,
        "disclosure": disclosure,
        "event_visibility": workspace.policy.get("event_visibility"),
        "published": False,
        "notice": (
            "Review every listed byte and the case disclosure terms. This prepares a local "
            "branch only; it does not push, verify, accept, allocate credit, or pay."
        ),
    }
    if not confirm:
        return preview

    author_name = _configured_identity(repository, "user.name")
    author_email = _configured_identity(repository, "user.email")
    prepared_at = _stamp()
    commit = _prepare_branch(
        repository,
        base_commit,
        branch,
        handoff_id,
        manifest,
        files,
        prepared_at,
        author_name,
        author_email,
    )
    promotion = {
        **preview,
        "status": "prepared_for_human_push",
        "commit": commit,
        "prepared_at": prepared_at,
        "reviewed": False,
        "published": False,
        "review_commands": [
            ["git", "-C", str(repository), "diff", "--stat", f"{base_commit}..{commit}"],
            ["git", "-C", str(repository), "diff", f"{base_commit}..{commit}"],
        ],
        "publication": {
            "source_repository": str(repository),
            "target_repository_url": repository_url,
            "branch": branch,
            "commit": commit,
            "requires_separate_maintainer_checkout": True,
        },
    }
    store.update(run_id, promotion=promotion)
    return promotion
