"""Local control plane for one signed registry and many Boule case workspaces."""

from __future__ import annotations

import os
import re
import tempfile
from collections import Counter
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from .canonical import canonical_bytes, digest_object
from .crypto import generate_private_key, load_private_key, public_key_text, write_private_key
from .errors import ProtocolError
from .problem_import import (
    FetchResponse,
    ImportResult,
    canonicalize_problem_url,
    fetch_problem,
    import_problem,
)
from .provider_contract import provider_contract_digest, provider_contract_for_problem
from .provisioner import CaseProvisioner, ProvisionResult, Repository, RepositoryProvider
from .registry import Registry
from .registry_api import fetch_case_state
from .remote_protocol import strict_json_bytes
from .repository_migration import verify_local_to_github_mirror
from .workspace import Workspace

HUB_SCHEMA = "boule-hub/0.6"
MAX_CASE_ABSOLUTE_LEASE_SECONDS = 12 * 3600
DEFAULT_CASE_CONFIG = {
    "lease_seconds": 3600,
    "absolute_lease_seconds": MAX_CASE_ABSOLUTE_LEASE_SECONDS,
    "stale_seconds": 900,
    "max_renewals": 11,
}
SAFE_CASE_ID = re.compile(r"[a-z0-9][a-z0-9._-]{2,127}\Z")
CaseStateFetcher = Callable[[dict[str, Any]], dict[str, Any]]


def _validate_case_config(value: Any) -> None:
    required = {
        "lease_seconds",
        "absolute_lease_seconds",
        "stale_seconds",
        "max_renewals",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise ProtocolError("hub case config has invalid fields")
    invalid_types = (
        isinstance(value[field], bool) or not isinstance(value[field], int) for field in required
    )
    if any(invalid_types):
        raise ProtocolError("hub case config values must be integers")
    lease = value["lease_seconds"]
    absolute = value["absolute_lease_seconds"]
    stale = value["stale_seconds"]
    renewals = value["max_renewals"]
    if not 60 <= lease <= absolute <= MAX_CASE_ABSOLUTE_LEASE_SECONDS:
        raise ProtocolError("hub case lease bounds are invalid")
    if not 1 <= stale < lease:
        raise ProtocolError("hub case stale threshold is invalid")
    if not 0 <= renewals <= 32 or lease * (renewals + 1) < absolute:
        raise ProtocolError("hub case renewal bounds are invalid")


def _write_json(path: Path, value: dict[str, Any], *, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.chmod(temporary, mode)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(canonical_bytes(value) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, mode)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


class Hub:
    """Trusted local maintainer state; only its registry projection is public."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.control = self.root / ".boule"
        self.config_path = self.control / "config.json"
        self.key_path = self.control / "private" / "registry.pem"
        self.registry_path = self.root / "registry.jsonl"
        self.intake_root = self.root / "intake"
        self.cases_root = self.root / "cases"
        try:
            config = strict_json_bytes(self.config_path.read_bytes())
        except (OSError, ProtocolError) as exc:
            raise ProtocolError("hub config is missing or invalid") from exc
        if not isinstance(config, dict) or set(config) != {
            "schema",
            "registry_key",
            "case_config",
        }:
            raise ProtocolError("hub config has invalid fields")
        if config["schema"] != HUB_SCHEMA:
            raise ProtocolError("hub config is unsupported")
        _validate_case_config(config["case_config"])
        self.key = load_private_key(self.key_path)
        if public_key_text(self.key) != config["registry_key"]:
            raise ProtocolError("hub registry key does not match its config")
        self.config = config
        self.registry = Registry.open(self.registry_path, self.key)

    @classmethod
    def initialize(cls, root: str | Path) -> Hub:
        destination = Path(root)
        control = destination / ".boule"
        if control.exists() or (destination / "registry.jsonl").exists():
            raise FileExistsError("Boule hub is already initialized")
        destination.mkdir(parents=True, exist_ok=True)
        for path in (control, control / "private", destination / "intake", destination / "cases"):
            path.mkdir(parents=True, exist_ok=True, mode=0o700)
            path.chmod(0o700)
        key = generate_private_key()
        write_private_key(control / "private" / "registry.pem", key)
        _write_json(
            control / "config.json",
            {
                "schema": HUB_SCHEMA,
                "registry_key": public_key_text(key),
                "case_config": DEFAULT_CASE_CONFIG,
            },
            mode=0o644,
        )
        Registry.create(destination / "registry.jsonl", key)
        return cls(destination)

    @staticmethod
    def _case_id(imported: ImportResult) -> str:
        slug = str(imported.manifest["slug"])
        commitment = str(imported.manifest["task"]["task_commitment"])
        maximum_slug = 128 - len("case--") - 12
        value = f"case-{slug[:maximum_slug]}-{commitment.removeprefix('sha256:')[:12]}"
        if SAFE_CASE_ID.fullmatch(value) is None:
            raise ProtocolError("derived case identifier is invalid")
        return value

    def propose(
        self,
        source_url: str,
        *,
        mode: str | None = None,
        fetcher: Callable[[str], FetchResponse] = fetch_problem,
    ) -> tuple[dict[str, Any], bool]:
        imported = import_problem(source_url, self.intake_root, mode=mode, fetcher=fetcher)
        commitment = str(imported.manifest["task"]["task_commitment"])
        existing = self.registry.problem_by_commitment(commitment)
        if existing is not None:
            return existing, False
        case_id = self._case_id(imported)
        record = self.registry.record_proposal({"case_id": case_id, "problem": imported.manifest})
        return record, True

    def _validated_import(
        self,
        record: Mapping[str, Any],
        *,
        fetcher: Callable[[str], FetchResponse] = fetch_problem,
    ) -> ImportResult:
        with tempfile.TemporaryDirectory(prefix="boule-admit-") as temporary:
            imported = import_problem(
                str(record["source_url"]),
                Path(temporary) / "problems",
                mode=str(record["task_mode"]),
                fetcher=fetcher,
            )
            manifest = imported.manifest
            task = manifest["task"]
            expected = {
                "problem_id": record["problem_id"],
                "title": record["title"],
                "source_name": record["source_name"],
                "source_url": record["source_url"],
                "task_id": record["task_id"],
                "task_mode": record["task_mode"],
                "task_commitment": record["task_commitment"],
                "formal_repository_pin": record["formal_repository_pin"],
                "pinned_source_url": record["pinned_source_url"],
            }
            actual = {
                "problem_id": manifest["problem_id"],
                "title": manifest["problem"]["title"],
                "source_name": manifest["source"]["provider"],
                "source_url": manifest["source"]["canonical_problem_url"],
                "task_id": task["task_id"],
                "task_mode": task["mode"],
                "task_commitment": task["task_commitment"],
                "formal_repository_pin": task["formal_repository_pin"],
                "pinned_source_url": task["pinned_source_url"],
            }
            if record.get("provider_contract_digest") is not None:
                actual["provider_contract_digest"] = provider_contract_digest(
                    provider_contract_for_problem(manifest)
                )
                expected["provider_contract_digest"] = record["provider_contract_digest"]
            if actual != expected:
                raise ProtocolError("reimported source no longer matches the proposed task")
            return ImportResult(
                path=Path(),
                created=imported.created,
                snapshot_created=imported.snapshot_created,
                manifest=dict(imported.manifest),
            )

    @staticmethod
    def _problem_projection(problem: Any) -> dict[str, Any]:
        try:
            source = problem["source"]
            task = problem["task"]
            details = problem["problem"]
            if not all(isinstance(value, dict) for value in (source, task, details)):
                raise TypeError
            projection = {
                "problem_id": problem["problem_id"],
                "title": details["title"],
                "source_name": source["provider"],
                "source_url": source["canonical_problem_url"],
                "task_id": task["task_id"],
                "task_mode": task["mode"],
                "task_commitment": task["task_commitment"],
                "formal_repository_pin": task["formal_repository_pin"],
                "pinned_source_url": task["pinned_source_url"],
            }
            if "provider_contract" in problem:
                projection["provider_contract_digest"] = provider_contract_digest(
                    provider_contract_for_problem(problem)
                )
            return projection
        except (KeyError, TypeError) as exc:
            raise ProtocolError("case workspace has an incomplete imported problem") from exc

    @staticmethod
    def _record_projection(record: Mapping[str, Any]) -> dict[str, Any]:
        projection = {
            "problem_id": record["problem_id"],
            "title": record["title"],
            "source_name": record["source_name"],
            "source_url": record["source_url"],
            "task_id": record["task_id"],
            "task_mode": record["task_mode"],
            "task_commitment": record["task_commitment"],
            "formal_repository_pin": record["formal_repository_pin"],
            "pinned_source_url": record["pinned_source_url"],
        }
        if record.get("provider_contract_digest") is not None:
            projection["provider_contract_digest"] = record["provider_contract_digest"]
        return projection

    def _canonical_workspace_path(self, record: Mapping[str, Any]) -> Path:
        source_url = record["source_url"]
        task_mode = record["task_mode"]
        if not isinstance(source_url, str) or not isinstance(task_mode, str):
            raise ProtocolError("registry case source identity is invalid")
        canonical_url, selected_mode, source_slug = canonicalize_problem_url(source_url, task_mode)
        if canonical_url != source_url or selected_mode != task_mode:
            raise ProtocolError("registry case source identity is not canonical")
        directory = (
            source_slug if selected_mode == "formalized" else f"{source_slug}-counterexample"
        )
        candidate = self.cases_root / directory
        if candidate.is_symlink():
            raise ProtocolError("case workspace must not be a symlink")
        try:
            root = self.cases_root.resolve(strict=True)
            resolved = candidate.resolve(strict=True)
        except OSError as exc:
            raise ProtocolError("provisioned case workspace does not exist") from exc
        if not resolved.is_relative_to(root):
            raise ProtocolError("case workspace escapes the hub cases root")
        for relative in ("problem.json", ".boule", ".boule/config.json", ".boule/policy.json"):
            path = candidate / relative
            if path.is_symlink():
                raise ProtocolError("case workspace files must not be symlinks")
            try:
                if not path.resolve(strict=True).is_relative_to(root):
                    raise ProtocolError("case workspace files escape the hub cases root")
            except OSError as exc:
                raise ProtocolError("provisioned case workspace is incomplete") from exc
        return resolved

    def _recorded_provision_result(self, record: Mapping[str, Any]) -> ProvisionResult:
        workspace = self.case_workspace(str(record["case_id"]))
        fields = (
            "repo_url",
            "marker_digest",
            "repository_commit",
            "clerk_key",
        )
        if any(not isinstance(record[field], str) for field in fields):
            raise ProtocolError("registry provisioned case has incomplete repository identity")
        repository_id = record["repository_id"]
        repository_node_id = record["repository_node_id"]
        if isinstance(repository_id, bool) or not isinstance(repository_id, (int, str)):
            raise ProtocolError("registry provisioned case has an invalid repository identity")
        if repository_node_id is not None and not isinstance(repository_node_id, str):
            raise ProtocolError("registry provisioned case has an invalid repository identity")
        return ProvisionResult(
            case_id=str(record["case_id"]),
            repository_name=CaseProvisioner.repository_name(
                workspace.root.name, str(record["task_commitment"])
            ),
            repository_url=str(record["repo_url"]),
            local_path=workspace.root,
            marker_digest=str(record["marker_digest"]),
            repository_created=False,
            repository_id=repository_id,
            repository_node_id=repository_node_id,
            problem_id=str(record["problem_id"]),
            task_commitment=str(record["task_commitment"]),
            clerk_key=str(record["clerk_key"]),
            commit=str(record["repository_commit"]),
        )

    def admit(
        self,
        case_id: str,
        *,
        fetcher: Callable[[str], FetchResponse] = fetch_problem,
    ) -> dict[str, Any]:
        record = self.registry.problem(case_id)
        if record["status"] != "PROPOSED":
            raise ProtocolError("only a proposed case may be admitted")
        self._validated_import(record, fetcher=fetcher)
        return self.registry.admit(case_id)

    def provision(
        self,
        case_id: str,
        provider: RepositoryProvider,
        *,
        fetcher: Callable[[str], FetchResponse] = fetch_problem,
    ) -> ProvisionResult:
        record = self.registry.problem(case_id)
        if record["status"] == "ADMITTED":
            self.registry.start_provisioning(case_id)
        elif record["status"] == "PROVISION_FAILED":
            self.registry.retry_provisioning(case_id)
        elif record["status"] == "PROVISIONING" and all(
            record[field] is not None
            for field in (
                "repo_url",
                "marker_digest",
                "repository_commit",
                "clerk_key",
            )
        ):
            return self._recorded_provision_result(record)
        elif record["status"] != "PROVISIONING":
            raise ProtocolError("case is not ready for provisioning")
        provisioner = CaseProvisioner(provider, self.cases_root)
        try:
            result = provisioner.provision(
                str(record["source_url"]),
                case_id=case_id,
                config=self.config["case_config"],
                fetcher=fetcher,
                mode=str(record["task_mode"]),
            )
        except ProtocolError as exc:
            self.registry.mark_provision_failed(case_id, str(exc))
            raise
        if (
            result.problem_id != record["problem_id"]
            or result.task_commitment != record["task_commitment"]
        ):
            self.registry.mark_provision_failed(case_id, "provisioned task identity mismatch")
            raise ProtocolError("provisioned task identity does not match the registry")
        current = self.registry.problem(case_id)
        if current["repo_url"] is None:
            try:
                self.registry.record_repository(
                    case_id,
                    result.repository_url,
                    result.clerk_key,
                    result.marker_digest,
                    result.commit,
                    result.repository_id,
                    result.repository_node_id,
                )
            except ProtocolError:
                self.registry.mark_provision_failed(
                    case_id, "repository has no publishable HTTPS identity"
                )
                raise
        return result

    def case_workspace(self, case_id: str) -> Workspace:
        record = self.registry.problem(case_id)
        workspace = Workspace(self._canonical_workspace_path(record))
        problem_projection = self._problem_projection(workspace.problem)
        if record.get("provider_contract_digest") is None:
            problem_projection.pop("provider_contract_digest", None)
        if problem_projection != self._record_projection(record):
            raise ProtocolError("case workspace problem does not match the registry")
        repository_id = record["marker_repository_id"]
        repository_node_id = record["marker_repository_node_id"]
        if isinstance(repository_id, bool) or not isinstance(repository_id, (int, str)):
            raise ProtocolError("case workspace has an invalid marker repository identity")
        if repository_node_id is not None and not isinstance(repository_node_id, str):
            raise ProtocolError("case workspace has an invalid marker repository identity")
        identity = CaseProvisioner._marker_identity(
            case_id,
            workspace,
            Repository(
                CaseProvisioner.repository_name(
                    workspace.root.name, str(record["task_commitment"])
                ),
                str(record["repo_url"]),
                None,
                False,
                repository_id,
                repository_node_id,
            ),
        )
        if (
            identity["maintainer_key"] != record["clerk_key"]
            or digest_object(identity) != record["marker_digest"]
        ):
            raise ProtocolError("case workspace marker identity does not match the registry")
        return workspace

    def migrate_repository(
        self,
        case_id: str,
        expected_registry_head: str,
        destination: Repository,
        *,
        revalidate: Callable[[], None],
        fetcher: CaseStateFetcher | None = None,
    ) -> dict[str, Any]:
        """Verify and record a one-shot local-to-GitHub repository migration."""
        record = self.registry.problem(case_id)
        if record["status"] != "LIVE":
            raise ProtocolError("only a LIVE case repository may be migrated")
        workspace = self.case_workspace(case_id)
        repository_name = CaseProvisioner.repository_name(
            workspace.root.name, str(record["task_commitment"])
        )
        source = self.root / "repositories" / "remotes" / f"{repository_name}.git"
        try:
            repository_root = (self.root / "repositories" / "remotes").resolve(strict=True)
            resolved_source = source.resolve(strict=True)
        except OSError as exc:
            raise ProtocolError("source case repository is unavailable") from exc
        if source.is_symlink() or not resolved_source.is_relative_to(repository_root):
            raise ProtocolError("source case repository escapes the hub boundary")
        evidence = verify_local_to_github_mirror(
            case_id=case_id,
            record=record,
            workspace=workspace,
            source_git_dir=resolved_source,
            destination=destination,
        )
        bundle = (fetcher or fetch_case_state)(record)
        snapshot = bundle.get("snapshot") if isinstance(bundle, dict) else None
        if not isinstance(snapshot, dict):
            raise ProtocolError("case clerk did not return a verified snapshot")
        evidence_name = evidence.ref_manifest_sha256.removeprefix("sha256:")
        _write_json(
            self.control / "private" / "repository-migrations" / f"{case_id}-{evidence_name}.json",
            {
                "schema": "boule-repository-migration-evidence/0.1",
                "case_id": case_id,
                "marker_blob_sha256": evidence.marker_blob_sha256,
                "ref_manifest": evidence.ref_manifest,
                "ref_manifest_sha256": evidence.ref_manifest_sha256,
            },
            mode=0o600,
        )
        revalidate()
        migrated = self.registry.migrate_repository(
            case_id,
            expected_registry_head,
            evidence.destination.url,
            evidence.destination_commit,
            evidence.destination.repository_id,
            evidence.destination.repository_node_id,
            evidence.marker_blob_sha256,
            evidence.ref_manifest,
            evidence.ref_manifest_sha256,
            snapshot.get("head_event_hash"),
            snapshot.get("event_count"),
        )
        return migrated

    def activate(
        self,
        case_id: str,
        clerk_url: str,
        *,
        fetcher: CaseStateFetcher = fetch_case_state,
    ) -> dict[str, Any]:
        record = self.registry.problem(case_id)
        if record["status"] != "PROVISIONING":
            raise ProtocolError("only a provisioned case may be activated")
        self.case_workspace(case_id)
        provisional = {
            **record,
            "clerk_url": clerk_url,
            "clerk_key": record["clerk_key"],
            "head_event_hash": None,
            "event_count": 0,
        }
        bundle = fetcher(provisional)
        snapshot = bundle.get("snapshot") if isinstance(bundle, dict) else None
        if not isinstance(snapshot, dict):
            raise ProtocolError("case clerk did not return a verified snapshot")
        return self.registry.mark_live(
            case_id,
            clerk_url,
            snapshot["head_event_hash"],
            snapshot["event_count"],
        )

    def tick(self) -> dict[str, Any]:
        self.registry.refresh()
        problems = self.registry.problems()
        counts = Counter(problem["status"] for problem in problems)
        return {
            "registry_head": self.registry.head,
            "registry_event_count": self.registry.count,
            "problem_count": len(problems),
            "status_counts": dict(sorted(counts.items())),
            "actions": {
                "validate": [
                    problem["case_id"] for problem in problems if problem["status"] == "PROPOSED"
                ],
                "provision": [
                    problem["case_id"]
                    for problem in problems
                    if problem["status"] == "ADMITTED"
                    or (problem["status"] == "PROVISIONING" and problem["repo_url"] is None)
                ],
                "recover": [p["case_id"] for p in problems if p["status"] == "PROVISION_FAILED"],
                "activate": [
                    problem["case_id"]
                    for problem in problems
                    if problem["status"] == "PROVISIONING" and problem["repo_url"] is not None
                ],
            },
        }

    def write_watcher_status(self, value: dict[str, Any]) -> Path:
        path = self.control / "watcher.json"
        _write_json(path, value, mode=0o600)
        return path
