from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from html.parser import HTMLParser
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit
from urllib.request import Request, urlopen

from .errors import ProtocolError

SCHEMA = "boule-problem/0.1"
SNAPSHOT_SCHEMA = "boule-problem-snapshot/0.1"
MAX_PAGE_BYTES = 4 * 1024 * 1024
SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
TASK_ID_RE = re.compile(r"fc-[a-z0-9-]+-(formalized|counterexample)-v[0-9]+\Z")
COMMIT_RE = re.compile(r"/blob/([0-9a-f]{40})/")
TARGET_RE = re.compile(r'fcTypeOfName%\s+"([A-Za-z0-9_.]+)"')
SLUG_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,126}[a-z0-9])?\Z")


@dataclass
class _Node:
    tag: str
    attrs: dict[str, str]
    children: list[_Node | str] = field(default_factory=list)

    def text(self) -> str:
        return "".join(child if isinstance(child, str) else child.text() for child in self.children)

    def descendants(self, tag: str) -> list[_Node]:
        found: list[_Node] = []
        for child in self.children:
            if isinstance(child, _Node):
                if child.tag == tag:
                    found.append(child)
                found.extend(child.descendants(tag))
        return found


class _TreeParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.root = _Node("document", {})
        self.stack = [self.root]
        self.ignored_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if self.ignored_depth:
            self.ignored_depth += 1
            return
        if tag in {"script", "style", "noscript"}:
            self.ignored_depth = 1
            return
        node = _Node(tag, {key: value or "" for key, value in attrs})
        self.stack[-1].children.append(node)
        if tag not in {"meta", "link", "img", "br", "hr", "input"}:
            self.stack.append(node)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        if self.stack[-1].tag == tag:
            self.stack.pop()

    def handle_endtag(self, tag: str) -> None:
        if self.ignored_depth:
            self.ignored_depth -= 1
            return
        if len(self.stack) > 1 and self.stack[-1].tag == tag:
            self.stack.pop()

    def handle_data(self, data: str) -> None:
        if not self.ignored_depth:
            self.stack[-1].children.append(data)


@dataclass(frozen=True)
class FetchResponse:
    body: bytes
    final_url: str
    status: int = 200
    content_type: str = "text/html; charset=utf-8"


@dataclass(frozen=True)
class ImportResult:
    path: Path
    created: bool
    snapshot_created: bool
    manifest: dict[str, object]


def canonical_problem_url(url: str, mode: str | None = None) -> tuple[str, str, str]:
    parts = urlsplit(url)
    if parts.scheme != "https" or parts.hostname != "conjectures.io" or parts.port is not None:
        raise ProtocolError("problem URL must use https://conjectures.io")
    if parts.username or parts.password or parts.fragment:
        raise ProtocolError("problem URL cannot contain credentials or a fragment")
    segments = parts.path.split("/")
    if len(segments) != 3 or segments[1] != "problems" or not SLUG_RE.fullmatch(segments[2]):
        raise ProtocolError("problem URL must have path /problems/<safe-slug>")
    query = parse_qs(parts.query, keep_blank_values=True, strict_parsing=True)
    if set(query) - {"mode"} or any(len(values) != 1 for values in query.values()):
        raise ProtocolError("problem URL has unsupported query parameters")
    query_mode = query.get("mode", [None])[0]
    if query_mode not in {None, "formalized", "counterexample"}:
        raise ProtocolError("problem mode must be formalized or counterexample")
    if mode not in {None, "formalized", "counterexample"}:
        raise ProtocolError("problem mode must be formalized or counterexample")
    if mode is not None and query_mode is not None and mode != query_mode:
        raise ProtocolError("explicit mode conflicts with the URL mode")
    selected = mode or query_mode or "formalized"
    query_text = urlencode({"mode": selected}) if selected == "counterexample" else ""
    canonical = urlunsplit(("https", "conjectures.io", parts.path, query_text, ""))
    return canonical, selected, segments[2]


def _normalize_text(value: str) -> str:
    return " ".join(value.split())


def _unique_text_node(root: _Node, tag: str, expected: str) -> _Node:
    matches = [node for node in root.descendants(tag) if _normalize_text(node.text()) == expected]
    if len(matches) != 1:
        raise ProtocolError(f"expected exactly one {expected!r} label, found {len(matches)}")
    return matches[0]


def _ancestor_with(node: _Node, root: _Node, wanted_tag: str) -> _Node:
    def visit(parent: _Node) -> _Node | None:
        if node in parent.children:
            if parent.descendants(wanted_tag):
                return parent
            return None
        for child in parent.children:
            if isinstance(child, _Node):
                result = visit(child)
                if result is not None:
                    return result
        return None

    result = visit(root)
    if result is None:
        raise ProtocolError(f"label has no associated {wanted_tag} value")
    return result


def _label_value(root: _Node, label: str) -> str:
    label_node = _unique_text_node(root, "dt", label)
    container = _ancestor_with(label_node, root, "dd")
    values = container.descendants("dd")
    if len(values) != 1:
        raise ProtocolError(f"expected exactly one value for {label}")
    return _normalize_text(values[0].text())


def parse_problem_html(
    body: bytes, source_url: str, mode: str
) -> tuple[dict[str, object], dict[str, object]]:
    try:
        html = body.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProtocolError("problem page must be UTF-8") from exc
    parser = _TreeParser()
    parser.feed(html)
    parser.close()
    root = parser.root

    title_meta = [
        node.attrs["content"].strip()
        for node in root.descendants("meta")
        if node.attrs.get("property") == "og:title" and node.attrs.get("content", "").strip()
    ]
    if len(title_meta) != 1:
        raise ProtocolError(f"expected exactly one og:title, found {len(title_meta)}")
    title = title_meta[0]
    h1_titles = [
        _normalize_text(node.text())
        for node in root.descendants("h1")
        if node.text().strip()
    ]
    if h1_titles.count(title) != 1:
        raise ProtocolError("exactly one h1 must corroborate og:title")
    lean_label = _unique_text_node(root, "p", "Lean type")
    lean_container = _ancestor_with(lean_label, root, "code")
    lean_codes = lean_container.descendants("code")
    if len(lean_codes) != 1:
        raise ProtocolError("expected exactly one Lean type block")
    lean_type = lean_codes[0].text().strip()
    proof_nodes = [
        node
        for node in root.descendants("pre")
        if node.attrs.get("aria-label") == "What you must prove"
    ]
    if len(proof_nodes) != 1 or len(proof_nodes[0].descendants("code")) != 1:
        raise ProtocolError("expected exactly one proof template")
    proof_template = proof_nodes[0].descendants("code")[0].text().strip() + "\n"

    pinned_labels = [
        node
        for node in root.descendants("span")
        if _normalize_text(node.text()).rstrip(":") == "Pinned source"
    ]
    if len(pinned_labels) != 1:
        raise ProtocolError("expected exactly one Pinned source label")
    pinned_container = _ancestor_with(pinned_labels[0], root, "a")
    links = pinned_container.descendants("a")
    if len(links) != 1:
        raise ProtocolError("expected exactly one pinned source link")
    pinned_url = links[0].attrs.get("href", "")
    commit_match = COMMIT_RE.search(pinned_url)
    if (
        urlsplit(pinned_url).scheme != "https"
        or urlsplit(pinned_url).hostname != "github.com"
        or commit_match is None
    ):
        raise ProtocolError("pinned source must be a GitHub blob URL at a 40-hex commit")

    source_digest = _label_value(root, "Source type SHA-256")
    task_id = _label_value(root, "Task id")
    commitment = _label_value(root, "Task commitment")
    if not SHA256_RE.fullmatch(source_digest) or not SHA256_RE.fullmatch(commitment):
        raise ProtocolError("source and task digests must be lowercase sha256 values")
    task_match = TASK_ID_RE.fullmatch(task_id)
    if task_match is None or task_match.group(1) != mode:
        raise ProtocolError("task id does not match the selected mode")
    targets = TARGET_RE.findall(proof_template)
    if len(targets) != 1:
        raise ProtocolError("proof template must contain exactly one fcTypeOfName target")
    if mode == "formalized":
        expected = re.compile(r'theorem\s+target\s*:\s*fcTypeOfName%\s+"[^"\n]+"\s*:=')
    else:
        expected = re.compile(r'theorem\s+target\s*:\s*¬\s*\(fcTypeOfName%\s+"[^"\n]+"\)\s*:=')
    if expected.search(proof_template) is None:
        raise ProtocolError("proof template theorem shape does not match the selected mode")

    bounty_labels = [
        node for node in root.descendants("p") if _normalize_text(node.text()) == "Bounty"
    ]
    bounty = None
    if len(bounty_labels) == 1:
        parent = _ancestor_with(bounty_labels[0], root, "p")
        texts = [_normalize_text(node.text()) for node in parent.descendants("p")]
        bounty = next((text for text in texts if text != "Bounty"), None)
    attempts = sorted(
        {
            _normalize_text(node.text())
            for node in root.descendants("span")
            if "attempts" in node.text()
        }
    )
    manifest: dict[str, object] = {
        "schema": SCHEMA,
        "problem_id": f"conjectures:{task_id}",
        "slug": urlsplit(source_url).path.rsplit("/", 1)[-1],
        "source": {"provider": "conjectures.io", "canonical_problem_url": source_url},
        "problem": {"title": title},
        "task": {
            "mode": mode,
            "task_id": task_id,
            "task_commitment": commitment,
            "lean_type": lean_type,
            "proof_template": proof_template,
            "pinned_source_url": pinned_url,
            "formal_repository_pin": commit_match.group(1),
            "source_type_sha256": source_digest,
            "reward_target_id": f"fc-target:{targets[0]}",
        },
    }
    snapshot: dict[str, object] = {
        "schema": SNAPSHOT_SCHEMA,
        "source_url": source_url,
        "page_sha256": f"sha256:{hashlib.sha256(body).hexdigest()}",
        "task_commitment": commitment,
        "bounty_display": bounty,
        "attempts_display": attempts,
    }
    return manifest, snapshot


def fetch_problem(url: str, timeout: float = 15.0) -> FetchResponse:
    request = Request(url, headers={"User-Agent": "Boule/0.3 problem importer"})
    try:
        with urlopen(request, timeout=timeout) as response:
            body = response.read(MAX_PAGE_BYTES + 1)
            result = FetchResponse(
                body=body,
                final_url=response.geturl(),
                status=response.status,
                content_type=response.headers.get("Content-Type", ""),
            )
    except (HTTPError, URLError, TimeoutError) as exc:
        raise ProtocolError(f"problem fetch failed: {exc}") from exc
    return result


def _validated_response(response: FetchResponse, expected_url: str, mode: str) -> None:
    if response.status != 200:
        raise ProtocolError(f"problem fetch returned HTTP {response.status}")
    if len(response.body) > MAX_PAGE_BYTES:
        raise ProtocolError("problem page exceeds the size limit")
    if response.content_type.split(";", 1)[0].strip().lower() != "text/html":
        raise ProtocolError("problem response is not HTML")
    final_url, final_mode, _ = canonical_problem_url(response.final_url)
    if final_url != expected_url or final_mode != mode:
        raise ProtocolError("problem fetch redirected to a different problem or mode")


def _write_json(path: Path, value: dict[str, object]) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(value, handle, indent=2, sort_keys=True, ensure_ascii=False)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())


def _load_manifest(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProtocolError(f"cannot validate existing problem manifest: {path}") from exc
    if not isinstance(value, dict) or value.get("schema") != SCHEMA:
        raise ProtocolError(f"existing problem manifest has an unsupported schema: {path}")
    return value


def import_problem(
    url: str,
    root: str | Path,
    *,
    mode: str | None = None,
    refresh_snapshot: bool = False,
    fetcher: Callable[[str], FetchResponse] = fetch_problem,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> ImportResult:
    canonical_url, selected_mode, source_slug = canonical_problem_url(url, mode)
    response = fetcher(canonical_url)
    _validated_response(response, canonical_url, selected_mode)
    manifest, snapshot = parse_problem_html(response.body, canonical_url, selected_mode)
    snapshot["fetched_at"] = now().astimezone(UTC).isoformat().replace("+00:00", "Z")
    snapshot["final_url"] = response.final_url
    snapshot["http_status"] = response.status
    snapshot["content_type"] = response.content_type
    commitment = manifest["task"]["task_commitment"]  # type: ignore[index]

    root_path = Path(root)
    if root_path.exists() and not root_path.is_dir():
        raise ProtocolError("problems root is not a directory")
    for existing_path in sorted(root_path.glob("*/problem.json")) if root_path.exists() else []:
        existing = _load_manifest(existing_path)
        existing_task = existing.get("task")
        if isinstance(existing_task, dict) and existing_task.get("task_commitment") == commitment:
            if existing != manifest:
                raise ProtocolError(
                    "task commitment already exists with conflicting immutable data"
                )
            created = (
                _append_snapshot(existing_path.parent, snapshot) if refresh_snapshot else False
            )
            return ImportResult(existing_path.parent, False, created, existing)

    directory_slug = (
        source_slug if selected_mode == "formalized" else f"{source_slug}-counterexample"
    )
    destination = root_path / directory_slug
    if destination.exists():
        raise ProtocolError("problem destination already exists with another task commitment")
    root_path.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{directory_slug}-", dir=root_path))
    try:
        (staging / "snapshots").mkdir()
        _write_json(staging / "problem.json", manifest)
        _write_json(staging / "snapshots" / _snapshot_name(snapshot), snapshot)
        os.replace(staging, destination)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return ImportResult(destination, True, True, manifest)


def _snapshot_name(snapshot: dict[str, object]) -> str:
    fetched = str(snapshot["fetched_at"]).replace(":", "").replace("-", "")
    digest = str(snapshot["page_sha256"]).removeprefix("sha256:")[:12]
    return f"{fetched}-{digest}.json"


def _append_snapshot(problem_dir: Path, snapshot: dict[str, object]) -> bool:
    snapshots = problem_dir / "snapshots"
    snapshots.mkdir(exist_ok=True)
    destination = snapshots / _snapshot_name(snapshot)
    if destination.exists():
        existing = json.loads(destination.read_text(encoding="utf-8"))
        if existing != snapshot:
            raise ProtocolError("snapshot filename collision")
        return False
    temporary = snapshots / f".{destination.name}.tmp"
    try:
        _write_json(temporary, snapshot)
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)
    return True
