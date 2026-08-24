from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from boule.errors import ProtocolError
from boule.problem_import import FetchResponse, canonical_problem_url, import_problem

FIXTURES = Path(__file__).parent / "fixtures" / "conjectures"
BASE = "https://conjectures.io/problems/erdos686-erdos-686-variants-four"
NOW = datetime(2026, 8, 24, 12, 30, tzinfo=UTC)


def response(name: str, final_url: str = BASE) -> FetchResponse:
    return FetchResponse((FIXTURES / name).read_bytes(), final_url)


def test_imports_current_formalized_task_and_is_idempotent(tmp_path: Path) -> None:
    fetch = lambda _: response("erdos686-formalized.html")  # noqa: E731
    first = import_problem(BASE, tmp_path / "problems", fetcher=fetch, now=lambda: NOW)
    second = import_problem(BASE, tmp_path / "problems", fetcher=fetch, now=lambda: NOW)

    assert first.created is True and second.created is False
    assert first.path == second.path
    manifest = json.loads((first.path / "problem.json").read_text())
    assert manifest["problem_id"] == (
        "conjectures:fc-379fc029-variants-four-27f59536d7-formalized-v1"
    )
    assert manifest["task"]["task_id"] == "fc-379fc029-variants-four-27f59536d7-formalized-v1"
    assert manifest["task"]["task_commitment"] == (
        "sha256:bd2f52489d971db4ae4a8c79e106c7fd3080827a8d4dc72f3154e395da098528"
    )
    assert manifest["task"]["formal_repository_pin"] == ("379fc0298dc146df549e7061c3ede0353a5bb51f")
    assert len(list((first.path / "snapshots").iterdir())) == 1


def test_title_comes_from_unique_og_title_and_is_corroborated(tmp_path: Path) -> None:
    body = (FIXTURES / "erdos686-formalized.html").read_bytes()
    assert body.count(b"<h1") == 2
    result = import_problem(
        BASE,
        tmp_path,
        fetcher=lambda _: FetchResponse(body, BASE),
        now=lambda: NOW,
    )
    assert result.manifest["problem"]["title"] == "Erdős problem 686 - four"

    missing_meta = body.replace(b' property="og:title"', b' property="other:title"')
    with pytest.raises(ProtocolError, match="exactly one og:title"):
        import_problem(
            BASE,
            tmp_path / "missing",
            fetcher=lambda _: FetchResponse(missing_meta, BASE),
        )

    mismatched = body.replace(b'Erd\xc5\x91s problem 686 - four"></head>', b'Wrong title"></head>')
    with pytest.raises(ProtocolError, match="corroborate"):
        import_problem(
            BASE,
            tmp_path / "mismatch",
            fetcher=lambda _: FetchResponse(mismatched, BASE),
        )


def test_imports_current_counterexample_as_separate_task(tmp_path: Path) -> None:
    url = f"{BASE}?mode=counterexample"
    fetch = lambda _: response("erdos686-counterexample.html", url)  # noqa: E731
    result = import_problem(url, tmp_path / "problems", fetcher=fetch, now=lambda: NOW)

    assert result.path.name.endswith("-counterexample")
    task = result.manifest["task"]
    assert result.manifest["problem_id"] == (
        "conjectures:fc-379fc029-variants-four-48642f6e67-counterexample-v1"
    )
    assert task["task_id"] == "fc-379fc029-variants-four-48642f6e67-counterexample-v1"
    assert task["source_type_sha256"] == (
        "sha256:cae2f5de9d6a3b7f8694319a5baf6359a0889013314de022a467f203905fec3c"
    )
    assert task["task_commitment"] == (
        "sha256:2c9ab16bc1a6745054b6411054da9c2e886da7051ec89c4383a1604451e1e2a7"
    )


def test_dynamic_page_change_does_not_change_identity(tmp_path: Path) -> None:
    body = (FIXTURES / "erdos686-formalized.html").read_bytes()
    calls = iter([body, body.replace(b"15499.4335", b"15500.0000")])
    fetch = lambda _: FetchResponse(next(calls), BASE)  # noqa: E731
    first = import_problem(BASE, tmp_path, fetcher=fetch, now=lambda: NOW)
    stable = (first.path / "problem.json").read_bytes()
    later = datetime(2026, 8, 25, tzinfo=UTC)
    second = import_problem(BASE, tmp_path, fetcher=fetch, refresh_snapshot=True, now=lambda: later)

    assert second.created is False and second.snapshot_created is True
    assert (first.path / "problem.json").read_bytes() == stable
    assert len(list((first.path / "snapshots").iterdir())) == 2


@pytest.mark.parametrize(
    "url,mode",
    [
        ("http://conjectures.io/problems/x", None),
        ("https://evil.example/problems/x", None),
        (f"{BASE}#fragment", None),
        (f"{BASE}?extra=1", None),
        (f"{BASE}?mode=weird", None),
        (f"{BASE}?mode=counterexample", "formalized"),
    ],
)
def test_url_and_mode_validation_fail_closed(url: str, mode: str | None) -> None:
    with pytest.raises(ProtocolError):
        canonical_problem_url(url, mode)


@pytest.mark.parametrize(
    "old,new,error",
    [
        (b"Task commitment</dt>", b"Missing commitment</dt>", "Task commitment"),
        (b"sha256:bd2f", b"sha256:BD2F", "digests"),
        (b"formalized-v1", b"counterexample-v1", "selected mode"),
        (
            b"theorem target : fcTypeOfName%",
            "theorem target : ¬ (fcTypeOfName%".encode(),
            "theorem shape",
        ),
    ],
)
def test_malformed_task_evidence_leaves_no_files(
    tmp_path: Path, old: bytes, new: bytes, error: str
) -> None:
    body = (FIXTURES / "erdos686-formalized.html").read_bytes().replace(old, new)
    with pytest.raises(ProtocolError, match=error):
        import_problem(BASE, tmp_path / "problems", fetcher=lambda _: FetchResponse(body, BASE))
    assert not (tmp_path / "problems").exists()


def test_response_metadata_and_redirect_fail_closed(tmp_path: Path) -> None:
    body = (FIXTURES / "erdos686-formalized.html").read_bytes()
    bad = [
        FetchResponse(body, BASE, 503),
        FetchResponse(body, BASE, content_type="application/json"),
        FetchResponse(body, "https://conjectures.io/problems/another"),
    ]
    for item in bad:
        with pytest.raises(ProtocolError):
            import_problem(BASE, tmp_path / "problems", fetcher=lambda _, item=item: item)
    assert not (tmp_path / "problems").exists()


def test_duplicate_commitment_conflict_fails_without_overwrite(tmp_path: Path) -> None:
    fetch = lambda _: response("erdos686-formalized.html")  # noqa: E731
    first = import_problem(BASE, tmp_path, fetcher=fetch, now=lambda: NOW)
    manifest_path = first.path / "problem.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["problem"]["title"] = "Conflicting title"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ProtocolError, match="conflicting immutable data"):
        import_problem(BASE, tmp_path, fetcher=fetch, now=lambda: NOW)
