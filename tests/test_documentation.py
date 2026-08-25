import re
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
MARKDOWN_ROOTS = (
    ROOT / "README.md",
    ROOT / "CONTRIBUTING.md",
    ROOT / "AGENTS.md",
    ROOT / "docs",
    ROOT / "examples",
    ROOT / "cases",
)
LINK_RE = re.compile(r"(?<!!)\[[^]]+\]\(([^)]+)\)")


def markdown_files() -> list[Path]:
    files: list[Path] = []
    for root in MARKDOWN_ROOTS:
        if root.is_file():
            files.append(root)
        else:
            files.extend(root.rglob("*.md"))
    return sorted(files)


def test_relative_markdown_links_resolve() -> None:
    missing: list[str] = []
    for document in markdown_files():
        for raw_target in LINK_RE.findall(document.read_text(encoding="utf-8")):
            target = raw_target.strip().split(maxsplit=1)[0].strip("<>")
            parsed = urlsplit(target)
            if parsed.scheme or parsed.netloc or not parsed.path:
                continue
            destination = document.parent / unquote(parsed.path)
            if not destination.exists():
                missing.append(f"{document.relative_to(ROOT)} -> {target}")
    assert not missing, "missing relative Markdown links:\n" + "\n".join(missing)
