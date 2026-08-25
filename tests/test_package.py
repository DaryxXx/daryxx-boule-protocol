from importlib.metadata import version
from importlib.resources import files

from boule import __version__
from boule.version import USER_AGENT


def test_public_version_matches_distribution_metadata() -> None:
    assert __version__ == version("boule-protocol")
    assert USER_AGENT == f"Boule/{__version__}"


def test_observatory_assets_are_packaged() -> None:
    web = files("boule").joinpath("web")
    for name in ("index.html", "styles.css", "app.js", "favicon.svg", "docs.html", "llms.txt"):
        assert web.joinpath(name).is_file(), name
