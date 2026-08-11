"""The Changelog tab of /guide renders CHANGELOG.md at request time.

It shipped blank in production for two months: the Dockerfile never copied
CHANGELOG.md into the image, and the route answered a missing file with an
empty string, so the panel looked like a product with no history instead of a
deployment missing a file. These tests pin both halves — real content when the
file is there, an explanation when it is not.
"""

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import pestilentia.config as config
import pestilentia.web.app as web
from pestilentia.config import Settings
from pestilentia.models.base import Base
from pestilentia.web.app import app


@pytest.fixture
def client(monkeypatch, authenticate):
    # Session auth (v0.7): the guide pages sit behind login like everything
    # else, so the fixture seeds a user in an in-memory DB and signs in.
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    monkeypatch.setattr(config, "_settings", Settings(secret_key="x" * 64))
    monkeypatch.setattr(web, "_session_factory", factory)
    c = TestClient(app)
    authenticate(c, factory)
    yield c
    web._session_factory = None
    config._settings = None


def test_changelog_file_ships_at_the_path_the_route_reads():
    """The route resolves the repo root; the Dockerfile mirrors that layout."""
    assert web.CHANGELOG_PATH.name == "CHANGELOG.md"
    assert web.CHANGELOG_PATH.exists(), (
        f"{web.CHANGELOG_PATH} is missing — if this fails inside a container, "
        "the Dockerfile stopped copying CHANGELOG.md"
    )


def test_image_build_carries_the_changelog():
    """Two independent gates hid this file from production for two months: the
    Dockerfile never copied it, and .dockerignore excludes every *.md. Fixing
    either one alone still ships a blank panel, so both are pinned here."""
    root = web.CHANGELOG_PATH.parent
    dockerfile = (root / "Dockerfile").read_text(encoding="utf-8")
    # Match the intent (a COPY whose source is CHANGELOG.md), not an exact
    # string — the copy grew a `--chown=` flag in the layer-dedup work and a
    # literal-substring check broke on it while the file was still shipped.
    assert re.search(r"^COPY\b.*\bCHANGELOG\.md\b", dockerfile, re.MULTILINE), (
        "Dockerfile no longer copies the changelog"
    )

    ignore = (root / ".dockerignore").read_text(encoding="utf-8").splitlines()
    rules = [ln.strip() for ln in ignore if ln.strip() and not ln.strip().startswith("#")]
    assert "*.md" in rules, "blanket *.md exclusion gone — this guard needs rewriting"
    # Later rules win, so the negation has to come after the exclusion.
    assert rules.index("!CHANGELOG.md") > rules.index("*.md")


def test_guide_renders_changelog_content(client):
    body = client.get("/guide").text
    # A released version heading, rendered from markdown rather than echoed raw.
    assert "<h2" in body
    assert "0.7.0" in body
    assert "changelog-content" in body


def test_guide_does_not_leak_raw_markdown(client):
    """Markdown is converted, not dumped: no literal '## [' in the output."""
    assert "## [" not in client.get("/guide").text


def test_missing_changelog_explains_itself(client, monkeypatch, tmp_path):
    monkeypatch.setattr(web, "CHANGELOG_PATH", tmp_path / "absent.md")
    body = client.get("/guide").text
    assert "not available in this deployment" in body
    assert "changelog-missing" in body


def test_unreadable_changelog_does_not_500(client, monkeypatch, tmp_path):
    """A directory at the path raises OSError on read, not on exists()."""
    directory = tmp_path / "CHANGELOG.md"
    directory.mkdir()
    monkeypatch.setattr(web, "CHANGELOG_PATH", directory)
    response = client.get("/guide")
    assert response.status_code == 200
    assert "not available in this deployment" in response.text


def test_changelog_panel_carries_both_themes():
    """Markdown output cannot wear Tailwind dark: classes, so the panel's own
    CSS must define a .dark counterpart for every colour it sets."""
    template = (Path(web.__file__).resolve().parent / "templates" / "guide.html").read_text(
        encoding="utf-8"
    )
    for selector in (
        ".dark .changelog-content h2",
        ".dark .changelog-content h3",
        ".dark .changelog-content code",
        ".dark .changelog-content strong",
        ".dark .changelog-content a",
    ):
        assert selector in template, f"{selector} has no dark-mode rule"
