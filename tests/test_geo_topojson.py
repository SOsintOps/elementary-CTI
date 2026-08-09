"""Geo maps only render if BOTH halves hold — pin them together.

Plotly fetches world boundaries at render time. The default source is
cdn.plot.ly, which the CSP (connect-src 'self') blocks and the perennial
no-remote-assets rule forbids; the maps shipped blank for a day before anyone
noticed, because the only symptom is a console error. Like the /guide
changelog bug, the fix has two independently-breakable halves: the shared
Plotly config must point at the vendored path, and the vendored file must
actually exist (with the object the choropleth traces read). One test per
half, plus one pinning that no template opts into a geo scope or resolution
whose boundary file we did not vendor.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pestilentia.web as web

STATIC = Path(web.__file__).resolve().parent / "static"
TOPOJSON_DIR = STATIC / "vendor" / "plotly-topojson"
TEMPLATES = Path(web.__file__).resolve().parent / "templates"


def test_shared_plotly_config_points_at_the_vendored_topojson():
    theme = (STATIC / "pest-theme.js").read_text(encoding="utf-8")
    assert "topojsonURL: '/static/vendor/plotly-topojson/'" in theme, (
        "plotlyConfig no longer routes Plotly's boundary fetch to the vendored "
        "copy; geo maps will fetch cdn.plot.ly, which the CSP blocks"
    )


def test_the_vendored_world_file_exists_and_carries_countries():
    world = TOPOJSON_DIR / "world_110m.json"
    assert world.is_file(), "world_110m.json missing; every geo map renders blank"
    data = json.loads(world.read_text(encoding="utf-8"))
    assert data.get("type") == "Topology"
    assert "countries" in data.get("objects", {}), (
        "the choropleth traces read objects.countries; a file without it renders an empty map"
    )


def test_no_template_requests_a_boundary_file_we_did_not_vendor():
    """Plotly resolves scope+resolution to a file name (e.g. europe_50m.json).

    The defaults (world, 110m) are the only ones vendored; a template that
    sets geo.scope or geo.resolution silently reintroduces a blocked CDN
    fetch. This stays green until someone does that — then it names the file
    they must vendor.
    """
    offenders = []
    for template in TEMPLATES.glob("*.html"):
        text = template.read_text(encoding="utf-8")
        for match in re.finditer(r"\b(scope|resolution)\s*:", text):
            snippet = text[max(0, match.start() - 80) : match.start()]
            if "geo" in snippet:
                offenders.append(f"{template.name}: geo {match.group(1)}")
    assert not offenders, (
        f"{offenders} — vendor the matching topojson file(s) into "
        f"{TOPOJSON_DIR} and extend this test"
    )
