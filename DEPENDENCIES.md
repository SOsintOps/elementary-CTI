# Dependencies

## Critical dependencies

### httpx
- **Type:** SDK (HTTP client)
- **Version:** 0.28.1
- **Contract:** async HTTP calls to ransomware.live API, retry with backoff, rate limit handling
- **Licence:** BSD-3-Clause
- **Why chosen:** async-native, modern API, drop-in replacement for requests with async support
- **Alternatives considered:** aiohttp (heavier, lower-level), requests (sync only)
- **Last verified:** 2026-04-25

### SQLAlchemy
- **Type:** ORM / Database
- **Version:** 2.0.49
- **Contract:** 18+ ORM models, session management, SQLite + PostgreSQL support
- **Licence:** MIT
- **Why chosen:** industry standard Python ORM, 2.0 typed mapping, dual-dialect support
- **Alternatives considered:** Tortoise ORM (async-native but smaller ecosystem), peewee (simpler but less powerful)
- **Last verified:** 2026-04-25

### FastAPI
- **Type:** Web framework
- **Version:** 0.136.1
- **Contract:** REST API endpoints, Jinja2 template rendering, OpenAPI auto-docs
- **Licence:** MIT
- **Why chosen:** async, auto OpenAPI, Pydantic validation, large ecosystem
- **Alternatives considered:** Flask (no async), Starlette (lower-level, FastAPI wraps it)
- **Last verified:** 2026-04-25

### APScheduler
- **Type:** SDK (task scheduler)
- **Version:** 3.11.2 (pinned <4)
- **Contract:** periodic pipeline execution, configurable intervals, graceful shutdown
- **Licence:** MIT
- **Why chosen:** mature, supports async, simple API for periodic jobs
- **Alternatives considered:** Celery (overkill for solo project), custom asyncio loop (less robust)
- **Notes:** pinned to 3.x — 4.x is a full rewrite with breaking API changes
- **Last verified:** 2026-04-25

### Plotly
- **Type:** SDK (visualization)
- **Version:** 6.7.0
- **Contract:** choropleth map rendering (client-side JS via plotly.js)
- **Licence:** MIT
- **Why chosen:** interactive maps with no server-side rendering, good choropleth support
- **Alternatives considered:** Folium/Leaflet (no choropleth colorscale), Matplotlib (static only)
- **Last verified:** 2026-04-25

### feedparser
- **Type:** library (RSS/Atom parsing)
- **Version:** 6.x
- **Contract:** parses article-source feeds in the AI pipeline (`ai/sources/rss.py`, Phase 2)
- **Licence:** BSD-2-Clause
- **Why chosen:** de-facto standard, battle-tested against malformed real-world feeds; pure Python
- **Alternatives considered:** stdlib xml.etree (fragile on real feeds), atoma (less maintained)
- **Last verified:** 2026-06-12

### trafilatura
- **Type:** library (web content extraction)
- **Version:** 2.x
- **Contract:** full-text extraction of article pages (`ai/sources/fulltext.py`, Phase 2)
- **Licence:** Apache-2.0
- **Why chosen:** best-in-class readability extraction in pure Python, benchmark leader
- **Alternatives considered:** readability-lxml (less accurate), newspaper3k (unmaintained)
- **Last verified:** 2026-06-12

### psycopg2-binary
- **Type:** SDK (database driver)
- **Version:** 2.9.x
- **Contract:** PostgreSQL connectivity for SQLAlchemy
- **Licence:** LGPL-3.0
- **Why chosen:** most mature Python PostgreSQL adapter, binary package avoids libpq build dependency
- **Alternatives considered:** asyncpg (async-only, requires different SQLAlchemy setup), psycopg3 (newer but less battle-tested)
- **Notes:** use `psycopg2` (non-binary) in production if building from source is preferred
- **Last verified:** 2026-04-25

### model2vec
- **Type:** library (static text embeddings)
- **Version:** 0.8.2
- **Contract:** vectorises articles for campaign clustering (`ai/embeddings.py`); model `minishlab/potion-base-8M` (256 dim, ~30 MB) fetched at image build by `scripts/fetch_embedding_model.py`, never at request time
- **Licence:** MIT (model weights: MIT)
- **Why chosen:** static lookup-and-pool embeddings run on the Pi's CPU at ~1,400 docs/s with no torch and no ONNX runtime; chosen over an ONNX transformer **by measurement on the live corpus**, not by recommendation — method and numbers recorded in the upstream working repository (local-AI plan, step A3)
- **Alternatives considered:** fastembed/onnxruntime (16 transitive packages vs 11, heavier per-document cost), sentence-transformers (pulls torch — ruled out on a Pi), TF-IDF (kept as the fallback backend and the baseline any future model is measured against)
- **Transitive weight (the real cost):** numpy 2.5.1 (BSD-3), tokenizers 0.23.1 (Apache-2.0), safetensors 0.8.0 (Apache-2.0), huggingface-hub 1.27.0 + hf-xet 1.6.0 (Apache-2.0, build-time fetch only), joblib 1.5.3 (BSD-3) — ~60 MB installed, the largest single addition since Plotly
- **Last verified:** 2026-08-08

## Front-end assets (vendored — permanent no-remote-assets rule, UI-SPEC.md §6)

All served from `static/`, committed in the repo. Never reference a remote URL in templates.

| Asset | Version | Path | Licence |
|---|---|---|---|
| Tailwind Play runtime | 3.x (CDN snapshot 2026-06-11) | `static/vendor/tailwindcss-play.js` | MIT |
| HTMX | 2.0.4 | `static/vendor/htmx.min.js` | BSD-2 |
| plotly.js | 2.35.2 | `static/vendor/plotly-2.35.2.min.js` | MIT |
| Inter (variable woff2, latin + latin-ext) | v20 | `static/fonts/` | OFL-1.1 |

## Runtime dependencies (non-critical)

### anyio
- **Purpose:** async compatibility layer, used by httpx
- **Version:** 4.13.0
- **Pinned:** no (range >=4.0)

### Jinja2
- **Purpose:** HTML template rendering for web UI
- **Version:** 3.1.6
- **Pinned:** no (range >=3.1)

### uvicorn
- **Purpose:** ASGI server for FastAPI
- **Version:** 0.46.0
- **Pinned:** no (range >=0.30)

### python-dotenv
- **Purpose:** load `.env` files for configuration
- **Version:** 1.2.2
- **Pinned:** no (range >=1.0)

### thefuzz
- **Purpose:** fuzzy string matching for watchlist alerts
- **Version:** 0.22.1
- **Pinned:** no (range >=0.22)

### Pillow
- **Purpose:** image manipulation for mugshot avatar generator
- **Version:** 12.3.0
- **Pinned:** no (range >=10.0)

## Development dependencies

### pytest
- **Purpose:** test runner
- **Version:** 9.0.3
- **Pinned:** no (range >=8.0)

### pytest-cov
- **Purpose:** coverage reporting and ratchet enforcement
- **Version:** 7.1.0
- **Pinned:** no (range >=6.0)

### pytest-httpx
- **Purpose:** mock httpx requests in tests
- **Version:** 0.36.2
- **Pinned:** no (range >=0.30)

### ruff
- **Purpose:** linter and formatter
- **Version:** 0.15.11
- **Pinned:** no (range >=0.4)
