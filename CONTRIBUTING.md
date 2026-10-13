# Contributing

Elementary CTI is a solo project, developed in the open. Issues and pull
requests are welcome, but review may take time — if you plan something larger
than a fix, open an issue first so the work is not wasted.

## From clone to green

```sh
git clone https://github.com/SOsintOps/elementary-CTI.git
cd elementary-CTI
uv sync --extra dev                            # Python 3.11+; the dev tools (pytest, ruff) live in this extra
uv run python scripts/fetch_embedding_model.py # ~30 MB, one-time; without it 4 tests skip and clustering falls back to TF-IDF
uv run pytest -q                               # must be green
uv run ruff check src/ tests/ scripts/         # must be clean
uv run ruff format --check src/ tests/ scripts/
```

Run the app locally with `uv run uvicorn pestilentia.web.app:app --reload`,
or as the production stack with `docker compose up -d` — see `DEPLOY.md`.
The Docker build needs no manual steps: it fetches the embedding model itself.

## Rules that will be applied to your PR

- **Conventional Commits** (`feat:`, `fix:`, `docs:`, …) — the history is kept
  clean and the release notes are cut from it.
- **Tests accompany code.** A behaviour change without a test pinning it will
  be asked for one.
- **Every user-visible change updates `CHANGELOG.md` `[Unreleased]`.** This
  repo treats documentation drift as a defect, not a chore.
- **No remote front-end assets.** Everything under `static/` is vendored;
  never reference a CDN in a template (`UI-SPEC.md` §6).
- **Protected paths** need explicit maintainer approval before changes:
  `docker-compose.yml`, and the design records (product requirements and ADRs,
  kept outside this distribution).
- **Schema changes are migrations.** Model edits without an Alembic revision
  break the deployed PostgreSQL — `create_all` does not alter existing tables.

## Where things are

| What | Where |
|---|---|
| Schema source of truth | `src/pestilentia/models/tables.py` + `alembic/` |
| API reference | FastAPI's `/docs` and `/redoc` on a running instance |
| Current state & history | `CHANGELOG.md` |
| Design decisions | Kept outside this distribution; the reasoning that matters to users is in `docs/FAQ.md` and in the module docstrings |
| Development playbook | [Codex Machinae](https://github.com/SOsintOps/codex-machinae) |
| Intelligence method (grading, estimative language, report writing) | [Intelligence Field Notes](https://github.com/SOsintOps/intelligence-field-notes) |

## Licence

AGPL-3.0. By contributing you agree your work is released under the same
licence.
