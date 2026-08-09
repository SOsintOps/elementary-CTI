## What this changes

<!-- One or two sentences. What and why, not a file list. -->

## How it was verified

- [ ] `uv run pytest -q` green
- [ ] `uv run ruff check src/ tests/ scripts/` clean
- [ ] `uv run ruff format --check src/ tests/ scripts/` clean
- [ ] CHANGELOG `[Unreleased]` updated (if user-visible)
- [ ] Schema change carries an Alembic migration (if models changed)

## Notes for the reviewer

<!-- Anything non-obvious: a trade-off, a follow-up, a risk. -->
