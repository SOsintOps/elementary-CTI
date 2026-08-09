FROM python:3.14-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Create the runtime user before anything lands in /app, and own the workdir up
# front. The previous Dockerfile did the reverse — built everything as root,
# then `chown -R appuser /app` at the end — which rewrites every file, including
# the ~289 MB virtualenv, into a fresh layer that duplicates all of /app (~180 MB
# of pure waste). Owning the tree first and writing to it as appuser means each
# artifact is created with the right owner once and never rewritten.
RUN useradd -m -u 1000 appuser && mkdir -p /app && chown appuser:appuser /app
WORKDIR /app
USER appuser

COPY --chown=appuser:appuser pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

COPY --chown=appuser:appuser src/ src/
COPY --chown=appuser:appuser alembic.ini ./
COPY --chown=appuser:appuser alembic/ alembic/

RUN uv sync --frozen --no-dev

# Campaign clustering loads this at request time and must never fetch it then:
# the Pi's DNS is intermittent, so a lazy download would be a latent outage.
# Baked into the image rather than mounted, because docker-compose.yml is a
# protected path. ~30 MB; without it the app still boots and falls back to
# TF-IDF.
#
# Fetched here rather than COPYed from the build context. A COPY only works if
# whoever runs the build happened to fetch the model first, which made a fresh
# clone fail to build at all — verified, and the reason this is a RUN.
COPY --chown=appuser:appuser scripts/fetch_embedding_model.py scripts/
RUN uv run --no-sync python scripts/fetch_embedding_model.py

# The /guide Changelog tab renders this file at request time. Copied after the
# dependency sync so editing it does not invalidate that layer.
COPY --chown=appuser:appuser CHANGELOG.md ./

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/healthz')" || exit 1

# --no-server-header: uvicorn otherwise emits its own `Server: uvicorn` at the
# ASGI-server layer, after the app middleware runs, so the middleware's
# `Server: Elementary CTI` ended up as a *second* header rather than a
# replacement. Suppressing uvicorn's leaves the middleware's as the only one.
CMD ["uv", "run", "uvicorn", "pestilentia.web.app:app", "--host", "0.0.0.0", "--port", "8000", "--no-server-header"]
