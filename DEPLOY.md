# Deploy — single host (Docker + Postgres)

Runbook for running Elementary CTI on one machine (e.g. a Raspberry Pi 5, arm64)
with the bundled `docker-compose.yml`: a Postgres database, the web UI, and the
collection scheduler. The database starts empty and the scheduler backfills it
from the configured sources on the first cycles; if you have a SQLite dump to
seed from, an optional import step is included.



## Weekly API sentinel

A user-level systemd timer (`api-sentinel.timer`, Sundays 07:30, `Persistent=true`)
checks that every upstream this codebase parses is **alive and unchanged in
shape**: 19 contracts — the three ransomware.live endpoints, Ransomwhere,
the three deepdarkCTI tables, and the 12 article feeds. Type-structure
baselines live in `contracts/` (committed); drift reports land in
`.reports/api-drift/` (gitignored).

On drift the wrapper asks `claude -p` (headless, plan mode, authenticated via
the Max subscription's file-based credentials — no keyring, so it survives
reboots unattended) for an impact analysis: what changed, which code consumes
it (file:line), and the minimum indispensable fix — written next to the drift
report, never auto-applied.

- Install/reinstall: `bash scripts/install_api_sentinel.sh` (no sudo; linger
  is enabled for the user).
- Status at a glance: `systemctl --user --failed` — the unit **fails on
  purpose on drift weeks** (exit 3) and succeeds on clean ones.
- Logs: `journalctl --user -u api-sentinel.service`
- Manual run: `systemctl --user start api-sentinel.service`
- After a *deliberate* upstream change is absorbed: re-capture baselines with
  `uv run python scripts/api_sentinel.py --update` and commit `contracts/`.

Plan and drill evidence are kept in the upstream working repository.

## Build prerequisites

None beyond Docker. The image fetches the local embedding model (~30 MB) during
the build, so a fresh clone builds without any manual step — verified by
building from a clean clone, not assumed.

`uv.lock` is tracked on purpose: the Dockerfile runs `uv sync --frozen`, which
cannot resolve without it. Until it was committed, a fresh clone failed at the
dependency layer.

The model is baked into the image rather than mounted, because
`docker-compose.yml` is a protected path and because a runtime download would
make page rendering depend on DNS. Without the model the app still starts and
campaign clustering falls back to TF-IDF.

## 0. Prerequisites

Docker Engine + Compose plugin. On Raspberry Pi OS:

```bash
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker "$USER"   # then log out/in so the group takes effect
docker compose version            # sanity check
```

## 1. Configure `.env`

```bash
cd ~/github/elementary-CTI
cp .env.example .env
```

Edit `.env` and set at least:

```ini
POSTGRES_PASSWORD=<a strong random password>
PEST_SECRET_KEY=<python -c "import secrets; print(secrets.token_hex(32))">
# Required — this pair seeds the FIRST ADMIN account at first startup
# (session login; the pair is ignored once accounts exist):
PEST_AUTH_USER=<your username>
PEST_AUTH_PASS=<a strong password>
# Plain-HTTP LAN deployments must disable the Secure cookie flag until a
# TLS proxy fronts the app (keep the default true behind HTTPS):
PEST_COOKIE_SECURE=false
# Expose the web UI on the LAN (default is loopback only):
PEST_WEB_BIND=0.0.0.0
```

`docker-compose.yml` refuses to start without `POSTGRES_PASSWORD` and
`PEST_SECRET_KEY`. Postgres itself is always bound to `127.0.0.1` — never the LAN.

## 2. Start Postgres and create the schema

```bash
docker compose up -d db
# wait until healthy
docker compose ps

# create the schema in the empty Postgres DB
docker compose run --rm scheduler uv run alembic upgrade head
```

## 3. Seed from a SQLite dump (optional)

This package ships **no database** — the schema is created empty (step 2) and
the scheduler backfills it from ransomware.live and the other sources over its
first cycles. That is the default and needs no action.

If you have a SQLite dump to start from (for example one exported from a prior
instance), import it from the host against the loopback-exposed Postgres:

```bash
# uv on the host (one-time): curl -LsSf https://astral.sh/uv/install.sh | sh
uv run python scripts/migrate_sqlite_to_postgres.py \
  --source sqlite:///elementaryctiDB.db \
  --target "postgresql://pestilentia:${POSTGRES_PASSWORD}@127.0.0.1:5432/pestilentia" \
  --wipe
```

The script copies tables in FK order, transfers only columns present in both
schemas, and resets Postgres id sequences. Verify the counts it prints
(victims ≈ 27k, cyberattacks ≈ 3.4k, btc transactions ≈ 5.3k).

## 4. Bring up the full stack

```bash
docker compose up -d
docker compose ps              # web + scheduler + db, all healthy
```

Open `http://<host>:8000/`. Anonymous visitors see the public 30-day
dashboard; sign in from the sidebar with the bootstrap admin credentials
(`PEST_AUTH_USER`/`PEST_AUTH_PASS`) to unlock the full UI. Then create the
accounts you need.
`http://<host>:8000/healthz` is always public and is what Docker probes.

## 5. Operate & observe (multi-day trial)

```bash
docker compose logs -f scheduler      # JSON cycle logs; +N victims / +N attacks
docker compose logs -f web            # request + app logs
docker compose logs --since 24h scheduler | grep '"level":"ERROR"'
```

- **Update cadence:** victims/attacks every `PEST_POLL_INTERVAL_HOURS` (default 4h);
  MITRE / Ransomwhere / deepdarkCTI enrichment weekly (`PEST_*_ENRICHMENT_HOURS`).
- **Source health:** the Pipeline page shows reachable/format status dots per source.
- **Watchlist test:** add a real asset under Watchlist (replace the `CSRFTest`
  rows) to exercise fuzzy matching + alert dispatch end-to-end.
- **Log volume:** cap Docker's json-file driver so logs don't grow unbounded —
  add to `/etc/docker/daemon.json`:
  `{ "log-driver": "json-file", "log-opts": { "max-size": "10m", "max-file": "3" } }`
  then `sudo systemctl restart docker`.

## 6. Backup / teardown

### Running a migration against production — read this first

`alembic upgrade head` on its own **does not touch production**. Alembic reads
`PEST_DB_URL` from `.env`, which points at the tracked development SQLite file,
so the bare command silently migrates the wrong database. This happened on
2026-08-08: the migration reported success, and PostgreSQL stayed on the
previous revision.

The tell is alembic's first line of output: `Context impl **SQLiteImpl**` means
the dev file, `Context impl **PostgresqlImpl**` means production.

```bash
cd ~/github/elementary-CTI
sudo systemctl start elementarycti-backup.service     # always, before DDL

set -a; source .env; set +a                            # keeps the password off the command line
PEST_DB_URL="postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@127.0.0.1:5432/${POSTGRES_DB}" \
  uv run alembic upgrade head

docker exec elementary-cti-db-1 psql -U pestilentia -d pestilentia \
  -t -A -c 'select version_num from alembic_version;'  # confirm before deploying
```

**Migrate before you deploy, never after.** Nothing runs migrations at container
start — the Dockerfile only copies the alembic files, and `create_all` creates
missing tables but does not alter existing ones. Deploying an image whose models
expect columns the database lacks breaks the application.

If you keep a local SQLite file for development, remember it is a *separate*
database from production: a bare `alembic upgrade head` with the default
`PEST_DB_URL` migrates that file, not Postgres. Target the Postgres URL
explicitly when deploying (the tell is alembic's first log line —
`PostgresqlImpl` vs `SQLiteImpl`).

### Automated backup (installed on `invictus` 2026-08-07)

A systemd timer takes a verified Postgres dump every day. Until this was set
up, the only backup on the host was a single manual dump from 2026-06-12 —
nearly two months of accumulated intelligence was unprotected, including
`group_source_history`, which archives *previous* versions of what each source
said about each adversary and therefore cannot be re-fetched.

| | |
|---|---|
| Script | `/usr/local/sbin/elementarycti-backup.sh` |
| Units | `elementarycti-backup.service` + `.timer` (enabled) |
| Schedule | daily 03:30, `Persistent=true`, `RandomizedDelaySec=600` |
| Destination | `~/backups/elementary-cti/{daily,weekly}/` |
| Format | `pg_dump -Fc` (compressed, selective restore) |
| Rotation | 7 daily + 4 weekly (Sunday copy) |
| Log | `/var/log/elementarycti-backup.log` |

Two safety properties worth keeping if the script is ever rewritten:

1. **Every dump is verified with `pg_restore --list` before rotation runs.** A
   dump that cannot be read is discarded and the older backups are left intact —
   a corrupt run can never evict a good backup.
2. **Credentials are never duplicated.** `POSTGRES_USER` / `POSTGRES_DB` are
   expanded *inside* the container, so the script does not read `.env`.

The script exits non-zero (and systemd records a failure) when the database
container is not running, rather than writing an empty file.

```bash
# manual run / status / log
sudo systemctl start elementarycti-backup.service
systemctl list-timers elementarycti-backup.timer
sudo cat /var/log/elementarycti-backup.log
```

### Restore

Verified end-to-end on 2026-08-07 against a throwaway database: 36 tables,
66 indexes, `alembic_version` 0012, and identical row counts on every table
checked (victims 28,718 · cyberattacks 3,799 · group_btc_transactions 5,395 ·
group_source_history 2,979 · group_ttps 1,013 · groups 409).

```bash
# restore into a throwaway DB first — never straight over production
docker exec elementary-cti-db-1 createdb -U pestilentia restore_test
docker exec -i elementary-cti-db-1 pg_restore -U pestilentia -d restore_test --no-owner \
  < ~/backups/elementary-cti/daily/<dump>
# compare counts, then drop it
docker exec elementary-cti-db-1 dropdb -U pestilentia restore_test
```

### Ad-hoc backup / teardown

```bash
# one-off dump (custom format, like the automated one)
docker exec elementary-cti-db-1 sh -c 'pg_dump -U "$POSTGRES_USER" -Fc "$POSTGRES_DB"' > backup_$(date +%F).dump

# stop (keep data) / wipe (drop the volume)
docker compose down
docker compose down -v
```
