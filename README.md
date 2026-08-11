# Elementary CTI

[![CI](https://github.com/SOsintOps/elementary-CTI/actions/workflows/ci.yml/badge.svg)](https://github.com/SOsintOps/elementary-CTI/actions/workflows/ci.yml)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
<img align="left" width="440" height="440" src="multimedia/elementarycti.png">

**Multi-source ransomware threat intelligence aggregator with MITRE ATT&CK, BTC payment, and operational enrichment.**

Elementary CTI collects victim and cyberattack data from ransomware tracking sources, enriches it with MITRE ATT&CK TTPs, Ransomwhere BTC payment intelligence, and deepdarkCTI operational data, then surfaces it through a web UI for analyst investigation. Watchlists fuzzy-match new victims against your asset perimeter and dispatch alerts via log or webhook.

> **Legacy code name:** the project was originally known as **Pestilentia**. The Python package is still `pestilentia/` — only the product brand and the repository have been renamed.

<br clear="left"/>

---

## Features

Grouped by the release that introduced them — see [`CHANGELOG.md`](CHANGELOG.md) for the full history.

### Core platform (v0.6.0 — June 2026, first tagged release)

- **Multi-source ingestion** — ransomware.live as primary source, extensible to additional ransomware feeds
- **MITRE ATT&CK enrichment** — automatic alias matching, TTP import, software-to-technique mapping, country attribution
- **Ransomwhere BTC enrichment** — Bitcoin payment transactions linked to ransomware families
- **deepdarkCTI operational enrichment** — onion URLs, communication channels (Tox, Telegram, email) for tracked gangs
- **Web UI** — dashboard, victims, adversaries, cyberattacks, geographic map, BTC explorer, watchlist, pipeline status, multi-tab guide
- **Watchlist fuzzy matching** — compare new victims against an internal asset list and dispatch alerts
- **Notifications** — log channel and webhook channel (SSRF-guarded; Telegram bot channel planned)
- **REST API** — read-only `/api/v1/*` endpoints for third-party tools
- **Relational storage** — SQLAlchemy 2.0 ORM with SQLite (dev) and PostgreSQL (prod) support, Alembic migrations
- **Scheduled collection** — configurable polling per source with exponential backoff and structured JSON logging
- **Source health monitoring** — automated HTTP and format checks with status dots on the Pipeline page
- **Production deployment** — Docker + PostgreSQL stack with a hardening pass (XSS-safe feed URLs, constant-time auth, loopback-bound database)

### v0.7.0 — June 2026

- **Noir dark mode and design system** — elementary OS palette, theme toggle, font-size controls
- **Multi-source adversary profiles** — ransomware.live description plus the full MITRE ATT&CK profile, with version history and evidence preservation
- **Fully self-hosted front end** — every library and font vendored; no remote request at runtime
- **Accessibility pass** — ARIA tabs with keyboard navigation, visible focus, corrected contrast
- **Schema hardening** — timezone-aware datetimes, unique cyberattack constraint, CASCADE on alerts

### v0.8.0 — August 2026

- **CTI article pipeline** — 12 curated vendor and government feeds polled on the scheduler, canonical-URL and near-duplicate dedup, full-text extraction, read-only article view with source/TLP filters
- **Priority Intelligence Requirements** — the active watchlist doubles as the PIR set; articles matching it are flagged and filterable
- **Campaign grouping** — articles describing the same incident across outlets read as one story
- **ATT&CK coverage matrix** — techniques by tactic in kill-chain order, intensity by how many tracked adversaries use each
- **STIX 2.1 export** — per-adversary bundles (intrusion-set, attack-pattern, tool, `uses`) pushable into MISP or OpenCTI
- **Triaged alerts** — three severity levels plus an "actioned" flag to measure decision impact
- **First time series** — victims per month with range selector and per-adversary sparklines
- **Conditional feed caching** — etag / last-modified handling and a versioned User-Agent

### Since v0.8.0 (0.9.0.dev0 — August 2026)

- **Campaign clustering on local embeddings** — model2vec (256 dim, ~30 MB, no torch, no network at request time), with a recurring-series guard so a publisher's weekly column is not mistaken for a campaign
- **LLM router, live** — provider-agnostic routing behind a fail-closed TLP gate and hard budget ceilings; first real calls run on NVIDIA NIM's free tier, every call logged with cost and token counts
- **TLP handling with an audited override** — content above the configured cloud ceiling never reaches a third-party LLM; an analyst can release it deliberately, and every crossing records who, why, and where it went
- **Weekly API contract sentinel** — fingerprints the shape of every upstream contract against committed baselines and reports drift before it breaks ingestion
- **Multi-user authentication** — server-side accounts with argon2id hashing and three roles (`user` read-only, `analyst` adds the analysis surfaces, `admin` adds management); signed session cookies with rotation, expiry, CSRF protection and sign-in backoff
- **Public TLP:CLEAR storefront** — anonymous visitors get a 30-day overview built only from public-source data, with a sidebar sign-in and a public [FAQ](docs/FAQ.md); everything deeper requires an account
- **Activity audit log** — every authenticated action and every failed access attempt recorded with client address, retained for a configurable window
- **Security response headers** — CSP, frame denial, referrer policy, permissions policy on every response
- **Runtime on Python 3.14** — Docker image and CI aligned
- **Settings page** — self-service password change and theme; admin tabs for user management (with last-admin guard), the activity log viewer, source enable/disable, and write-only service API keys with env-over-DB precedence

### Planned

- **Company enrichment** — DB schema in place for GLEIF, Wikidata, OpenCorporates and country registries; client integrations not yet implemented
- **Telegram notification channel**

## Architecture

```
┌────────────────────┐     ┌──────────────────┐     ┌────────────────────┐
│   Data Sources     │     │  Elementary CTI  │     │   Enrichment       │
│                    │     │                  │     │                    │
│  ransomware.live ──┼────▶│  API Client      │     │  MITRE ATT&CK      │
│                    │     │  Normalizer      │────▶│  Ransomwhere (BTC) │
│  12 curated RSS ───┼────▶│  Article ingest  │     │  deepdarkCTI       │
│  feeds (vendor,    │     │   + dedup        │     │  (operational)     │
│  government)       │     │  DB Store        │     │                    │
│                    │     │  Scheduler       │     │                    │
│                    │     │  Health Monitor  │     │                    │
│                    │     │  Fuzzy Matcher   │     │                    │
└────────────────────┘     └──────────────────┘     └────────────────────┘
                                      │
                                      ▼
                             ┌──────────────────┐
                             │ SQLite / Postgres│
                             └──────────────────┘
                                      │
                    ┌─────────────────┼─────────────────┐
                    ▼                                   ▼
        ┌──────────────────────┐            ┌──────────────────────┐
        │  AI layer (ADR-006)  │            │   Web UI + REST      │
        │                      │            │                      │
        │  Local embeddings ──▶│ campaigns  │  dashboard, victims, │
        │  TLP gate            │            │  adversaries, ATT&CK │
        │  LLM router  ────────┼──▶ cloud   │  matrix, articles,   │
        │  Budget guard        │    or local│  campaigns, STIX     │
        └──────────────────────┘            └──────────────────────┘
```

Embeddings, the TLP gate and the LLM router all run today — the router makes
real calls on NVIDIA NIM's free tier. See [`CHANGELOG.md`](CHANGELOG.md) for release history.

## Documentation

| Document | Description |
|----------|-------------|
| [`docs/FAQ.md`](docs/FAQ.md) | Frequently asked questions (also rendered live at `/faq`) |
| [`DEPLOY.md`](DEPLOY.md) | Single-host Docker + Postgres deployment runbook (incl. SQLite→Postgres migration and the weekly API sentinel) |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Clone-to-green setup, the gates a change must pass, and conventions |
| [`DEPENDENCIES.md`](DEPENDENCIES.md) | Every dependency with version, contract and rationale |
| [`UI-SPEC.md`](UI-SPEC.md) | Design system, palette tokens, dark mode, the no-remote-assets rule |
| [`CHANGELOG.md`](CHANGELOG.md) | Release history (Keep a Changelog) |
| Database schema | `src/pestilentia/models/tables.py` + `alembic/` (source of truth) |
| HTTP API reference | Generated by FastAPI at `/docs` (Swagger) and `/redoc` on any running instance |

## Tech Stack

| Component | Choice |
|-----------|--------|
| Language | Python 3.11+ |
| Web framework | FastAPI + Jinja2 + Tailwind + HTMX (all front-end assets self-hosted, see `UI-SPEC.md`) |
| HTTP client | httpx |
| ORM | SQLAlchemy 2.0 |
| Database | SQLite (dev) / PostgreSQL (prod) |
| Scheduler | APScheduler |
| Fuzzy matching | thefuzz + python-Levenshtein |
| Linter/formatter | Ruff |
| Tests | pytest + pytest-httpx + pytest-anyio |
| Feed parsing | feedparser |
| Full-text extraction | trafilatura |
| Local embeddings | model2vec (static vectors, CPU-only — no torch) |
| Package manager | uv |
| Containerisation | Docker + docker-compose |

The architectural rationale (ADR series) is kept in the working repository.

## Data Sources

### Ransomware tracking

| Source | Status | Type | Notes |
|--------|--------|------|-------|
| [ransomware.live](https://www.ransomware.live/api) | Active | REST API | Primary source — victims, groups, cyberattacks |
| [MITRE ATT&CK](https://attack.mitre.org/) | Active | STIX 2.1 bundle | Enrichment — TTPs, software, aliases, country |
| [Ransomwhere](https://ransomwhe.re/) | Active | JSON feed | Enrichment — Bitcoin payment tracking (29/136 families matched) |
| [deepdarkCTI](https://github.com/fastfire/deepdarkCTI) | Active | Markdown files | Enrichment — onion URLs, comms channels (244/442 gangs matched) |
| [RansomLook](https://www.ransomlook.io/doc/) | Planned (v1.1) | REST API | 566+ groups, posts, actors, crypto |
| ~~[ransomwatch](https://ransomwatch.telemetry.ltd/)~~ | Dropped | ~~JSON feeds~~ | Project archived March 2026, data stale |
| [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/usage/api) | Future (v2.0) | REST API | Enrichment — malware families, YARA rules |

### CTI article feeds (Phase 2)

12 curated sources, all live-probed before being added. Vendor research
(Unit 42, Cisco Talos, Microsoft, SentinelLABS, Check Point, Trend Micro,
Securelist, WeLiveSecurity), incident write-ups (The DFIR Report), news
(BleepingComputer, The Record) and government advisories (CISA). Onion leak
sites and Telegram channels are **deliberately excluded** as article sources —
prompt-injection risk into any downstream LLM step.

### Company enrichment (planned)

DB schema is in place (`Organization`, `OrganizationIdentifier`, `VictimOrganization`, `EnrichmentReview`); no client integrations are wired up yet.

| Source | Coverage | Cost | Priority |
|--------|----------|------|----------|
| [GLEIF](https://www.gleif.org/en/lei-data/gleif-api) | 3.3M worldwide | Free (CC0) | P1 |
| [Wikidata](https://query.wikidata.org/) | Notable companies | Free | P1 |
| [UK Companies House](https://developer.company-information.service.gov.uk/) | 5M UK | Free | P2 |
| [France SIRENE](https://www.data.gouv.fr/datasets/base-sirene-des-entreprises-et-de-leurs-etablissements-siren-siret) | 31M France | Free | P2 |
| [OpenCorporates](https://api.opencorporates.com/) | 210M worldwide | 200 req/month free | P2 |
| [SEC EDGAR](https://www.sec.gov/search-filings/edgar-application-programming-interfaces) | 800K+ US public | Free | P2 |

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md).

## License

[GNU Affero General Public License v3.0](LICENSE)

## Related Projects

- [Exploratores](https://github.com/SOsintOps/Exploratores) — OSINT toolkit with 50+ company registry integrations
- [RansomLook](https://github.com/RansomLook/RansomLook) — Ransomware leak site monitor
- [ransomwatch](https://github.com/joshhighet/ransomwatch) — Ransomware leak site scraper
- [OpenCTI](https://github.com/OpenCTI-Platform/opencti) — Full CTI platform
