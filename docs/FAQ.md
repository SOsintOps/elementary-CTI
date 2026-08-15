# Frequently asked questions

This FAQ answers common questions about Elementary CTI: what it is, how to
get access, where the data comes from, how to run your own instance, and how
to solve common problems. It is rendered live at `/faq` on every deployment.

## About the project

### What is Elementary CTI?

Elementary CTI is a multi-source ransomware threat-intelligence aggregator.
It collects victim and cyberattack data from public ransomware tracking
sources, enriches it with MITRE ATT&CK TTPs, Bitcoin payment intelligence,
and operational data, and presents everything through a web UI built for
analyst investigation.

### Why is it called "Elementary"?

The name honors the TV series *Elementary* and its Sherlock Holmes: a
consultant who turns scattered observations into deductions. The codebase is
full of quotes from the series. The project's original code name was
**Pestilentia**, and the Python package is still named `pestilentia/` — only
the product brand changed.

### Is this a commercial product?

No. Elementary CTI is a personal open-source project, released under the
AGPL-3.0 license. There is no company behind it, no paid tier, and no SLA.

### Who is it for?

Threat-intelligence analysts, SOC teams, researchers, and anyone who wants a
self-hosted, auditable view of ransomware activity without depending on a
commercial platform.

## Access and accounts

### Why do I see only a small dashboard and a sign-in box?

You are not signed in. Anonymous visitors see a public overview limited to
the last 30 days of activity from public sources. Everything else — full
history, adversary profiles, maps, watchlists, the AI pipeline — requires an
account.

### How do I get an account?

Accounts are created by an administrator of the instance you are visiting.
There is no self-registration. Contact the instance operator.

### What are the roles?

| Role | What it unlocks |
|---|---|
| `user` | Read access to the full dataset: dashboard, victims, adversaries, cyberattacks, map, articles, campaigns, search |
| `analyst` | Everything `user` has, plus the analysis surfaces (IP analysis, review queues, AI actions) as they ship |
| `admin` | Everything, plus user management, source toggles, and service API keys in the settings |

### How do I sign in?

1. Find the sign-in box in the left sidebar, or open `/login`.
2. Enter your username and password.
3. Select **Sign in**.

### How long does a session last?

A session ends 12 hours after sign-in, or after 2 hours without activity,
whichever comes first. Sign in again to continue.

### I typed my password wrong several times and now I am locked out. What do I do?

Wait. After five failed attempts, the account-and-address pair is locked,
starting at 30 seconds and doubling up to 15 minutes. The lock clears by
itself. If you forgot the password, ask an administrator to reset it.

### Can I change my password?

Yes:

1. Open **Settings** in the sidebar.
2. In **Change password**, enter your current password and the new one
   (minimum 10 characters), twice.
3. Select **Update password**. You stay signed in.

### Why was I signed out without warning?

Three common causes: your session passed the 12-hour limit, you were
inactive for more than 2 hours, or an administrator disabled your account.
Disabled accounts are signed out at the next request.

## The public dashboard and TLP

### What exactly does the public dashboard show?

Aggregate counters, a daily victim timeline, recent victim names, and the
most active groups — all restricted to the last 30 days and built only from
public tracking sources. There are no links into the full dataset.

### What is TLP and how does this site apply it?

TLP (Traffic Light Protocol) marks how widely information may be shared.
Elementary CTI marks every ingested article with a TLP level. The public
dashboard never queries TLP-marked content at all, so nothing above
TLP:CLEAR can appear there — by construction, not by filter. The same
discipline gates which content may reach a cloud LLM.

### The public page names ransomware victims. Is that responsible?

The names come from public ransomware tracking sources; the victims were
already published by the criminals and indexed by trackers. Elementary CTI
republishes only what is already public, limited to 30 days, without
amplifying details (no claim URLs, no screenshots, no drill-down).

## Data and sources

### Where does the data come from?

Structured data: ransomware.live (victims, groups, attacks), MITRE ATT&CK
(TTPs), Ransomwhere (Bitcoin payments), and deepdarkCTI (operational data:
onion sites, Telegram/Tox channels). Articles: 12 curated RSS feeds from
vendor research labs and news outlets (CISA, The DFIR Report, Unit 42,
Talos, Microsoft, SentinelLABS, BleepingComputer, and others).

### How does the platform know that two adversary names are the same group?

It asks a catalogue rather than deciding for itself. The same adversary is
usually known by several names at once, because each research house names
what it finds under its own scheme: one calls a Chinese group Panda, another
calls it Typhoon, a third gives it a number until it is confident enough to
name it. Reading a name and guessing the rest merges groups that are not the
same, which is the one mistake here that nothing downstream can catch.

So an alias is recorded only where a published catalogue lists it, and the
record keeps which catalogue said so. The catalogues used are the MITRE
ATT&CK intrusion sets, the MISP Project's threat-actor galaxy, and
Microsoft's own published mapping of its actor names to the names other
vendors use. All three are public, versioned, and can be checked by anyone
holding the same file, which is what makes an alias evidence rather than an
opinion. Where no catalogue lists the name, the platform says so and leaves
the question to an analyst instead of inventing an answer.

### How fresh is the data?

The scheduler polls sources every 4 hours. MITRE, Ransomwhere, and
deepdarkCTI enrichments refresh weekly. The dashboard header shows the last
update time.

### A victim entry is wrong or should be removed. Can you fix it?

Elementary CTI mirrors upstream sources; it does not originate claims.
Corrections must happen at the source (for example, ransomware.live). When
the upstream record changes, the next scheduler cycle picks it up.

### What is the source health monitor?

Every cycle checks each source with an HTTP and format probe. Status appears
on the Pipeline page. A separate weekly sentinel fingerprints the *shape* of
every upstream API contract and reports drift before it breaks ingestion.

### Does the site track its visitors?

Anonymous visits to the public pages are not logged. Signed-in activity is
recorded (page, time, address) for security auditing — see the Security
section.

## Using the UI

### What is the difference between "Victims" and "Cyberattacks"?

Victims are organizations claimed on ransomware leak sites. Cyberattacks are
incident records (breach notices, disclosures) tracked separately, with
their own dates and descriptions.

### What do the adversary pages show?

Each group page combines the ransomware.live description, the full MITRE
ATT&CK profile (aliases, TTPs, software), deepdarkCTI operational channels,
BTC transactions, geographic attribution, and a victim history with trends.

### What is the ATT&CK matrix page?

`/attack` shows which MITRE ATT&CK techniques are covered by the groups in
the database, ordered by kill chain. A blank cell means "not observed in our
data", not "not used by anyone".

### How does the watchlist work?

Add the names of organizations you care about (your company, suppliers,
customers). Every new victim is fuzzy-matched against the watchlist; matches
raise alerts with severity levels, visible in the UI and dispatchable via
webhook.

### What are Articles and Campaigns?

Articles is the reading list the AI pipeline ingests: deduplicated entries
from the curated feeds, with TLP marks and priority flags driven by your
watchlist. Campaigns clusters related articles with local embeddings so one
incident covered by five outlets reads as one story.

### Can I export data?

Yes. Each adversary offers a STIX 2.1 bundle export (`/api/v1/groups/{id}/stix`),
ready for MISP or OpenCTI. The REST API serves JSON for everything else.

## The AI pipeline

### What does the AI actually do?

Today: article ingestion, deduplication, campaign clustering, and a routed
LLM triage layer. In development: a full extraction pipeline that turns
articles into structured, source-anchored adversary intelligence with an
analyst review queue.

### Which LLM providers does it use?

A provider-agnostic router decides per call. The current preferred cloud
provider is NVIDIA NIM's free tier (Llama 3.1 8B for triage, Llama 3.3 70B
for analysis); Anthropic Claude models are registered for when a funded key
exists; a local Ollama fallback is planned.

### Can my data leak to a cloud LLM?

Content at or below the configured TLP ceiling (`PEST_AI_TLP_CLOUD_MAX`,
default `green`) may reach a cloud provider. Anything above stays local or
waits for a human. Every LLM call is logged with cost and token counts.

### What stops the AI from spending money?

Three hard ceilings: per-article token cap, daily budget, monthly budget. At
80% of the daily budget the router downgrades to the cheap tier; at 100% it
refuses. All limits are configuration, not habits.

### Can the AI hallucinate an indicator into the database?

The extraction design (in development) requires every indicator to be
verbatim-anchored in the source article and every claim to be labeled as
observed or inferred; unverifiable output is rejected or staged for human
review, never silently merged.

## REST API

### Is there an API?

Yes: read-only JSON endpoints under `/api/v1/` (stats, victims, groups,
cyberattacks, map data, timeline, STIX export). Interactive documentation is
at `/docs` after you sign in.

### How do I authenticate API calls?

The API uses the same session cookie as the UI. Sign in through `/login`,
then send the `pest_session` cookie with each request. Unauthenticated calls
receive `401`. Token-based API access is on the roadmap.

### Is there a rate limit?

Not per-endpoint today. Sign-in attempts are rate-limited. Be reasonable:
this is typically a Raspberry Pi, not a CDN.

## Self-hosting

### What do I need to run my own instance?

- Docker and Docker Compose.
- 2 GB of RAM and a few GB of disk. A Raspberry Pi 5 runs the reference
  instance.
- Optional: a PostgreSQL database (the default is SQLite for development).

### How do I install it?

1. Clone the repository.
2. Copy `.env.example` to `.env`.
3. Set `PEST_SECRET_KEY` to a random value. Generate one with
   `python -c "import secrets; print(secrets.token_hex(32))"`.
4. Set `PEST_AUTH_USER` and `PEST_AUTH_PASS`. These seed the first admin
   account.
5. Run `docker compose up -d --build`.
6. Open `http://localhost:8000` and sign in.

### How is the first admin account created?

At first startup, if the `users` table is empty and `PEST_AUTH_USER` and
`PEST_AUTH_PASS` are set, the application creates that account with the
`admin` role. After that, manage accounts in **Settings → Users** (create,
disable, delete, change role, reset password — the last active admin is
protected from lockout-by-accident). The variables are not read again once
users exist.

### How do I apply database migrations?

Run `alembic upgrade head` with `PEST_DB_URL` pointing at your database.
Migrations are additive and support downgrade. Always back up first.

### How do I back up the database?

For PostgreSQL: `pg_dump` on a schedule. The reference deployment pushes a
daily dump to a private off-site git branch via a systemd timer. For SQLite:
copy the database file while the app is stopped.

### Which environment variables matter most?

| Variable | Purpose |
|---|---|
| `PEST_DB_URL` | Database connection string |
| `PEST_SECRET_KEY` | Signs sessions and CSRF tokens. Required in production |
| `PEST_AUTH_USER` / `PEST_AUTH_PASS` | Bootstrap seed for the first admin |
| `PEST_COOKIE_SECURE` | `true` behind TLS (default); `false` only for plain-HTTP LAN use |
| `PEST_ACTIVITY_RETENTION_DAYS` | How long user-activity log rows are kept (default 90) |
| `PEST_POLL_INTERVAL_HOURS` | Scheduler cycle (default 4) |
| `PEST_AI_TLP_CLOUD_MAX` | Highest TLP level allowed to reach a cloud LLM |
| `PEST_AI_DAILY_BUDGET_USD` / `PEST_AI_MONTHLY_BUDGET_USD` | Hard LLM spend ceilings |
| `PEST_AI_NVIDIA_API_KEY` | NVIDIA NIM key for the AI pipeline |

`.env.example` documents the full list.

### Can I expose my instance to the internet?

Only behind a TLS reverse proxy, and only after you review the security
checklist. The reference deployment uses Caddy for TLS termination and keeps
the app port unpublished. Set `PEST_COOKIE_SECURE=true` (the default) behind
TLS. An OWASP Top 10 audit gates the reference deployment's own exposure.

### Can I disable a data source?

Yes, as an administrator: **Settings → Sources** lists primary sources,
enrichments, and article feeds, each with an enable/disable control. A
disabled source is skipped from the scheduler's next cycle. Every change is
recorded in the admin audit log.

## Security

### How is authentication implemented?

Server-side accounts with argon2id password hashing, signed session cookies
(HttpOnly, SameSite=Lax, Secure behind TLS) with a 12-hour absolute and
2-hour idle expiry, session rotation at every sign-in, CSRF tokens on every
form, and exponential backoff on sign-in attempts.

### What is recorded in the activity log?

Every authenticated request (who, what page, when, from which address),
every failed sign-in with the attempted username, every lockout, and every
denied request. Anonymous browsing of the public pages is not recorded.
Rows are purged after a configurable retention period (default 90 days).

### Who can read the activity log?

Administrators, in **Settings → Activity**: filters by event type, username
and time window, with counters for failed sign-ins, lockouts and denied
requests. Log rows never contain passwords or session tokens.

### How do I report a security vulnerability?

Use GitHub's private vulnerability reporting on the repository (Security →
Report a vulnerability). Do not open a public issue. See `SECURITY.md`.

### Is my password stored safely?

Passwords are hashed with argon2id (the current OWASP recommendation) and
never logged, displayed, or sent anywhere. Nobody, including the
administrator, can read your password.

## Troubleshooting

### I cannot sign in.

1. Check the username. It is lowercase.
2. Check the password. The error message is the same for a wrong username
   and a wrong password.
3. Wait 15 minutes if you tried many times. The lockout clears by itself.
4. Ask an administrator to check that your account exists and is enabled.

### The sign-in succeeds but I am immediately signed out.

Your browser rejected the session cookie. If the instance runs on plain
HTTP (no TLS), the operator must set `PEST_COOKIE_SECURE=false`. Behind
HTTPS, check that your browser accepts cookies for the site.

### The administrator is locked out and no other admin exists.

1. Stop the application.
2. Delete all rows from the `users` table.
3. Verify `PEST_AUTH_USER` and `PEST_AUTH_PASS` in `.env`.
4. Start the application. The bootstrap creates the admin account again.

Warning: this removes every account. Use it only for recovery.

### The maps are blank.

Check the browser console. If a Plotly file fails to load, the deployment is
missing vendored static assets — rebuild the image. All assets are served
locally; the app never fetches from a CDN, so an ad-blocker is not the
cause.

### The FAQ or Changelog page is empty.

The deployment image was built without the markdown files. Rebuild the
image; the Dockerfile must copy `CHANGELOG.md` and `docs/FAQ.md`.

### `docker compose up` fails with a secret-key error.

Set `PEST_SECRET_KEY` in `.env` to a value other than the placeholder.
Generate one with `python -c "import secrets; print(secrets.token_hex(32))"`.

### A migration fails on upgrade.

1. Read the error. Most failures name the table and revision.
2. Restore the database backup.
3. Open an issue with the error text and your revision (`alembic current`).

### The scheduler is not ingesting.

1. Open the Pipeline page and check the source health dots.
2. Check the scheduler container logs:
   `docker logs <project>-scheduler-1 --since 1h`.
3. A failing source retries on the next cycle. Two consecutive format
   failures usually mean the upstream API changed shape — check the contract
   sentinel report.

## Project and license

### What license does Elementary CTI use?

AGPL-3.0-or-later. If you run a modified version as a network service, you
must offer the modified source to its users.

### Can I contribute?

Yes. Open an issue or a pull request on GitHub. The repository ships issue
templates, a PR template with the quality gates, and contribution
guidelines.

### Where is the roadmap?

High level: `README.md` and the `/guide` page. In detail: `docs/adr/` for
architectural decisions and `.planning/` for the working plans (private
working repo).

### Was any Large Language Model unduly stressed during development?

Several, extensively, and they would do it again — although one of them
maintains that the correct spelling is "Watson".
