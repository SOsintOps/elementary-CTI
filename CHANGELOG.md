# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- **The list used to rule out rented infrastructure had been dead for two and a half years, and nothing could have noticed.** The exit-node feed the exclusion check ran on was last updated upstream in March 2024 — Microsoft froze all three of its VPN feeds without announcing it — while our register asserted a daily cadence on the strength of the upstream folder being named "Daily". The file we held matched upstream byte for byte, so nothing was broken locally and every check reported green: a stale file and a stable one are the same bytes, and the gate's refusal to enrich without exclusion data was being satisfied by a corpse. Live coverage now comes from ASN ownership instead of one vendor's server list — the address space announced by the hosting and VPN-infrastructure networks named in the register, rebuilt daily from a public-domain source, which keeps answering correctly when a provider replaces its fleet. Measured on the day of the change: 15,275 ranges covering 305 million addresses, against roughly twelve thousand single addresses in the dead list. The Tor Project's own exit-address list joins as a separate kind, because leaving through Tor and renting a server say different things about an operator and folding them together would be irreversible in the data. Every source in the register now records the **licence** someone actually read, a field added at the cost of a candidate source: a vendor's own live API was rejected for granting nobody the right to reuse it, and for answering the request for its terms with a 403. A feed that has stopped moving now says so in a field rather than in nobody's memory
- **The off-device database backup was failing every night and telling nobody.** Three days of dumps existed only on the machine's own SD card while every place an operator would look said the system was fine: the timer reported it had run, `systemctl --user --failed` was clean, and the script's own loud complaint went to a journal this host does not keep — then the next reboot erased the unit's failed state as well. The authentication is now an SSH key rather than a token in a keyring that a reboot locks and an expiry silently invalidates, and the outcome of every attempt is written to two places that survive a restart: a log file beside the local backup's, and a row on the platform's own pipeline page. The application no longer waits to be told, either: on every cycle it reads how old the last successful off-device copy is and says `degraded` after two days and `down` after four, which is the only check that catches a backup that has stopped running altogether and therefore reports nothing at all. A backup that fails loudly is a problem; one that fails quietly is counted as done, and that is the failure this closes

### Added
- **The analysis pipeline can now actually run in a container.** Two things it needs were reaching the host and stopping there: the reference data (the ATT&CK bundle and the four curated feeds, fetched into `./data` and excluded from the image on purpose) and the provider key. `web` and `scheduler` now mount `./data` read-only and receive `PEST_AI_NVIDIA_API_KEY`, so a deployment that has done the DEPLOY.md §0 downloads gets a pipeline that analyses instead of one that reports itself idle. Read-only because a catalogue that changes under a run in progress makes two articles an hour apart disagree for a reason that has nothing to do with the articles; a bind rather than a copy because 54 MB does not belong in a layer rebuilt every time a publisher edits a file the code only reads
- **The article pipeline now reads the articles.** Every ingested piece of reporting goes through eight steps — is this worth analysing, what kind of document is it, which indicators does it contain, which ATT&CK techniques does it evidence, the Diamond Model, the assessment, the actor sketch, and an audit of all of it by a model from a different family than the one that wrote it — with one row per step, so a crash halfway through keeps what was already paid for and the next cycle picks up exactly where it stopped. Each step's cost is recorded per article and per state. **Nothing is stored that the article does not say:** an indicator the model returns is kept only if a pattern also found it in the text, a technique only if the ATT&CK catalogue recognises it *and* a quote from the body can be located verbatim, and what gets persisted is the character offset of that quote — so a finding can always be shown as the sentence it came from rather than asked to be believed. A triage step on the cheap tier drops the irrelevant articles before any analysis is paid for, restricted content still never leaves the building unless an analyst deliberately releases it, and a model that keeps failing its schema ends up staged for a person instead of retried forever. The pipeline page counts it all: analysed, pending, dropped at triage, staged, blocked, plus the indicators and techniques extracted and the month's spend. Proven end to end on a real CISA ransomware advisory: twenty-nine indicators whose stored offsets each cut their defanged form out of the article verbatim, six invented ones refused, ten techniques with anchored evidence, seven claims audited by a second pass — and the Diamond Model's adversary vertex left empty, because the article's evidence reached the infrastructure and not the operator. The audit step is deliberately served by a different model family, and when no such model is configured it declines to run rather than letting the writer mark its own work — an audit by the author produces labels and a quality rating and looks exactly like an audit, which is worse than not having one
- **The interface is now fully multilingual by architecture.** Language catalogs are per-locale JSON files (adding a language is adding one file), the sidebar switcher lists whatever locales exist, and Markdown documents resolve per language (`docs/FAQ.<lang>.md` with English fallback — the Italian FAQ ships complete). Every surface follows the chosen language end to end: intros, titles, sidebar, dashboards, list tables and filters, detail pages, the settings area, error messages, and the full user guide
- **The interface speaks English by default, Italian one click away.** An EN|IT switch in the sidebar (available to anonymous visitors too) changes every page introduction and notice; data content stays in its source language. If a sign-in succeeds but the browser refuses the session cookie, the landing page now says so explicitly — in either language — instead of silently returning the public view; the compose file also learned to pass `PEST_COOKIE_SECURE` through to the container, which was the root cause of exactly that silent failure
- **A complete settings page.** Every signed-in user can change their password and pick a default theme; administrators additionally manage accounts (create, disable, delete, change role, reset password — with a guard that keeps the last active admin alive), read the activity log with failed-attempt counters, enable or disable every data source (primary, enrichment, article feed) from one place, and store API keys for external services. Keys are write-only: the page shows whether a key exists and who set it, never its value, and a host environment variable always wins over a stored key. Every administrative change lands in the audit log. The JSON toggle endpoints that predate the settings page now require the admin role, and the manual refresh endpoint requires analyst
- **A public storefront.** Anonymous visitors now land on a TLP:CLEAR overview of the last 30 days — victim and group counters, a daily timeline, recent victim names, most active groups — built exclusively from public tracking sources; the page never queries TLP-marked content, so nothing restricted can appear on it. The left sidebar carries a sign-in box; signing in unlocks the full platform on the same landing page. A public `/faq` page (rendered from `docs/FAQ.md`, ~50 questions) explains what the site is, how accounts and roles work, where the data comes from, how to self-host, and how to troubleshoot common problems
- **Session login replaces HTTP Basic Auth** (v0.7 track). Real accounts land in the database (argon2id password hashes, fixed `user` < `analyst` < `admin` role hierarchy) with a `/login` page issuing signed, rotating session cookies (12-hour absolute and 2-hour idle expiry) and a `/logout`. The first admin is seeded from the existing `PEST_AUTH_USER`/`PEST_AUTH_PASS` pair on an empty users table, so a fresh deployment is never locked out and never open. Every route outside `/healthz` and `/login` now requires a signed-in user — anonymous page requests bounce to the login page, anonymous API requests get a clean 401, and the interactive API docs are no longer public. A `require_role` gate stands ready for the analyst- and admin-only surfaces coming next
- **The AI pipeline made its first real LLM call.** NVIDIA NIM (free tier) is now the preferred cloud provider — adopted when it emerged that the Max subscription carries no Console API credit — with `meta/llama-3.1-8b-instruct` on triage and `meta/llama-3.3-70b-instruct` on analysis, both behind the existing TLP and budget gates. The first caller (`ai/router/nvidia.py`) is plain httpx against the OpenAI-compatible endpoint, keeping the no-vendor-SDK property; its errors name their fix (the 403 family opt-in, the ~40 RPM shared limit). Phase 3 was live-accepted against production Postgres: real triage call, `llm_call_logs` cost rows verified with real token counts at $0, and the prefix cache observed serving 848 of 849 prompt tokens on an identical repeat call
- **Weekly API contract sentinel.** The in-app health monitor answers "is the source up?"; the sentinel answers what it cannot: *has the shape of the data changed?* A systemd user timer fingerprints the type structure of all 19 upstream contracts against committed baselines (`contracts/`); on drift, a headless Claude session produces an impact analysis — what changed, which code consumes it with file:line, the minimum indispensable fix — as a report, never as applied changes. Nullable fields and empty windows are contract, not drift; a 429 gets a respectful retry and its own status rather than masquerading as an outage. In the live drill the analyst named the silent failure mode (`tx.get("amountUSD", 0) or 0` under-counting USD totals with no error) and even recognised the drill itself, recommending a baseline restore instead of a code change

### Security
- **The platform passed a full OWASP Top 10 audit — the gate that stood between it and the internet.** Every item was verified by hand with concrete evidence, and the four findings it surfaced are fixed and covered by regression tests: the read-only `user` role could still add and delete watchlist targets, mark alerts handled and trigger health checks (it now cannot — those are analyst actions); the language switch accepted one off-site redirect form it should have refused; and the article full-text fetch would follow a feed-supplied link anywhere, including the deployment's own internal network, where the retrieved content landed in the article store and leaked out through the watchlist-term tooltips. That last one took three attempts to close properly — a guard on the URL, then re-checking every redirect hop, then verifying the address actually connected to, because a hostile DNS server can answer one way for the check and another for the connection. The report (`docs/security/AUDIT-2026-08.md`) records the evidence per item, a threat model for the exposed deployment, and four residual risks accepted with reasons rather than left unsaid
- **The platform now serves HTTPS only, through a Caddy reverse proxy.** The app container no longer publishes any host port: the sole way in is the `caddy` service on 80/443 (80 permanently redirects), which terminates TLS and adds a one-year HSTS header. Certificates are automatic at every stage — Caddy's internal CA today (LAN names and raw IPs included, with a `default_sni` answer for clients that dial the IP), Let's Encrypt at go-live by changing two `.env` variables and nothing else. The activity log now records the real visitor address instead of the docker bridge: `X-Forwarded-For` is honoured only when the request comes from the pinned compose subnet (`172.28.0.0/16`), and only its rightmost, proxy-appended entry counts, so a forged header from anywhere else is ignored. Internet exposure itself remains gated on the OWASP Top 10 audit
- **Every user action and every failed access attempt is now recorded** in a dedicated `user_activity` table (OWASP A09 groundwork for the planned internet exposure): authenticated page views and API calls, failed logins with the attempted username and client IP, lockouts, and authorisation denials. Login attempts back off exponentially per username+IP (five free attempts, then 30-second to 15-minute locks). Rows older than `PEST_ACTIVITY_RETENTION_DAYS` (default 90) are purged on the scheduler cycle, and audit rows snapshot the actor's name so they survive account deletion
- **Upgraded past two dependency advisories**: Pillow 12.2.0 → 12.3.0 (thirteen PYSEC advisories) and starlette 1.3.0 → 1.5.1 (PYSEC-2026-249 — the HTTP layer beneath FastAPI). `pip-audit` on the refreshed environment reports no known vulnerabilities
- **Security response headers on every response** — `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, a `Permissions-Policy` disabling geolocation/microphone/camera/FLoC, and a Content-Security-Policy. The CSP is honest about the Tailwind Play runtime's in-browser `eval`/inline needs (removing them is gated on the build-step debt in UI-SPEC §9) while locking down `frame-ancestors`, `object-src`, `base-uri` and `form-action`. The `Server` banner no longer leaks the server name or version

### Changed
- **Runtime moved to Python 3.14** (Docker base `python:3.11-slim` → `python:3.14-slim`) and CI now tests on 3.14 — the version the image actually ships. Verified three ways before the switch: full suite on a 3.14 host venv, full suite inside the built 3.14 image, and a control run proving the only in-image failures also occur on 3.11 (tests that read repo files the image never carries)
- **First Dependabot wave drained (10 PRs)**: apscheduler 3.11.3, markdown 3.10.3, ruff 0.16.1, trafilatura 2.2.0, uvicorn 0.52.1 (floor raised from `>=0.30`), plus the four CI actions (checkout, setup-python, setup-uv, upload-artifact) to their current majors
- The campaigns view shares one embedding model across requests instead of reloading the ~30 MB model on every render; the gain lands on new (cache-miss) articles

### Added
- **The platform now asks a catalogue whether two adversary names are one group, instead of deciding for itself.** The same adversary usually carries several names at once, because each research house names what it finds under its own scheme, and reading a name and inferring the rest merges groups that are not the same — the one mistake here that nothing downstream can catch. Three published catalogues are consulted: the MITRE ATT&CK intrusion sets, the MISP Project's threat-actor galaxy (1041 actors under 2393 names), and Microsoft's own mapping of its actor names to those other vendors use. All three are public, versioned, and recheckable by anyone holding the same file, which is what makes an alias evidence rather than an opinion, and every answer records which catalogue gave it. A name no catalogue knows is reported as unknown rather than approximated to the nearest match. The same lookup also tells apart the things a report calls an adversary that are not one: malware named after the intrusion it was found in, and the numbered designations a vendor assigns to activity it has deliberately not named yet

### Fixed
- **Analyses already stored were held to the new evidence check too, and 31 unsupported claims were removed.** The check protects what the pipeline writes from now on, and every Diamond Model row already in the database predated it. Because the decision is settled by the article and the quote rather than by the model, the stored rows could be put through the same rule at no cost and without a single call: 233 vertices examined, 31 dropped for a quote that is not in the article, 202 kept and none of those unsupported. The verdict written onto a corrected row is marked as added afterwards, so a reader can tell it from a check made at the time

- **Every quote the analysis offers as evidence is now checked against the article, in every step that offers one.** Two steps asked the model for a supporting sentence and never looked for it: the Diamond Model, whose whole risk is that a plausible sentence about the adversary gets derived from what was seen about the infrastructure, and the document classifier. Measured on the stored corpus before the fix: of 203 Diamond vertices asserted with a quote, 35 carried a sentence that could not be found in the article, and all 35 were stored and displayed exactly like the supported ones. A vertex whose quote cannot be located is now left empty, which is what the analysis is asked to return when the evidence is not there; the classification survives an unfindable quote, because the document type drives every later step and the failure is rare, but it loses a level of confidence and the failure is written into the record the gate reads. **The check itself was corrected first**: six of those 35 were correct quotations refused over a quotation mark the article typed differently, an explicit ellipsis, or a bullet the model left out. A quoting convention that does not change the meaning no longer counts as a fabrication, while two true fragments taken from opposite ends of an article and joined into one sentence still do

- **Two adversary names in one article are no longer assumed to be the same adversary.** The pipeline handed the model's list of named actors downstream as bare strings, which left the relationship between them to be inferred, and the inference was that every name was an alias of every other — so an article mentioning a state intelligence service, a military intelligence organisation and a hacktivist front proposed all three as one group under three names. The model is now asked the question instead: for every name it reports whether it matches an adversary the database already holds (those names are supplied to it as data), how the name relates to the others in the article, and **the sentence from the article that establishes the relation**. That sentence is checked against the body exactly as an indicator or a technique's evidence is, so a relation nobody wrote down is reduced rather than believed. An alias is proposed only where the model states the two names are one actor, the related name resolves to a group already held, and the quote anchored — affiliate, operator, broker and rebrand are now recorded as what they are instead of being flattened into a merge. Analyses stored before the change still read correctly

- **The weekly API sentinel had been crying wolf, and the fix was in the sentinel rather than the baseline.** It went red on 9 August because ransomware.live now returns a victim's `infostealer` field as a detailed object — and the report explaining that nothing in the codebase reads the field sat unread for three days, which is precisely the fatigue the check exists to prevent. Re-recording what the API returns today would have gone green and red again within weeks: the upstream sends that object for the victims it has data on and an empty value for the rest, mixed together in one response, so the contract was effectively being decided by whichever victim happened to come first. The check now reads the whole response instead of its first record, and understands that some things cannot be pinned down: a field left empty, a field the upstream genuinely sends two different ways, and names that are data rather than structure (the per-infostealer-family counts, or a group's tool categories — a new family appearing is news, not a broken contract). It also stopped treating a whole-dollar amount as a different kind of number from a fractional one, which had been about to blind the very field an earlier drill identified as the one that fails silently. The result covers more of the data than before, not less — 93% of the structure is under contract, and every exception is recorded with its reason
- **Geographic maps render again.** Plotly fetched its world-boundary topojson from `cdn.plot.ly` at render time; the Content-Security-Policy shipped with the security headers rightly blocked that, and every choropleth (world map, dashboard, group pages) went blank with only a console error as a symptom. The boundary file is now vendored under `static/vendor/plotly-topojson/` and the shared Plotly config points there — the CSP stays intact, and the last runtime CDN dependency is gone. A regression test pins both halves plus a tripwire for any future geo scope whose boundary file is not vendored
- The Docker image no longer duplicates the whole `/app` tree in a trailing `chown` layer — **1.2 GB → 805 MB**. It also builds from a fresh clone (the lockfile is tracked and the embedding model is fetched during the build rather than copied from a context that might not have it)


### Added
- **An analyst can now send TLP:AMBER and TLP:RED content to a cloud provider anyway, and every crossing is recorded.** The boundary stays closed by default; the override is per-decision rather than a setting, because a setting relaxes the ceiling for everything from then on and leaves no record of who chose it or why. An override cannot be constructed without naming both the person authorising it and their reason — an audit row that says a boundary was crossed but not why looks like accountability without providing any. Each crossing writes an `ai_enrichment_audit` row carrying the actor, the justification, the article's TLP at the time, the source's share flag, and **which provider and model actually received the content** — "it left the building" is not the question a reviewer asks
- **Overriding an article's TLP does not override a source's own never-share flag.** These are two different promises: the TLP marking is our handling rule for the content, while `share_with_third_party=False` is the publisher's instruction about its own material. Crossing the second needs a separate, explicit acknowledgement, and the refusal that asks for it (`source_ban`) says exactly how to proceed rather than looking like a dead end
- An override attached to content that was within the ceiling anyway, or routed to a local model, is **not** recorded as a crossing. Auditing boundaries that were never crossed would bury the real ones

### Fixed
- **A privacy refusal now outranks a budget refusal.** Both gates can decline the same task, and the reason that gets persisted is what an operator or a retry job acts on. The router checked the spend ceiling first, so an AMBER article arriving while the budget happened to be spent was recorded as `budget_exhausted` — and the fix for that is to raise a cap, after which someone retries a document that was never a spending question. The test named for this property only exercised the case where the budget was fine, so it asserted something true and vacuous; it is now parametrised across both flags, with a companion test pinning that a genuine budget refusal still surfaces when TLP permits

### Changed
- **Campaign clustering now runs on local embeddings, and recurring editorial series no longer collapse into one campaign.** The 0.8.0 release shipped TF-IDF explicitly as a placeholder — "a baseline to measure any future model against" — and this is that measurement, taken on the live 338-article corpus rather than on fixtures. Counting clusters turned out to hide the answer, because the feature exists to join *different outlets covering one incident*: split by source, TF-IDF produced 8 multi-article clusters of which exactly **one** was cross-source, against **five** for embeddings, three of them genuine on inspection. ChainDrop covered by Unit 42 and Microsoft, and the Levi Strauss breach by BleepingComputer and The Record, are precisely the same-incident-different-wording case a lexical vectoriser cannot reach. Encoding the whole corpus takes 0.25 s against 13.37 s for the TF-IDF pass, on a 29.5 MB static model with no torch and no network at request time
- **A negative result changed the design.** Embeddings did not fix the known template problem, they made it worse: a semantic model recognises a shared register more confidently, merging nine editions of Check Point's weekly bulletin where TF-IDF merged two. So the fix is a publication-cadence signal, not a better vectoriser — three or more same-source headlines that reduce to one template are treated as a series and never joined. On the live corpus this removes three noise clusters from each backend while touching no cross-source cluster. It deliberately needs **three** instalments: the DFIR Report's flash alert about its own Akira write-up is same-source with a near-identical title and is a *genuine* grouping, so a blanket same-source rule would have silently broken a case that already worked. A test pins it
- The campaigns page states which vectoriser produced the view, since the two disagree and a reader comparing against yesterday should know which they are looking at. `PEST_AI_CLUSTER_BACKEND` selects `auto` (default — prefers embeddings, falls back when the model was never fetched), `embedding`, or `tfidf`. An explicit choice never falls back silently: an operator who pinned a backend should see a broken deploy rather than a quiet downgrade

## [0.8.0] - 2026-08-08

The release that made the article pipeline real. Phase 2 of ADR-006 shipped in
June but had no production caller — the fetcher existed, nothing invoked it,
and the running image predated the code entirely, so `articles` sat at zero for
two months. This release wires the ingest cycle into the scheduler, takes the
curated source list from 8 feeds to 12, and puts the corpus behind a read-only
page. On top of that: the application's first time-series after fifteen
templates of a single chart type, an ATT&CK coverage matrix, Priority
Intelligence Requirements derived from the watchlist, a decision-impact flag on
alerts, and STIX 2.1 export for adversary profiles. Schema moves to migration
0013 (conditional-GET validators and `alerts.actioned_at`).

Phases 3-7 of ADR-006 — LLM router, extraction pipeline, confidence gate,
review UI, source discovery — remain unbuilt, and the `ai/` package below
`sources/` is still a skeleton. The v0.9 line takes them on.

### Fixed
- **The Changelog tab of the Guide was blank in production.** The page renders `CHANGELOG.md` at request time, but **two** independent gates kept that file out of the image: the Dockerfile never copied it, and `.dockerignore` excludes every `*.md`. So `exists()` was false on every deployment and the route answered with an empty string — a panel that read as a product with no history rather than a deployment missing a file. Both gates are now open (the copy lands after the dependency sync, so editing the changelog does not invalidate that layer), a missing or unreadable file produces an explicit note instead of silence, and a test pins both halves — fixing either one alone still ships a blank panel
- **The Changelog panel shipped light-mode only.** Its styles are plain CSS, because markdown output cannot carry Tailwind `dark:` classes — headings at `#1f2937` and code chips on `#f3f4f6` would have sat on the `#1a2433` noir card the moment content appeared. Headings, bold text, code, links, rules and blockquotes all gained `.dark` counterparts on palette tokens, verified by rendering the real changelog on both surfaces
- **Pyramid of Pain used the wrong kind of colour encoding.** Pain is an ordered scale, but the six layers were painted with six different elementary families — a categorical rainbow on ordinal data. Measured, it failed colour-vision-deficiency separation: adjacent bands sat at deutan ΔE 0.5 on the dark surface, meaning they were the same colour for roughly 8% of men. Replaced with a single-hue Blueberry ramp, verified monotonic in relative luminance in both themes (dark→light on white, inverted on the noir card)
- **The Pyramid had no dark-mode variants.** Its inactive bands were `#f3f4f6` — near-white — sitting on a `#1a2433` card. Fills, separators, silhouette and labels now all carry `dark:` variants
- Pyramid labels no longer take the band colour: text wears text tokens, the band carries identity

### Changed
- **Watchlist alerts are triaged into three tiers instead of one flat list** — unread ("needs attention", prominent), reviewed in the last 7 days (expanded), and older (collapsed and muted). A flat list makes everything look equally urgent, which is the documented route to alert fatigue. Within the unread tier, alerts are ordered by match strength: an exact **domain** match is documentary evidence, a **name** match is weaker, a fuzzy **keyword** match may be coincidence. Each match type carries a glyph and a word, never colour alone. Severity is **derived** from what the row already records — `Alert` has no severity column, and adding one would need a migration without making the answer any truer
- HTTP client User-Agent now carries a version and a contact URL (`elementary-cti/0.8.0.dev0 (+https://github.com/SOsintOps/elementary-CTI)`) instead of a bare token — the polite convention for a client polling a dozen vendor feeds on a schedule, and it gives an upstream operator someone to contact
- The four Pyramid levels that the pipeline cannot populate yet (network/host artifacts, domains, IPs, hashes — they need IOC extraction, Phase 4) now read **"Not collected yet"** with an explanatory tooltip, distinct from **"None found"**. "Not collected" and "searched and empty" are different claims and the UI should not blur them
- Group pages show a "Data as of" freshness timestamp, matching the dashboard

### Added
- **STIX 2.1 export per adversary** (`GET /api/v1/groups/{id}/stix`, linked from the TTP tab) — intrusion-set, attack-pattern, tool and the `uses` relationships between them, TLP-marked. Pushable into MISP or OpenCTI today. The plan filed this behind Phase 4 because *indicators* need extraction that does not exist yet, but a group with its techniques and tooling is already a complete, valid STIX story. Object ids are deterministic UUIDv5, so re-exporting updates the consumer's objects instead of accumulating duplicates. No new dependency: emitting a bundle is JSON assembly
- **Priority Intelligence Requirements** — the active watchlist now doubles as the PIR set, and the articles page gains a "Priority only" filter plus a star badge on every article that mentions something you are watching. PIRs are the direct answer to "more data is not better data": without a statement of what the analyst cares about, a feed pipeline accumulates noise by definition. Derived from the watchlist rather than stored in a new table — the watchlist already *is* that statement, and duplicating it would need a migration without saying anything new. Matching reads title and body but never the URL, where a vendor's own domain would match a watchlisted company by chance
- **Campaign clustering (`/ai/campaigns`)** — groups articles that describe the *same incident*, which is a different question from dedup: simhash asks "is this the same article?", this asks "are these different reports about the same event?". Validated on the live 330-article corpus, where it correctly joined the Akira/Bumblebee report with its flash alert, the ChainDrop npm worm as covered by two vendors, and the Levi Strauss breach as reported by two outlets. **Computed on demand, nothing persisted** — `articles` has no campaign column and adding one needs an approved migration. TF-IDF and cosine similarity rather than a local embedding model: no new dependency on the Pi, and a baseline to measure any future model against. **Known limitation, stated on the page itself**: lexical similarity also groups recurring editorial series and reports that share a template while describing different incidents
- **Time-range selector on the dashboard timeline** (3m / 12m / 24m / 5y). It re-queries the server rather than slicing the loaded data in the browser, so a wider window genuinely reaches further back; the label always states the active window, and a failed update leaves the previous chart in place instead of blanking it
- **Four more curated feeds** — WeLiveSecurity (ESET), Trend Micro Research, Check Point Research and Securelist (Kaspersky GReAT), taking the seed list from 8 to 12. Every URL was probed live before being added; Sophos and Mandiant/Google were on the shortlist but are **not** included, because Sophos redirects to a 404 and Google serves HTML rather than a feed
- **ATT&CK coverage matrix (`/attack`)** — tactics as columns in MITRE's kill-chain order (alphabetical would scramble the narrative an analyst reads left to right), techniques as cells, colour intensity showing how many distinct adversaries use each technique. Magnitude on a grid, so the colour job is sequential: one hue, more-is-darker on light and more-is-brighter on dark. Scopable to a single adversary from its TTP tab, and every cell links to attack.mitre.org. The page states plainly that a missing technique means "not observed in our data", not "not used"
- **Per-adversary activity sparkline** on both the adversary list and each group profile — 12 months of victim counts, answering "is this group alive or dormant?" at a glance, which is the first question anyone asks of a profile. Rendered as inline SVG rather than a chart library: the list draws every group at once (400+ cards), so a charting instance per card was not an option. Dormant groups get a flat line rather than a missing one — the flat line *is* the signal
- **Articles page (`/ai/articles`)** — the read-only view of the ingested corpus, with search, source and TLP filters, pagination, and an explicit "Summary only" vs "Full text" state per row. This was Phase 2's fourth success criterion and had never been started: no route in the application contained the word `article`. Article URLs come from adversary-controlled feeds, so they pass through the same `safe_url` gate as leak-site links — a regression test asserts a `javascript:` URL never reaches an `href`
- **Pipeline page gained an Articles card** with real counters (articles ingested, how many have full text, enabled feeds) and its own enable/disable toggle, alongside MITRE, Ransomwhere and deepdarkCTI. A state word on its own said nothing useful when the count was zero
- **KPI tiles gained a trend**: Victims and Cyberattacks now show a 30-day count against the preceding 30 days, with an arrow and a sign (never colour alone), plus a 12-month sparkline. Groups, Countries and Sources deliberately keep bare counts — they have no date column, and an invented trend is worse than no trend. When there is no preceding window to compare against, the tile shows an em dash rather than a fabricated percentage
- **Victims-per-month timeline on the dashboard** — the first time-series in the application. Until now there was exactly one chart type (a choropleth, used three times) across fifteen templates, and no temporal view at all despite thousands of dated victims and attacks; "attack trends" is one of the things analysts ask for most. Single series, 24-month window, crosshair with unified tooltip. Buckets are aggregated **in SQL** (`date_trunc` on PostgreSQL, `strftime` on SQLite) so the payload is one point per month rather than one per victim, and empty months are zero-filled rather than dropped — a line that skips a gap implies a continuity that isn't there
- `GET /api/v1/stats/timeline?months=N` returns the same series as JSON
- **The article pipeline actually runs**: the scheduler now drives a full ingest cycle (seed curated sources → poll every enabled feed → fill in missing full text) on the regular enrichment pass, with its own enable/disable toggle and last-run timestamp. Until now the Phase 2 code had no production caller at all — only tests — so the `articles` table stayed empty even though the fetcher shipped in June. Verified live against the eight seed feeds: 8/8 sources, 110 entries, 101 articles ingested, 9 near-duplicates suppressed; a second pass added nothing and recognised all 101, confirming dedup. Cadence follows the existing poll cycle (`PEST_ARTICLE_INGEST_HOURS`, default 4h)
- **Article ingestion (AI pipeline Phase 2, iteration 1)**: curated RSS source seed (8 live-verified feeds, ranked by how often each vendor appears in our adversaries' references) and an RSS/Atom fetcher with canonical-URL dedup (tracking params stripped, exact dedup via `uq_article_url_hash`). Summary-only for now; full-text, near-dup and campaign clustering follow

## [0.7.0] - 2026-06-12

Post-v0.6.0 consolidation release. The May code review is fully dispositioned
(fix groups A/B/C + the deferred schema round), the UI gains a design system
(elementary OS palette, *Elementary*-series noir dark mode, self-hosted
assets) and adversary profiles become multi-source with preserved evidence.

### Added
- **Multi-source adversary profiles (evidence vs synthesis)**: the full MITRE ATT&CK group profile — previously discarded after country extraction — is now preserved as attributed evidence in `group_source_data` and rendered as its own block on the group page ("Profile — MITRE ATT&CK", with G-id, update date and link), alongside the ransomware.live description
- **Evidence history** (`group_source_history`, migration 0012): when a source's payload for a group changes, the previous version is archived instead of overwritten — adversary self-descriptions evolve, and the history is itself intelligence. Unchanged payloads are now skipped entirely (no more rewrite-every-cycle churn)
- **Phase 2 implementation plan** (`.planning/PHASE2-PLAN.md`): article ingestion & dedup kickoff for the ADR-006 pipeline

### Database (migrations 0008-0012 — run `alembic upgrade head`)
- All 40 datetime columns are now timezone-aware (`TIMESTAMPTZ` on PostgreSQL, stored as UTC) — closes BL-04 at the schema level
- `cyberattacks` gains `UNIQUE(victim_name, attack_date)` after an idempotent dedup (BL-07); NULL-keyed rows remain allowed
- `alerts` foreign keys now `ON DELETE CASCADE`: deleting a watchlist target or victim removes its alerts at the DB level
- New `groups.is_hacktivist` column, backfilled from descriptions; the hacktivist classification is computed once at ingest (`pestilentia/classify.py`) instead of on every page render
- SQLite connections now enforce foreign keys (`PRAGMA foreign_keys=ON`) for parity with PostgreSQL

### Added
- **User-adjustable font size** — A−/A+ controls in the sidebar footer scale the root font size (87.5%–137.5%); the whole rem-based UI follows proportionally; persisted per browser (localStorage)
- **Dark mode (noir)** — *Elementary*-series direction on the elementary OS Slate/Silver families: `darkMode: 'class'`, `noir-*` surface tokens, dark variants across all 15 templates, dark-aware Plotly maps (Slate land/ocean), sidebar/focus dark CSS. Defaults to the OS preference (`prefers-color-scheme`), persisted in `localStorage`, toggle (◐) in the sidebar footer
- **UI-SPEC.md** — design system spec: typography, brand + semantic status color tokens, component recipes (cards, badges, dots, tabs, tables, buttons), chart theming rules, a11y floor

### Changed
- **Guide prose raised from 12px to 14px** (133 paragraphs): long-form documentation copy now respects the 14px body floor; `text-xs` remains for tables/labels/badges
- **Dashboard/map stat numerals are now neutral** (gray-800 / Silver 100 in dark) instead of red/orange/yellow/blue — color is reserved for state, not magnitude (verified alert-fatigue best practice); page title reduced to `text-xl` so numerals own the visual hierarchy (UI-REVIEW #10); tables render tabular figures (`font-variant-numeric: tabular-nums`) so numeric columns align
- **Color palette remapped onto the official elementary OS brand palette** (UI-SPEC §2, binding rule): every UI color now comes from elementary's published families — accent = Blueberry 500/300/700 (the 500 was already in use), status tokens = Lime/Banana/Strawberry/Slate, Pyramid-of-Pain layers = Strawberry→Orange→Banana→Lime→Blueberry→Grape, Diamond Model nodes = Blueberry/Banana/Grape/Strawberry. Mood reference for shade choices (and the future dark mode): the CBS series *Elementary* — Victorian brownstone, muted Slate/Cocoa tones
- **Front-end fully self-hosted — permanent rule, no remote assets** (UI-SPEC §6): Tailwind Play runtime, HTMX 2.0.4 and Plotly 2.35.2 vendored under `static/vendor/`; **Inter self-hosted** under `static/fonts/` (variable woff2, latin + latin-ext) replacing Google Fonts. Zero remote requests: works offline/air-gapped, immune to the LAN DNS failure observed on `cdn.tailwindcss.com`, and no analyst browsing metadata leaks to third parties
- **Semantic status tokens** (`status-ok/warn/down/off` with `-dot/-bg/-border` variants) defined in the Tailwind config and applied to pipeline and group-detail status UI — replaces the drifting mix of raw `green/emerald/yellow/orange/red/slate` classes
- **Shared chart theme** (`static/pest-theme.js`): one `PEST` object owns the Plotly layout (transparent backgrounds, Inter font — charts previously fell back to Open Sans), geo defaults, the YlOrRd choropleth scale and the ISO-3166 alpha-2→alpha-3 map that was duplicated in 3 templates
- **Diamond Model and Pyramid of Pain redrawn** (group detail): the pyramid was rendered upside-down (TTPs widest at the top) with a jagged sawtooth silhouette — now a true triangle (TTPs at the apex, Hash Values at the base) with a continuous outline, white band separators and a right-hand label column with counts/leader lines. The diamond now follows the canonical Caltagirone orientation (socio-political axis vertical: Adversary/Victim; technical axis horizontal: Capability/Infrastructure — Victim was at left and Infrastructure at bottom), with full labels outside the nodes (no more "ADV"/"CAP"/"VIC" abbreviations), the metric + sublabel inside each node, subtle axis captions and `<title>` tooltips. Same click-to-expand behavior
- **UI accessibility & consistency pass** (UI-REVIEW followups): tab navigation in group detail and guide now uses real ARIA tab semantics (`role="tablist"/"tab"/"tabpanel"`, `aria-selected` kept in sync, arrow-key navigation); pipeline status badges unified on the solid `bg-*-50 border border-*-200 text-*-700` style (was a mix with 20%-opacity variants); dynamic Tailwind class interpolation replaced with whole-class conditionals (build-step safe); Pyramid-of-Pain "No data" label bumped to readable contrast (gray-400, 9px); group avatars have real `alt` text; visible `:focus-visible` ring and `[disabled]` styling on buttons; single hover convention (`hover:bg-accent-dim`); "Loading map…" placeholder while Plotly initializes; `apple-touch-icon` link added
- **MITRE match logs now name the alias that triggered the match** (LO-04), easing false-positive debugging
- `_normalize` consolidated into `clients/_util.py:normalize_group_name` (was duplicated identically in the MITRE, Ransomwhere and deepdarkCTI clients) (NI-02)
- deepdarkCTI per-file error handling narrowed from bare `except Exception` to `(httpx.HTTPError, ValueError, KeyError)` with full traceback logging — unexpected bugs now propagate instead of being silently swallowed (NI-05)
- `InfoUpdate.category` namespaces documented on the model (exact-match lookups only); CSRF threat model documented as accepted (stateless HMAC tokens, no nonce store, admin app behind Basic Auth) (ME-10, HI-01, LO-07)
- **Watchlist fuzzy matching is now incremental** (HI-09): the per-refresh fuzzy scan only matches victims added since the last scan (high-water marks persisted in `info_updates`: `watchlist_victim_hwm`, `watchlist_target_hwm`); a newly added watchlist target still gets one full scan over all victims. Previously every refresh re-scanned all targets against all ~27k victims (O(W×V) thefuzz calls). Known trade-off: a target deactivated across a scan and later re-activated may miss victims ingested while it was inactive
- Development version reopened at `0.7.0.dev0` (`pyproject.toml`, `__version__`, web footer)

### Fixed
- **Orphaned alerts are skipped instead of dispatched as "unknown"** (ME-01): if an alert references a deleted watchlist or victim, the dispatcher logs a warning and skips it rather than emitting an event with `watchlist_name="unknown"` that downstream consumers can't distinguish from a real name (FK `ondelete="CASCADE"` deferred to the migration round)
- **Malformed STIX bundle fails loudly** (ME-07): `validate_bundle` raises a `SourceError` with a clear message when the bundle lacks the `objects` key, instead of an opaque `KeyError` deep in the enrichment cycle
- **Source count no longer includes disabled enrichments** (ME-09): the dashboard "sources" counter only counts an enrichment if it is currently enabled and has run at least once
- **`aliases` JSON scalar no longer iterates char-by-char in templates** (LO-01): `_parse_aliases` wraps non-list JSON values in a list
- **Country attribution detected beyond the first paragraph** (LO-05): `extract_country` searches the whole MITRE description (origin is often stated in paragraph 2)
- **Back-to-back markdown tables no longer leak headers as data** (LO-06): `parse_ransomware_table` drops the row preceding a separator when two tables are adjacent and the second header has an unrecognized first column
- **Scheduler unregisters its signal handlers on exit** (LO-03): a second `run_scheduler` in the same event loop no longer acts on a stale stop event
- **Savepoint no longer poisoned by unexpected DB errors** (ME-02): `_safe_add`/`_safe_add_tx`/`_safe_add_comm` (MITRE, Ransomwhere, deepdarkCTI) now roll back the savepoint before re-raising non-`IntegrityError` exceptions; previously a disconnect mid-insert left the savepoint open and every subsequent insert in the same enrichment cycle failed with "this Session's transaction has been rolled back"
- **STIX bundle cache can no longer go permanently stale** (HI-03): `download_stix_bundle` takes an explicit `force: bool` parameter and bypasses/refreshes the on-disk cache when set; the implicit `_invalidate_cache` side-channel is removed. Direct callers now get documented cache semantics instead of a silent forever-cache
- **MITRE enrichment no longer discards ingested aliases** (ME-03): MITRE aliases are now merged (case-insensitive union, group's own name excluded) with the aliases set during ingestion (e.g. "BlackCat" from ransomware.live survives MITRE's "ALPHV" list) instead of overwriting them on every enrichment pass
- **deepdarkCTI enrichment no longer self-suppresses for a week on a transient failure** (ME-05): the last-enrichment timestamp is now set only if at least one source file was fetched and parsed; a total network/DNS outage leaves it untouched so the next cycle (~4h) retries instead of skipping for the full interval
- **`Group.profile_urls` stored raw markdown** (HI-04): profile entries like `[Tor mirror](http://x.onion)` were saved verbatim into `profile_urls` (rendered literally in the UI) while `group_references` held the clean URL. Now stores the cleaned URLs

### Removed
- Dead/broken MITRE etag helpers `_get_stored_etag` and `_get_etag_value` (returned the lookup constant, never called) and the now-unused `MITRE_ETAG_CATEGORY` constant; the etag is read/written via `_read_etag_file`/`_write_etag_file` (HI-02)

## [0.6.0] - 2026-06-11

First tagged release. Production deployment (Docker + PostgreSQL on Raspberry Pi 5),
a full security-hardening pass, several PostgreSQL-only bug fixes found during deployment,
and the v0.6 schema / AI foundation (Phase 1 of 7). The AI article-analysis pipeline
(ADR-006, phases 2–7) remains in active development.

### Fixed
- **Recent victim dates lost** — `_parse_datetime` only accepted space-separated/date-only formats, but the ransomware.live API now returns ISO 8601 with `T` and a UTC offset (`2026-06-11T15:50:04.568000+00:00`). Every recent victim's `attackdate` parsed to `None`, so they were ingested date-less and vanished from date-filtered views ("only 1 victim in the last month"). Now parses via `datetime.fromisoformat` (handles `T`, offset, and `Z`), keeping the legacy formats as fallback. Verified: 100/100 recent victims now carry dates
- MITRE incremental enrichment crashed on PostgreSQL with `can't compare offset-naive and offset-aware datetimes` (`_filter_modified_since`): the DB returns a naive `last_enrichment` while STIX `modified` parses to tz-aware UTC. Now coerces `since` to aware UTC before comparing (BL-04 site that remained)
- `_ingest_groups` guards each new-group insert with a savepoint (`begin_nested`) and absorbs `IntegrityError`: a concurrent writer (or web `/api/v1/refresh` overlapping the scheduler) inserting the same `group_name` between the dedup check and flush no longer rolls back the entire multi-minute ingest cycle (BL-07/HI-07)
- Feed-supplied URL/link columns widened from `String(300)` to `Text` (Alembic `0007`, batch mode for SQLite portability): `groups.url`, `group_locations.fqdn`/`slug`, `victims.claim_url`/`screenshot`/`url`, `victim_duplicates.dup_link`, `victim_press.press_link`, `victim_updates.update_link`. Onion URLs routinely exceed 300 chars; SQLite never enforced it but PostgreSQL does, so ingestion failed with `StringDataRightTruncation` (review finding ME-04)
- Dockerfile now copies `alembic.ini` + `alembic/` into the image so containers can run `alembic upgrade head`
- Scheduler service overrides the image's web `HEALTHCHECK` (it serves no HTTP) so the container is not perpetually reported unhealthy

### Security
- `safe_url` Jinja filter: feed-supplied URLs (`claim_url`, group URL, references, communication channels) are now restricted to `http(s)://` in `href` attributes, neutralizing `javascript:`/`data:` scheme injection from adversary-controlled feed data
- Optional HTTP Basic Auth for the web UI and REST API via `PEST_AUTH_USER`/`PEST_AUTH_PASS` (constant-time comparison; setting only one of the two refuses to boot)
- Webhook channel rejects non-http(s) URLs and private/loopback/link-local addresses (SSRF defense); fixed potential `raise None` when retries are exhausted without a captured exception
- `/api/v1/groups/{name}/avatar` now enforces `size >= 16` (parity with `/avatar/{name}`)
- `fetch_group_detail` URL-encodes the group name before building the ransomware.live API path

### Added
- Shared sync HTTP helper `clients/http.py` (`get_with_retry`/`head_with_retry`): 3 attempts with exponential backoff on transport errors and 5xx, explicit `elementary-cti` User-Agent — adopted by MITRE, Ransomwhere, deepdarkCTI clients and source health checks
- `send()` on the webhook channel now delegates to `send_batch()` (single implementation)
- Unauthenticated `/healthz` liveness endpoint (no DB access) for the Docker `HEALTHCHECK`, exempt from Basic Auth
- `scripts/migrate_sqlite_to_postgres.py`: schema-agnostic, FK-safe data migration (copies shared columns, resets Postgres sequences, `--wipe` for idempotent re-runs)
- `DEPLOY.md`: single-host Docker + Postgres runbook (including the SQLite→Postgres seed migration)

### Changed
- Default SQLite database renamed from `pestilentia.db` to `elementaryctiDB.db` (file renamed in git, default `PEST_DB_URL` and all docs/templates updated). Existing local setups: rename the file or point `PEST_DB_URL` at the old path
- Scheduler now honors `PEST_RANSOMWHERE_ENRICHMENT_HOURS` and `PEST_DEEPDARKCTI_ENRICHMENT_HOURS` (previously defined but ignored — both fell back to the MITRE interval)
- Web app initializes structured JSON logging on startup (FastAPI `lifespan`), matching the scheduler
- `docker-compose.yml` hardened: Postgres bound to `127.0.0.1` only, credentials + `PEST_SECRET_KEY` + optional auth sourced from `.env` (compose refuses to start without `POSTGRES_PASSWORD`/`PEST_SECRET_KEY`); web port bind configurable via `PEST_WEB_BIND` (loopback by default)
- Docker `HEALTHCHECK` probes `/healthz` instead of the authenticated `/api/v1/pipeline/status`

### Added
- Six Alembic revisions (0001–0006) chained from baseline `e829876f638c`, one per AI pipeline table: `article_sources`, `articles`, `article_analysis_runs`, `llm_call_logs`, `ai_enrichment_audit`, `group_alias_proposals`; `alembic upgrade head` on a fresh DB exits 0 and creates all six tables; six-step downgrade returns to baseline
- `ai_enrichment_audit` table (revision 0005): AI audit log with `before_json`/`after_json` (sa.JSON), `model_name`, `confidence`, denormalized `tlp`, `decision`, and indexes `ix_aieaud_target`/`ix_aieaud_decision`/`ix_aieaud_article` — distinct from `enrichment_review` (victim-org matcher; unchanged)
- `tests/ai/test_ai_migrations.py`: round-trip migration test (upgrade head + 6 × downgrade -1 via alembic CLI subprocess on tmp_path SQLite)
- ADR-006 §5 resolved: new table `ai_enrichment_audit` confirmed as the AI audit log (not an extension of `enrichment_review`)
- Alembic migration tooling with baseline revision `e829876f638c` capturing the full v0.6 schema (24 tables); existing databases run `alembic stamp head` once. `alembic/env.py` resolves the URL from `PEST_DB_URL` (`.env` supported)
- ADR-006 skeleton: AI article-analysis pipeline (state machine, multi-LLM router, composite confidence gate, TLP 2.0 cloud boundary, audited enrichment, on-demand intel reports)
- SVG favicon (noir + accent magnifying glass with hex motif) wired into base template
- Ransomwhere BTC payment enrichment: matches 29/136 families, imports transactions with USD values
- deepdarkCTI operational enrichment: matches 244/442 gangs, imports onion URLs and comms channels
- `GroupBtcTransaction` table for BTC payment data (address, tx_hash, amount BTC/USD, date)
- `GroupComm` table for communication channels (Tox, Telegram, email, etc.)
- Financial Intelligence section in Infrastructure tab (total USD, BTC, tx count, address count)
- Communication Channels section in Infrastructure tab with typed channel display
- BTC addresses linked to blockchain.com explorer
- `PEST_RANSOMWHERE_ENRICHMENT_HOURS` and `PEST_DEEPDARKCTI_ENRICHMENT_HOURS` config options
- BTC Explorer page (`/btc`) with address search, summary cards, top 20 landing
- Hacktivist group detection: description-based flag with adaptive UI labels ("Claims" vs "Victims")
- Source health monitoring agent: HTTP availability + format validation + row count thresholds
- `SourceHealth` table tracking status (ok/degraded/down) per enrichment source
- Health check for deepdarkCTI (3 files), Ransomwhere, MITRE ATT&CK
- Health indicators on Pipeline page: status dots on cards, status column in enrichment table, detail section
- `POST /api/v1/health` endpoint to trigger health checks on demand
- Ransomwhere + deepdarkCTI + health checks integrated into scheduler post-cycle
- deepdarkCTI expanded: ransomware_gang.md + telegram_threat_actors.md + twitter_threat_actors.md
- Tabbed adversary detail pages: Overview, Infrastructure, Arsenal, TTPs, Victims, References
- Group detail enrichment from ransomware.live `/v2/group/{name}` endpoint (type, extensions, lineage, BTC addresses, profile URLs)
- `GroupSourceData` table for raw JSON storage (multi-source comparison foundation)
- New Group model columns: `group_type`, `extensions`, `lineage`, `btc_addresses`, `profile_urls`
- Origin country visualization on adversary choropleth maps (diagonal blue stripes via SVG pattern)
- Jinja2 filters: `extract_sources`, `parse_json_list`, `parse_group_type`, `parse_aliases`
- Guide page expanded to 9 tabs: Guida Utente, API, Pipeline, Glossario, Fonti, Playbook, FAQ, Metodologia, Changelog
- Glossario tab: 20 CTI terms in 4 categories (threat landscape, financial, infra, analyst)
- Fonti tab: deep-dive per source (endpoints, fields, matching strategy, limitations)
- Playbook tab: Quick Triage, 6 Pivot Strategies ranked by signal, Confidence Framework, Report template
- FAQ tab: 10 Elementary CTI-specific questions
- Metodologia tab: assessment methodology, pipeline flow, matching strategy, limitations
- Inline description paragraphs on all 9 pages (dashboard, victims, groups, cyberattacks, map, BTC, search, watchlist, pipeline)
- Enrichment enable/disable toggles for Ransomwhere and deepdarkCTI on Pipeline page
- `POST /api/v1/enrichment/{name}/toggle` endpoint
- Health status display rewritten: summary banner + Reachable/Format/Details table
- CSRF protection on all POST form routes using HMAC-signed tokens (US-SEC-001)
- `PEST_SECRET_KEY` config option for CSRF token signing
- `python-multipart` dependency for form data parsing
- Notification system core with strategy pattern and channel registry (US-NOTIFY-001)
- Built-in log channel for alert dispatch
- `NotificationSubscription` database model for channel configuration
- CI pipeline with GitHub Actions: lint + test with coverage ratchet (Codex §7)
- `DEPENDENCIES.md` with critical dependency contracts (Codex §2.2)
- Docker deployment: Dockerfile, docker-compose.yml with PostgreSQL (US-CORE-007)
- `psycopg2-binary` dependency for PostgreSQL support
- Fuzzy matching engine with configurable threshold (US-MATCH-001)
- `PEST_FUZZY_THRESHOLD` config option (default 85%)
- Global search box in top-right header (all pages)
- Map page time filter: 7 days, 15 days, 1 month, 1 year, all time
- `/api/v1/map` endpoint with period parameter
- Webhook notification channel with retry/backoff and secret header (US-NOTIFY-003)
- Dispatcher now reads channel config from `NotificationSubscription` table
- MITRE ATT&CK incremental enrichment: bundle freshness check, delta processing, new group detection
- MITRE enrichment integrated into scheduler (weekly by default, `PEST_MITRE_ENRICHMENT_HOURS`)
- Import `altname` from ransomware.live into group aliases (merged with MITRE aliases, case-insensitive dedup)
- Tests for config, logging, notifications, mugshot, webhook, MITRE incremental, altname merge (104 total)
- Pipeline page: toggle switches to enable/disable individual data sources and MITRE enrichment
- Toggle API endpoints: `POST /api/v1/source/{name}/toggle`, `POST /api/v1/mitre/toggle`
- Refresh API respects source enabled/disabled state

### Changed
- Adversary detail page: stacked cards → tabbed interface with map always visible above tabs
- Diamond Model and Pyramid of Pain moved into Overview tab (side-by-side on large screens)
- Infrastructure split into Online/Offline columns with scroll overflow
- Profile card uses single-column layout
- `clean_desc` filter no longer appends source URLs (moved to References)
- group.url (ransomware.live page) moved from Infrastructure to References
- Coverage ratchet baseline set at 40% (Codex §5.3)

### Fixed
- **HI-08**: SQLAlchemy engine memoized per database URL (one connection pool per process) and SQLite connections now use WAL journal mode — fixes PostgreSQL connection-pool leak from repeated `get_engine()` calls
- **US-PERF-001**: N+1 queries in `pipeline_status` replaced with batch GROUP BY (3 queries instead of N*3+N*Y)
- **US-PERF-001**: N+1 in `/api/v1/pipeline/status` endpoint — same batch fix
- Watchlist `_check_watchlist` now fetches only `(id, domain)` tuples instead of full ORM objects
- Removed redundant `_migrate()` in base.py (manual ALTER TABLE for columns already in model)
- Dashboard sources counter now includes MITRE enrichment
- Uniform search box styling across victims, cyberattacks, and search pages (light theme)
- `@app.get("/")` decorator misplaced on helper function instead of dashboard route
- Dark theme CSS remnants purged from all templates (28+ instances of slate/dark classes)
- MITRE cache invalidation logic inverted: force mode now correctly gets fresh bundle
- Webhook retry: no longer sleeps after final failed attempt (saved 4s per failure)
- ransomware.live client: retry fallthrough now raises SourceError instead of returning empty list
- Pagination validation: negative/zero page values rejected with 422
- Pagination links now URL-encode query parameters (prevents corruption with special chars)
- Fuzzy matching: empty/short strings no longer produce spurious matches (min 3 chars)
- LIKE wildcard injection: escape `%` and `_` in user search input
- Jinja2 autoescape explicitly enabled (XSS prevention)
- SQLAlchemy bulk update/delete with `synchronize_session="fetch"`
- Dockerfile runs as non-root user (UID 1000)
- Mixed API types in group detail (dict/list) properly serialized to JSON strings
- `api_refresh` consolidated from multiple sessions to single session (reduced connection overhead)
- `api_refresh` watchlist matching and MITRE enrichment now run in thread pool (no longer blocks event loop)

### Removed
- `robohash` dependency — replaced by built-in mugshot avatar generator

### Security
- CSRF token validation on `/watchlist/add`, `/watchlist/{id}/delete`, `/alerts/mark-read`
- XSS fix: pipeline toggle switches use data attributes instead of inline JS with template variables
- Escape LIKE wildcards in all ilike queries
- Explicit Jinja2 autoescape=True
- Non-root Docker container
- **BL-01**: CSRF protection extended to every state-mutating API endpoint (`/api/v1/source/{n}/toggle`, `/api/v1/mitre/toggle`, `/api/v1/enrichment/{n}/toggle`, `/api/v1/refresh`, `/api/v1/health`) via `X-CSRF-Token` header dependency and a `csrfFetch()` JS wrapper
- **BL-02**: refuse to boot when `PEST_SECRET_KEY` equals the placeholder string; generate an ephemeral random secret with a warning when the env var is unset (CSRF tokens invalidated on restart in that mode)
- **BL-08**: `/avatar/{name}` size parameter bounded to `[16, 512]` to prevent memory-exhaustion DoS

### Fixed (2026-05-21 code review remediation)
- **BL-03 / BL-07 / HI-07**: NULL-safe deduplication in `_ingest_victims` and `_ingest_cyberattacks` (`is_(None)` predicates) + `session.flush()` after each insert to detect within-batch duplicates
- **BL-04**: `_parse_datetime` attaches `tzinfo=UTC`; scheduler's enrichment-due diff no longer corrupts already-tz-aware values returned from PostgreSQL timestamptz columns
- **BL-05**: scheduler initializes enrichment flags before conditional bind — no more `UnboundLocalError` on shutdown during cycle
- **BL-06**: `/api/v1/refresh` and `/api/v1/health` migrated to `with get_db() as session:` context manager with per-source rollback on ingest failure

## [0.5.0] — 2025-04-25

### Added
- Centralized configuration management via `config.py` singleton (US-CORE-005)
- Structured JSON logging with custom formatter (US-CORE-006)
- Diamond Model SVG visualization on adversary detail pages (US-WEB-018)
- Pyramid of Pain SVG visualization on adversary detail pages (US-WEB-019)
- 50+ Elementary TV series quotes as Easter eggs throughout codebase

### Changed
- Choropleth maps now use YlOrRd colorscale with log binning for readability (US-WEB-017)
- Zero-data countries render in neutral gray instead of white
- Diamond Model and Pyramid of Pain displayed side-by-side on large screens

### Fixed
- Backfill `datetime.now()` replaced with `datetime.now(UTC)` for timezone correctness
- Extra `</div>` tag in group detail template causing layout issues

## [0.4.0] — 2025-04-25

### Added
- Rebrand from Pestilentia to Elementary CTI
- Light theme with white cards, gray background, blue accents
- Pixel-art mugshot avatar generator replacing Robohash monsters
- MITRE ATT&CK enrichment: TTPs, tools, aliases, country of origin (US-MITRE-001)
- Adversary aliases as tags and country-of-origin flags (US-WEB-015)
- Dashboard time-filtered adversaries: 7d, 1m, 1y tabs (US-WEB-012)
- Dashboard victims time tabs with map sync (US-WEB-014)
- Refresh button with last update timestamp (US-WEB-013)
- Real-time search filtering on adversary cards

## [0.3.0] — 2025-04-25

### Added
- Web interface with dashboard, victims, adversaries, cyberattacks pages (US-WEB-001 to US-WEB-009)
- REST API at `/api/v1/` with OpenAPI docs (US-WEB-007)
- Watchlist and alert system (US-WEB-011)
- Adversary detail pages with tools, TTPs, and references (US-WEB-010)
- Global search across victims, groups, and cyberattacks (US-WEB-008)
- Geographic choropleth map (US-WEB-005)
- Pipeline status page (US-WEB-006)
- Usage guide and changelog pages (US-WEB-009)

## [0.2.0] — 2025-04-24

### Added
- Data ingestion pipeline with deduplication (US-CORE-003)
- Scheduler with backfill-first strategy (US-CORE-004)
- Historical data backfill by year (US-DATA-001)
- Graceful shutdown on SIGTERM/SIGINT

## [0.1.0] — 2025-04-24

### Added
- ransomware.live API client with retry and rate limiting (US-CORE-001)
- Multi-source base architecture with registry pattern (ADR-003)
- Database schema and ORM models — 18 tables (US-CORE-002)
- SQLite and PostgreSQL support
- Project bootstrap: PRD, ADRs, backlog, Codex Machinae
