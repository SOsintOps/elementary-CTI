# Elementary CTI — UI Specification

Single source of truth for visual decisions. If a template needs a style not
covered here, extend this spec first, then implement.

Tokens live in two places, kept in sync by hand:
- **Tailwind config** — `templates/base.html` (`tailwind.config.theme.extend.colors`)
- **Chart/JS theme** — `static/pest-theme.js` (`window.PEST`)

## 1. Typography

- Font: **Inter** (self-hosted, `static/fonts/`), fallback `system-ui,
  sans-serif`. Same family as elementary.io. Plotly charts inherit it via
  `PEST.font` — never let a chart fall back to Plotly's default Open Sans.
- Sizes: `text-xs` (data/labels, dominant), `text-sm` (body), `text-lg`
  (card headings), `text-xl`/`text-2xl` (page titles, stat numerals).
  Do not introduce new sizes.
- **Prose floor**: long-form copy (`<p>` paragraphs meant for sustained
  reading — guide, descriptions) is `text-sm` minimum; `text-xs` is for
  scanning surfaces only (tables, labels, badges, timestamps).
- **User font scale**: A−/A+ in the sidebar footer adjust the root font-size
  (87.5%–137.5%, step 12.5; everything is rem-based so the whole scale
  follows). Persisted in `localStorage` (`pest-font-scale`); `?font=NNN` URL
  override for testing/screenshots.
- Weights: `normal / medium / semibold / bold` only.

## 2. Color tokens

### Palette source — BINDING: the official elementary OS palette only

Every color in the UI comes from the **official elementary OS brand palette**
(elementary.io/brand; 5 shades per family: 900/700/500/300/100). Two reference
points, set by the project owner (2026-06-11):

1. **elementary OS palette = the allowed colors.** Never clash with the OS
   brand; never introduce hues outside it (the old Tailwind grays stay only as
   neutral chrome). New color need → pick from the palette, note it here.
2. **The CBS series *Elementary* = the mood.** Victorian brownstone,
   shabby-chic, worn wood and low warm light: prefer the muted/dark members
   (Slate, Cocoa, Silver, deep 700/900 shades) over saturated ones; this will
   drive the dark-mode direction (base Slate 900 `#0e141f` — the favicon
   square `#1a1d24` already sits there — surfaces Slate 700 `#273445`, warm
   Cocoa `#715344` accents).

Official families (500 values): Strawberry `#c6262e`, Orange `#f37329`,
Banana `#f9c440`, Lime `#68b723`, Blueberry `#3689e6`, Grape `#7a36b1`,
Cocoa `#715344`, Silver `#abacae`, Slate `#485a6c`, Black `#333333`.
Note: `base-bg #fafafa` = Silver 100 — already on-palette.
Light `-bg` tints (the palette has no 50-tier): 500 mixed ~92% with white.

### Brand
| Token | Hex | Palette | Use |
|---|---|---|---|
| `accent` | `#3689e6` | Blueberry 500 | links, active states, primary buttons |
| `accent-light` | `#64baff` | Blueberry 300 | hover text on dark |
| `accent-dim` | `#0d52bf` | Blueberry 700 | button hover background (the only hover variant) |

Rules: never use raw `text-blue-*` for links — always `text-accent`.
Button hover is `hover:bg-accent-dim`, not `accent/80`.

### Status (semantic) — the only way to express ok/degraded/down/disabled
| Token | Family | Text | Dot | Bg | Border |
|---|---|---|---|---|---|
| `status-ok` | Lime | `#206b00` (900) | `#68b723` (500) | `#f6fbef` | `#d1ff82` (100) |
| `status-warn` | Banana | `#ad5f00` (900) | `#f9c440` (500) | `#fefaec` | `#ffe16b` (300) |
| `status-down` | Strawberry | `#a10705` (700) | `#ed5353` (300) | `#fdf0ef` | `#ff8c82` (100) |
| `status-off` | Slate | `#485a6c` (500) | `#95a3ab` (100) | `#f7f9fa` | `#d9dfe4` |

Rules: no raw `green/emerald/yellow/red/orange/slate` classes for anything that
means "state of a source/enrichment/location/job". `status-warn` covers both
"degraded" and "in progress". `status-off` is "disabled by the user", not an
error. JS gets the dot colors from `PEST.status`.

### Data colors (non-semantic, fixed encodings — all on-palette)
- **Ordered scales take a SEQUENTIAL ramp, never a categorical rainbow.**
  One hue, monotonic in luminance. Six distinct families on an ordered scale
  read as "six different things" when the data means "a gradient", and the
  rainbow that was previously used here **failed CVD separation**: adjacent
  bands sat at deutan ΔE 0.5 in dark mode — identical for ~8% of men. The
  palette rule is *one hue*, not *one published step-list*: tints of an
  official family are on-palette, because a lighter Blueberry cannot clash
  with the elementary brand.
- Pyramid-of-Pain layers, top→bottom (most→least pain): a Blueberry ramp,
  dark→light on the light surface (`#0d52bf #3689e6 #64baff #8cd5ff #c6e2ff
  #e8f3ff`) and inverted light→dark on the noir surface (`#8cd5ff #64baff
  #3689e6 #2a6bb0 #1d4a7a #16324f`). Both are verified monotonic in relative
  luminance. Levels the pipeline cannot populate yet render neutral grey with
  "Not collected yet" — distinct from "None found".
- **Labels wear text tokens, never the mark colour.** The band carries
  identity; the text stays in `gray-800`/`noir-hi` (or `gray-400`/`noir-mute`
  when inactive). Low-contrast steps at the light end of a sequential ramp are
  expected and are relieved by those always-present labels.
- Diamond Model nodes: Adversary Blueberry, Capability Banana, Infrastructure
  Grape (Slate when empty), Victim Strawberry — light fill + colored border.
- Victim/claim counts: red danger framing (`text-red-500`) — candidate for
  Strawberry or a calmer neutral; decide during the visual tour (alert-fatigue
  principle: descriptive data should not scream).
- BTC/financial: amber today — candidate for **Cocoa** (series mood) when
  dark mode lands.
- Choropleth scale: `PEST.choroScale` (YlOrRd), log-scaled victim counts —
  cartographic scale, allowed exception.

## 3. Components

- **Card**: `bg-white border border-gray-200 rounded-lg p-4 shadow-sm` with a
  `text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3` heading.
- **Status badge**: `px-2 py-0.5 rounded-full text-xs bg-status-X-bg border
  border-status-X-border text-status-X`. Solid style only — the translucent
  `*-500/20` variant is banned (contrast).
- **Status dot**: `w-2.5 h-2.5 rounded-full bg-status-X-dot` + adjacent
  `text-status-X` label or `title` attr. Never a dot without an accessible label.
- **Neutral chip** (aliases, extensions): `text-xs bg-gray-100 text-gray-600
  px-2 py-0.5 rounded border border-gray-200`.
- **Tabs**: ARIA tablist pattern (`role="tablist"/"tab"/"tabpanel"`,
  `aria-selected` synced, arrow-key navigation). Active =
  `border-b-2 border-accent text-accent`.
- **Tables**: head `py-2 text-xs text-gray-400`, rows `py-1.5 border-b
  border-gray-100`, wrap in `overflow-x-auto`.
- **Buttons**: primary `bg-accent text-white hover:bg-accent-dim`; focus ring
  comes from the global `:focus-visible` rule in base.html — don't suppress it.

## 4. Charts (Plotly)

All Plotly calls go through `window.PEST`:
- layout: `PEST.geoLayout({ height, margin?, geo?: overrides })` — transparent
  backgrounds, Inter font, natural-earth projection, shared land/ocean colors.
- config: `PEST.plotlyConfig` (responsive, no modebar).
- country codes: `PEST.iso2to3`; scale: `PEST.choroScale`.
Templates must not re-declare any of these.

## 5. Language & a11y

- Document language: `lang="it"` (UI prose is Italian; labels may stay English).
- Every icon-only control needs `aria-label`; every avatar `alt="<name> avatar"`.
- Minimum text contrast: WCAG AA. De-emphasized text floor: `text-gray-400` at
  `text-xs`; never `gray-300` on white for content.

## 6. Assets — PERMANENT RULE: fully self-hosted, no exceptions

**No remote assets of any kind: no CDN scripts, no remote stylesheets, and NO
REMOTE FONTS — ever.** This is a standing development rule set by the project
owner (2026-06-11), not a temporary workaround. Anything the UI needs ships in
the repo:

- Libraries → `static/vendor/` (Tailwind Play runtime, HTMX, Plotly)
- Fonts → `static/fonts/` (Inter variable woff2, latin + latin-ext subsets,
  loaded via `static/fonts/inter.css`)

Background: the LAN's DNS resolver was observed failing to resolve
`cdn.tailwindcss.com` (2026-06-11), serving the app unstyled. Self-hosting
also keeps the app fully functional offline/air-gapped and avoids leaking
analyst browsing metadata to third parties (Google Fonts requests included) —
the right posture for a CTI tool.

When adding a dependency or a font: download it, commit it, reference it from
`/static/...`. A PR that introduces a remote URL in a template fails review.

## 7. Dark mode (noir)

Shipped 2026-06-12, `darkMode: 'class'` on the vendored Play runtime. The
*Elementary*-series noir direction: base Slate 900, cards/raised Slate-derived
(`noir-*` tokens in base.html), text Silver 300/100, muted Slate 100.
- Default follows `prefers-color-scheme`; persisted via `localStorage`
  (`pest-theme`); toggle (◐) in the sidebar footer; `?theme=dark|light` URL
  override (also used by the screenshot workflow).
- Toggling reloads the page so Plotly re-themes (`PEST.geoLayout()` is
  dark-aware: Slate land/ocean, Silver font).
- Status text switches to the vivid `-dot` colors on dark; badges use
  translucent `dot/10` fills (the on-white contrast ban does not apply on
  dark surfaces).
- Every new template MUST ship both themes: pair light classes with their
  `dark:` variants (`bg-white dark:bg-noir-card`, `text-gray-800
  dark:text-noir-hi`, ...).

## 8. Dashboard rules (verified best practices, 2026-06-11)

- Stat numerals are **neutral** (`text-gray-800 dark:text-noir-hi`): color is
  for state, not magnitude — descriptive data must not scream (alert-fatigue).
- Tables use tabular figures (global `font-variant-numeric: tabular-nums`).
- Page title (`text-xl`) sits one step below stat numerals (`text-2xl`).
- No zebra striping (evidence is mixed); row hover-highlight instead.

## 9. Known debt / future

- Tailwind runs from the vendored Play runtime (compiles in the browser):
  tokens are duplicated between base.html and pest-theme.js. Moving to a real
  build step (`tailwindcss` CLI, generated CSS) removes the runtime cost;
  regenerate both token copies from one source then.
- Diamond SVG fills are still light-theme hex; acceptable on dark (chip
  effect) — theme them if it ever jars. **The Pyramid was themed on
  2026-08-07**: its inactive bands were `#f3f4f6` on a `#1a2433` card, i.e.
  near-white on dark. Fills, strokes and labels now carry `dark:` variants.
- The Diamond SVG still uses hard-coded light-theme hex; give it `dark:`
  variants the way the Pyramid now has.
