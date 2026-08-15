#!/usr/bin/env python
"""Weekly upstream-contract sentinel: are the APIs alive AND unchanged?

Deterministic stage of the sentinel (see PLAN-API-SENTINEL-2026-08.md). Fetches
one sample from every upstream this codebase parses, fingerprints its type
structure, and compares against the committed baselines in `contracts/`.

    uv run python scripts/api_sentinel.py            # check
    uv run python scripts/api_sentinel.py --update   # (re)capture baselines

Exit codes: 0 all alive and matching, 3 drift or unreachable (report written
to .reports/api-drift/), 2 usage/config error. The LLM analysis stage lives in
api-sentinel-weekly.sh and only runs on exit 3 — this script never calls one.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import UTC, datetime

import feedparser
import httpx

from pestilentia.ai.sources.seeds import SEED_SOURCES
from pestilentia.clients.deepdarkcti import (
    DEEPDARK_FILES,
    parse_ransomware_table,
    parse_telegram_actors,
    parse_twitter_actors,
)
from pestilentia.contracts import (
    REPORT_DIR,
    ContractResult,
    check_sample,
    fingerprint,
    save_baseline,
)


class RateLimitedError(RuntimeError):
    """The upstream said 429 twice — back off until next week, distinctly."""


_TIMEOUT = httpx.Timeout(30.0)
_UA = {"User-Agent": "elementary-cti-sentinel/1.0 (+https://github.com/SOsintOps/elementary-CTI)"}

RANSOMWARE_LIVE = {
    # endpoint name -> (url, how to pick the sample from the response)
    "ransomware_live_groups": "https://api.ransomware.live/v2/groups",
    "ransomware_live_recentvictims": "https://api.ransomware.live/v2/recentvictims",
    "ransomware_live_recentcyberattacks": "https://api.ransomware.live/v2/recentcyberattacks",
}
RANSOMWHERE_URL = "https://api.ransomwhe.re/export"

_DEEPDARK_PARSERS = {
    "ransomware_gang": parse_ransomware_table,
    "telegram_threat_actors": parse_telegram_actors,
    "twitter_threat_actors": parse_twitter_actors,
}


def _sample_of(payload: object) -> object:
    """The whole record list, not one record off the top.

    One record cannot distinguish a stable contract from a field the upstream
    types two different ways — and both ransomware.live endpoints do exactly
    that, interleaved within a single page. `fingerprint` merges the list into
    one structure and marks the inconsistent fields, so the cost of reading all
    of them is a fold over records that were downloaded anyway."""
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for value in payload.values():
            if isinstance(value, list) and value:
                return value
    return payload


def _fetch_json(client: httpx.Client, url: str) -> object:
    response = client.get(url, headers=_UA)
    if response.status_code == 429:
        # Rate limiting is neither drift nor an outage. One respectful retry —
        # honouring Retry-After when sane — and if it persists the caller
        # reports it as its own status instead of crying "unreachable".
        wait = min(int(response.headers.get("Retry-After", "30") or 30), 120)
        time.sleep(wait)
        response = client.get(url, headers=_UA)
        if response.status_code == 429:
            raise RateLimitedError(url)
    response.raise_for_status()
    return response.json()


def probe_all(update: bool) -> list[ContractResult]:
    results: list[ContractResult] = []

    def handle(name: str, sample: object) -> None:
        if update:
            save_baseline(name, fingerprint(sample))
            results.append(ContractResult(name, ok=True, status="baseline-updated", problems=[]))
        else:
            results.append(check_sample(name, sample))

    with httpx.Client(timeout=_TIMEOUT, follow_redirects=True) as client:
        for name, url in RANSOMWARE_LIVE.items():
            try:
                handle(name, _sample_of(_fetch_json(client, url)))
            except RateLimitedError:
                results.append(
                    ContractResult(name, False, "rate-limited", [f"{url}: 429 twice, backed off"])
                )
            except Exception as exc:
                results.append(ContractResult(name, False, "unreachable", [f"{url}: {exc}"]))

        try:
            handle("ransomwhere_export", _sample_of(_fetch_json(client, RANSOMWHERE_URL)))
        except Exception as exc:
            results.append(
                ContractResult(
                    "ransomwhere_export", False, "unreachable", [f"{RANSOMWHERE_URL}: {exc}"]
                )
            )

        for key, url in DEEPDARK_FILES.items():
            parser = _DEEPDARK_PARSERS.get(key)
            if parser is None:
                continue
            name = f"deepdarkcti_{key}"
            try:
                rows = parser(client.get(url, headers=_UA).raise_for_status().text)
                if not rows:
                    results.append(ContractResult(name, False, "drift", ["parser yielded 0 rows"]))
                    continue
                handle(name, rows)
            except Exception as exc:
                results.append(ContractResult(name, False, "unreachable", [f"{url}: {exc}"]))

        # RSS feeds have no stable payload schema to fingerprint — entries churn
        # by design. Their contract is: parses as a feed, has entries, entries
        # carry the two fields ingestion cannot live without.
        for spec in SEED_SOURCES:
            name = (
                f"feed_{spec['name'].lower().replace(' ', '_').replace('(', '').replace(')', '')}"
            )
            try:
                raw = client.get(spec["url"], headers=_UA).raise_for_status().content
                parsed = feedparser.parse(raw)
                problems = []
                if not parsed.entries:
                    problems.append("feed parsed but has no entries")
                else:
                    entry = parsed.entries[0]
                    for field in ("title", "link"):
                        if not entry.get(field):
                            problems.append(f"entries lack '{field}'")
                if problems:
                    results.append(ContractResult(name, False, "drift", problems))
                else:
                    results.append(ContractResult(name, True, "alive+match", []))
            except Exception as exc:
                results.append(
                    ContractResult(name, False, "unreachable", [f"{spec['url']}: {exc}"])
                )

    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--update", action="store_true", help="capture baselines instead of checking"
    )
    args = parser.parse_args()

    results = probe_all(update=args.update)
    failed = [r for r in results if not r.ok]

    for r in results:
        marker = "ok " if r.ok else "FAIL"
        print(
            f"[{marker}] {r.name}: {r.status}"
            + (f" — {'; '.join(r.problems)}" if r.problems else "")
        )

    if args.update:
        print(f"\nBaselines written to contracts/ for {len(results)} upstreams.")
        return 0

    if failed:
        REPORT_DIR.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(UTC).strftime("%Y%m%d_%H%M")
        report = REPORT_DIR / f"{stamp}-drift.json"
        report.write_text(
            json.dumps(
                {
                    "checked_at": datetime.now(UTC).isoformat(),
                    "failed": [r.as_dict() for r in failed],
                    "passed": [r.name for r in results if r.ok],
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        print(f"\nDrift report: {report}")
        return 3

    print(f"\nAll {len(results)} upstream contracts alive and unchanged.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
