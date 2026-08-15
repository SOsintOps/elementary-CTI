# "It is a capital mistake to theorise before one has data." — Sherlock Holmes
"""Phase 5 step 1: build the calibration corpus, and score what it wrote.

    uv run python scripts/corpus_runner.py sweep [--limit N] [--passes N]
    uv run python scripts/corpus_runner.py analyse [--per-source N] [--dry-run]
    uv run python scripts/corpus_runner.py style [--detail N]
    uv run python scripts/corpus_runner.py restyle [--limit N]
    uv run python scripts/corpus_runner.py gate [--limit N] [--local]

`sweep` recovers article bodies. It costs no LLM calls, so it runs over the
whole truncated backlog. `analyse` runs the extraction machine over a sample
stratified by feed, and that one costs eight NIM calls per article: at ten per
feed it is roughly 960 calls, which is a run to leave going, not a command to
wait on. `style` scores the summaries already written against the house style in
`docs/intelligence-writing-style.md`, grouped by the prompt version that wrote
them, and costs nothing because the checker is deterministic.

All the logic lives in the library — `backfill_fulltext`, `stratified_pending`,
`analyse_articles` — and is covered by the suite. What is here is argument
parsing and a report, because the lesson of Phase 4 is that a repeatable
acceptance run finds what the suite cannot, and a run that lives in /tmp gets
rewritten from memory the next time it is needed.

Reads PEST_DB_URL from the environment like the rest of the application, so it
points at whatever .env points at. Check the first log line before a long run:
this is meant for the development SQLite.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from sqlalchemy import create_engine, delete, func, select
from sqlalchemy.orm import sessionmaker

from pestilentia.ai import report as report_module
from pestilentia.ai.confidence.thresholds import reachability
from pestilentia.ai.enrichment.gate import run_gate
from pestilentia.ai.enrichment.identity import IdentityCatalog
from pestilentia.ai.prompts import PROMPTS
from pestilentia.ai.sources.fulltext import backfill_fulltext
from pestilentia.ai.state.driver import analyse_articles, build_machine, stratified_pending
from pestilentia.ai.state.machine import OUTPUT_KEY
from pestilentia.ai.style import check, tally
from pestilentia.clients.curated_feeds import FEEDS_BY_NAME, load_json_feed
from pestilentia.clients.mitre_attack import download_stix_bundle
from pestilentia.config import get_settings
from pestilentia.models.tables import (
    Article,
    ArticleAnalysisRun,
    ArticleSource,
    Group,
    StagedFinding,
)

log = logging.getLogger("corpus_runner")


def _session_factory():
    url = get_settings().db_url
    print(f"database: {url}")
    return sessionmaker(bind=create_engine(url))


def _sweep(args) -> int:
    factory = _session_factory()
    with factory() as session:
        report = backfill_fulltext(session, limit=args.limit, passes=args.passes)
        session.commit()

    print(f"\n=== full-text sweep, {report.passes} pass(es) ===")
    print(f"{'feed':34} {'ok':>4} {'refused':>8} {'deferred':>9} {'mean chars':>11}")
    for name in sorted(report.per_source):
        tally = report.per_source[name]
        print(
            f"{name[:34]:34} {tally.ok:4} {tally.refused:8} "
            f"{tally.deferred:9} {tally.mean_chars:11.0f}"
        )
    print(f"\nrecovered {report.ok}, refused {report.refused}, deferred {report.deferred}")
    print(
        "deferred articles stay truncated and remain the scheduler's; "
        "a refusal is a verdict on the URL and will not change on its own"
    )
    return 0


def _analyse(args) -> int:
    factory = _session_factory()
    with factory() as session:
        if args.article:
            # Named articles instead of a sample. The stratified draw is right
            # for calibration, where the corpus has to stand in for itself, and
            # wrong for an acceptance run, where the point is a *particular*
            # article that exercises a particular path. Step 10 needs one whose
            # indicators can reach a group we already hold, and waiting for the
            # sample to offer one would cost hundreds of calls to reproduce a
            # condition that can simply be asked for.
            sample = [session.get(Article, article_id) for article_id in args.article]
            missing = [i for i, a in zip(args.article, sample, strict=True) if a is None]
            if missing:
                print(f"no such article: {missing}", file=sys.stderr)
                return 1
        else:
            sample = stratified_pending(session, per_source=args.per_source)
        names = dict(session.query(ArticleSource.id, ArticleSource.name).all())

        per_feed: dict[str, int] = {}
        for article in sample:
            per_feed[names.get(article.source_id, "unknown")] = (
                per_feed.get(names.get(article.source_id, "unknown"), 0) + 1
            )

        print(f"\n=== sample: {len(sample)} articles, at most {args.per_source} per feed ===")
        for name in sorted(per_feed):
            chars = [len(a.body or "") for a in sample if names.get(a.source_id, "unknown") == name]
            mean = sum(chars) / len(chars) if chars else 0
            print(f"{name[:34]:34} {per_feed[name]:3} articles, mean body {mean:8.0f} chars")

        if args.dry_run:
            print("\ndry run: nothing was sent to the provider")
            return 0

        machine = build_machine()
        if machine is None:
            print("\nthe machine could not be built — see the log line above", file=sys.stderr)
            return 1

        print(f"\nrunning the machine over {len(sample)} articles, ~8 calls each\n")
        outcome = analyse_articles(session, machine, articles=sample)
        session.commit()

        print("\n=== outcome ===")
        print(f"analysed        {outcome.analysed}")
        print(f"dropped, triage {outcome.dropped}")
        print(f"incomplete      {outcome.incomplete} {outcome.stopped or ''}")
        print(f"attempted       {outcome.attempted}")
        print(
            f"\ntriage kept {outcome.analysed} of {outcome.attempted}: the corpus that "
            "reaches the gate is the post-triage subset, and step 9 records that"
        )
    return 0


#: The narrative state's three prose fields, and whether counsel belongs in each.
PROSE_FIELDS = (("key_judgement", False), ("summary_md", False), ("recommendations_md", True))


def _style(args) -> int:
    """Score the written prose against the house style, grouped by prompt version.

    Read from the run row's `raw_output_json` rather than from `Article`,
    because that is where all three prose fields sit together beside the
    version that wrote them. `Article` carries only two of the three, and a
    judgement measured apart from the summary it heads is measured out of
    context.

    No LLM calls: the checker is deterministic, so the before-and-after of a
    prompt change costs nothing and can be re-measured whenever the rules move.
    Grouping by version is the whole point. A total that sums two prompt
    versions says nothing about either.
    """
    factory = _session_factory()
    with factory() as session:
        rows = session.execute(
            select(
                ArticleAnalysisRun.article_id,
                Article.title,
                ArticleAnalysisRun.prompt_version,
                ArticleAnalysisRun.raw_output_json,
            )
            .join(Article, Article.id == ArticleAnalysisRun.article_id)
            .where(
                ArticleAnalysisRun.state == "narrative",
                ArticleAnalysisRun.status == "ok",
                ArticleAnalysisRun.raw_output_json.isnot(None),
            )
            .order_by(ArticleAnalysisRun.article_id)
        ).all()

    by_version: dict[str, dict] = {}
    for article_id, title, version, raw in rows:
        output = (raw or {}).get("output") or {}
        name = version or "unversioned"
        bucket = by_version.setdefault(
            name, {"assessments": 0, "clean": 0, "counts": {}, "by_field": {}, "worst": []}
        )
        bucket["assessments"] += 1

        found = []
        for field, advice_allowed in PROSE_FIELDS:
            violations = check(output.get(field) or "", advice_allowed=advice_allowed)
            bucket["by_field"][field] = bucket["by_field"].get(field, 0) + len(violations)
            found.extend(violations)

        if not found:
            bucket["clean"] += 1
        else:
            bucket["worst"].append((len(found), article_id, title, found))
        for rule, count in tally(found).items():
            bucket["counts"][rule] = bucket["counts"].get(rule, 0) + count

    for name in sorted(by_version):
        bucket = by_version[name]
        total = sum(bucket["counts"].values())
        assessments = bucket["assessments"]
        print(f"\n=== {name}: {assessments} assessments, {total} violations ===")
        print(f"clean assessments: {bucket['clean']}/{assessments}")
        print(f"violations per assessment: {total / assessments:.2f}")
        print("\n  by rule:")
        for rule, count in sorted(bucket["counts"].items(), key=lambda kv: -kv[1]):
            print(f"    {rule:22} {count}")
        print("\n  by field:")
        for field, _ in PROSE_FIELDS:
            print(f"    {field:22} {bucket['by_field'].get(field, 0)}")

        if args.detail:
            for _, article_id, title, violations in sorted(
                bucket["worst"], key=lambda item: -item[0]
            )[: args.detail]:
                print(f"\n  --- article {article_id}: {title[:60]}")
                for violation in violations:
                    print(f"      {violation.rule:22} {violation.text[:70]!r}")
    return 0


#: Everything from the narrative onward. The three states that write prose, and
#: the audit that reads it. Clearing exactly these re-runs the prose for three
#: calls an article instead of eight, because the machine reuses every state
#: that already closed `ok`.
PROSE_STATES = ("narrative", "adversary_sketch", "verify")


def _restyle(args) -> int:
    """Rewrite the prose of already-analysed articles under the current prompts.

    The comparison this exists for has to be same-article: prompt versions
    differ, and so do articles, and an average across different articles cannot
    tell the two apart. So the before text is captured first, the prose states
    are cleared, and the machine is asked for them again on the same rows.

    The earlier states are left alone on purpose. Their output is grounded, it
    cost eight calls to produce, and none of it is what changed.
    """
    factory = _session_factory()
    with factory() as session:
        # The whole fingerprint, not the name it starts with. A style block is
        # edited far more often than a prompt is renamed, and every such edit
        # leaves the name alone and moves the digest. Matching on the prefix
        # therefore reads two different prompts as one and skips exactly the
        # rows a before-and-after needs: 64 rows carrying the old block sat
        # behind `narrative_v2` and were never offered for rewriting, while the
        # 3 genuinely old `v1` rows were.
        current = PROMPTS["narrative"].fingerprint
        candidates = session.execute(
            select(ArticleAnalysisRun.article_id, ArticleAnalysisRun.prompt_version)
            .where(
                ArticleAnalysisRun.state == "narrative",
                ArticleAnalysisRun.status == "ok",
                ArticleAnalysisRun.prompt_version != current,
            )
            .order_by(ArticleAnalysisRun.article_id)
            .limit(args.limit)
        ).all()

        if not candidates:
            print(f"nothing to restyle: every narrative row already reads {current}")
            return 0

        print(f"restyling {len(candidates)} articles onto {current}, ~3 calls each\n")

        machine = build_machine()
        if machine is None:
            print("\nthe machine could not be built — see the log line above", file=sys.stderr)
            return 1

        pairs = []
        for article_id, old_version in candidates:
            article = session.get(Article, article_id)
            before = session.scalar(
                select(ArticleAnalysisRun.raw_output_json).where(
                    ArticleAnalysisRun.article_id == article_id,
                    ArticleAnalysisRun.state == "narrative",
                )
            )
            session.execute(
                delete(ArticleAnalysisRun).where(
                    ArticleAnalysisRun.article_id == article_id,
                    ArticleAnalysisRun.state.in_(PROSE_STATES),
                )
            )
            session.commit()

            try:
                machine.run(session, article)
                session.commit()
            except Exception as exc:
                session.rollback()
                print(f"article {article_id} failed mid-restyle: {exc}", file=sys.stderr)
                continue

            after = session.scalar(
                select(ArticleAnalysisRun.raw_output_json).where(
                    ArticleAnalysisRun.article_id == article_id,
                    ArticleAnalysisRun.state == "narrative",
                )
            )
            pairs.append((article_id, article.title, old_version, before, after))

    for article_id, title, old_version, before, after in pairs:
        old = (before or {}).get("output") or {}
        new = (after or {}).get("output") or {}
        old_count = sum(
            len(check(old.get(field) or "", advice_allowed=allowed))
            for field, allowed in PROSE_FIELDS
        )
        new_count = sum(
            len(check(new.get(field) or "", advice_allowed=allowed))
            for field, allowed in PROSE_FIELDS
        )
        print(f"\n===== article {article_id}: {title[:70]}")
        print(f"  {old_version}: {old_count} violations -> {current}: {new_count}")
        for field, _ in PROSE_FIELDS:
            print(f"\n  --- {field}, before ---\n  {(old.get(field) or '').strip()}")
            print(f"  --- {field}, after ---\n  {(new.get(field) or '').strip()}")
    return 0


def _identity_catalog(session) -> IdentityCatalog:
    """Every catalogue this deployment holds, asked in the order that matters.

    Home first. A name this deployment already tracks is one somebody here has
    already reasoned about, and an outside catalogue must not quietly rename it.
    Missing files cost their own layer and not the run: the report then says a
    name is recognised by nothing, which is true of what is on disk.
    """
    local = IdentityCatalog.from_group_names(
        [(name, []) for (name,) in session.execute(select(Group.group_name)).all() if name]
    )
    catalogs = [local]
    try:
        catalogs.append(IdentityCatalog.from_bundle(download_stix_bundle()))
    except (OSError, ValueError) as exc:
        print(f"no ATT&CK bundle, its names will not resolve: {exc}", file=sys.stderr)
    galaxy = load_json_feed(FEEDS_BY_NAME["misp-galaxy-threat-actor"])
    if galaxy is not None:
        catalogs.append(IdentityCatalog.from_misp_galaxy(galaxy))
    naming = load_json_feed(FEEDS_BY_NAME["microsoft-actor-naming"])
    if naming is not None:
        catalogs.append(IdentityCatalog.from_microsoft_mapping(naming))
    return IdentityCatalog.merged(*catalogs)


def _report(args) -> int:
    """One article's analysis in the shape the sources prescribe.

    Costs nothing and calls nothing: the report is a projection of what the
    eight states already wrote. That is also why it can be printed as often as
    anyone likes while the form is being argued about.
    """
    factory = _session_factory()
    with factory() as session:
        article = session.get(Article, args.article)
        if article is None:
            print(f"no such article: {args.article}", file=sys.stderr)
            return 1
        rows = {
            row.state: (row.raw_output_json or {}).get(OUTPUT_KEY) or {}
            for row in session.scalars(
                select(ArticleAnalysisRun).where(
                    ArticleAnalysisRun.article_id == article.id,
                    ArticleAnalysisRun.status == "ok",
                )
            )
        }
        if "narrative" not in rows:
            print(f"article {article.id} has no narrative: nothing to report", file=sys.stderr)
            return 1
        source = session.get(ArticleSource, article.source_id)
        text = report_module.build(
            article_title=article.title or "",
            narrative=rows.get("narrative", {}),
            sketch=rows.get("adversary_sketch", {}),
            source_name=(source.name if source else ""),
            source_url=article.url or "",
            published=str(article.published_at or "")[:10],
            catalog=_identity_catalog(session),
        ).to_markdown()

    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"written to {args.out}")
    else:
        print(text)
    return 0


def _gate(args) -> int:
    """Run the confidence gate over every finished analysis and report the shape.

    No LLM calls: the gate is arithmetic over rows the machine already wrote.
    That is what makes recalibration cheap enough to actually do, which is the
    whole of roadmap criterion 1, and it is why this can be re-run after every
    change to a threshold or a grade map without spending anything.
    """
    factory = _session_factory()
    with factory() as session:
        finished = list(
            session.scalars(
                select(Article)
                .join(ArticleAnalysisRun, ArticleAnalysisRun.article_id == Article.id)
                .where(
                    ArticleAnalysisRun.state == "verify",
                    ArticleAnalysisRun.status == "ok",
                )
                .order_by(Article.id)
                .limit(args.limit)
            )
        )
        print(f"\ngating {len(finished)} analysed articles\n")

        for article in finished:
            outcome = run_gate(session, article, local_run=args.local)
            if outcome.skipped_because:
                print(f"  article {article.id}: skipped, {outcome.skipped_because}")
        session.commit()

        rows = session.execute(
            select(
                StagedFinding.finding_kind,
                StagedFinding.decision,
                func.count(StagedFinding.id),
                func.avg(StagedFinding.score_raw),
                func.avg(StagedFinding.score_total),
            ).group_by(StagedFinding.finding_kind, StagedFinding.decision)
        ).all()

        print(f"{'kind':12} {'decision':10} {'n':>5} {'mean raw':>10} {'mean total':>11}")
        for kind, decision, count, raw, total in rows:
            print(f"{kind:12} {decision:10} {count:5} {raw:10.3f} {total:11.3f}")

        print("\n--- why the staged ones staged ---")
        reasons = session.execute(
            select(StagedFinding.notes, func.count(StagedFinding.id))
            .where(StagedFinding.decision == "staged")
            .group_by(StagedFinding.notes)
            .order_by(func.count(StagedFinding.id).desc())
            .limit(8)
        ).all()
        for note, count in reasons:
            print(f"  {count:4}  {note}")

        print("\n--- can each category be cleared at all? ---")
        for entry in reachability(local_run=args.local):
            mark = "" if entry.reachable else "  <-- CLOSED BY ARITHMETIC"
            print(
                f"  {entry.kind.value:12} floor {entry.floor:.2f}  "
                f"ceiling {entry.ceiling:.3f}{mark}"
            )

        print("\n--- the two axes as assigned ---")
        for axis in ("source_grade", "info_grade"):
            column = getattr(StagedFinding, axis)
            spread = session.execute(
                select(column, func.count(StagedFinding.id)).group_by(column).order_by(column)
            ).all()
            print(f"  {axis:14} " + "  ".join(f"{grade}={count}" for grade, count in spread))
    return 0


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    sweep = sub.add_parser("sweep", help="recover article bodies (no LLM calls)")
    sweep.add_argument("--limit", type=int, default=None, help="stop after N articles")
    sweep.add_argument("--passes", type=int, default=3, help="retry rounds for transport failures")
    sweep.set_defaults(func=_sweep)

    analyse = sub.add_parser("analyse", help="run the extraction machine over a stratified sample")
    analyse.add_argument("--per-source", type=int, default=10, help="articles per feed")
    analyse.add_argument(
        "--article",
        type=int,
        action="append",
        default=[],
        help="analyse these article ids instead of a stratified sample",
    )
    analyse.add_argument("--dry-run", action="store_true", help="show the sample, call nothing")
    analyse.set_defaults(func=_analyse)

    style = sub.add_parser("style", help="score stored summaries against the house style")
    style.add_argument(
        "--detail", type=int, default=0, help="show the N worst summaries per prompt version"
    )
    style.set_defaults(func=_style)

    restyle = sub.add_parser(
        "restyle", help="re-run the prose states of already-analysed articles (~3 calls each)"
    )
    restyle.add_argument("--limit", type=int, default=5, help="how many articles to restyle")
    restyle.set_defaults(func=_restyle)

    report = sub.add_parser("report", help="assemble one article's report (no LLM calls)")
    report.add_argument("article", type=int, help="article id")
    report.add_argument("--out", default="", help="write to this file instead of the screen")
    report.set_defaults(func=_report)

    gate = sub.add_parser("gate", help="score every finished analysis (no LLM calls)")
    gate.add_argument("--limit", type=int, default=1000, help="articles to gate")
    gate.add_argument("--local", action="store_true", help="apply the local-model threshold lift")
    gate.set_defaults(func=_gate)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
