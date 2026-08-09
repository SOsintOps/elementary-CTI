# "The game is afoot." — Sherlock Holmes, Elementary
import asyncio

# Ensure ransomware_live registers itself
import pestilentia.clients.ransomware_live  # noqa: F401
from pestilentia.config import get_settings
from pestilentia.logging import setup_logging
from pestilentia.models import create_all, get_session_factory
from pestilentia.pipeline.scheduler import run_scheduler


# "My mind rebels at stagnation." — Sherlock Holmes, Elementary
def main() -> None:
    cfg = get_settings()
    setup_logging(cfg.log_level)

    create_all(cfg.db_url)
    session_factory = get_session_factory(cfg.db_url)

    asyncio.run(
        run_scheduler(
            session_factory,
            interval_seconds=cfg.poll_interval_hours * 3600,
            mitre_interval_seconds=cfg.mitre_enrichment_hours * 3600,
            ransomwhere_interval_seconds=cfg.ransomwhere_enrichment_hours * 3600,
            deepdarkcti_interval_seconds=cfg.deepdarkcti_enrichment_hours * 3600,
            article_interval_seconds=cfg.article_ingest_hours * 3600,
        )
    )


if __name__ == "__main__":
    main()
