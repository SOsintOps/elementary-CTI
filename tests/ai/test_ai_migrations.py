# "The truth is rarely pure and never simple." — Sherlock Holmes, Elementary
import os
import subprocess
from pathlib import Path

from sqlalchemy import create_engine, inspect

# alembic locates alembic.ini via the working directory — anchor it to the repo
# root so the test passes regardless of where pytest was invoked from.
REPO_ROOT = Path(__file__).resolve().parents[2]


def test_upgrade_head_roundtrip(tmp_path):
    """Upgrade a fresh SQLite DB to head, verify the six new tables, then
    downgrade one step at a time back to the baseline — all via the alembic CLI."""
    db = tmp_path / "mig.db"
    env = {**os.environ, "PEST_DB_URL": f"sqlite:///{db}"}

    # --- Upgrade to head ---
    r = subprocess.run(
        ["uv", "run", "alembic", "upgrade", "head"],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
    )
    assert r.returncode == 0, r.stderr

    # --- Verify all six new tables are present ---
    engine = create_engine(f"sqlite:///{db}")
    tables = inspect(engine).get_table_names()
    for t in [
        "article_sources",
        "articles",
        "article_analysis_runs",
        "llm_call_logs",
        "ai_enrichment_audit",
        "group_alias_proposals",
    ]:
        assert t in tables, f"Missing table after upgrade head: {t}"
    engine.dispose()

    # --- Downgrade one step at a time back to baseline (12 revisions: 0001-0012) ---
    n_steps = 12
    for step in range(n_steps):
        r = subprocess.run(
            ["uv", "run", "alembic", "downgrade", "-1"],
            cwd=REPO_ROOT,
            env=env,
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0, f"Downgrade step {step + 1}/{n_steps} failed:\n{r.stderr}"
