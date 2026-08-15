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
        "article_iocs",
        "article_ttps",
        "staged_findings",
    ]:
        assert t in tables, f"Missing table after upgrade head: {t}"
    engine.dispose()

    # --- Downgrade one step at a time (0019 and 0018 included) ---
    n_steps = 16
    for step in range(n_steps):
        r = subprocess.run(
            ["uv", "run", "alembic", "downgrade", "-1"],
            cwd=REPO_ROOT,
            env=env,
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0, f"Downgrade step {step + 1}/{n_steps} failed:\n{r.stderr}"


def test_the_new_findings_tables_match_their_models(tmp_path):
    """The migration is hand-written; the models are what the code queries.

    Drift between the two is the failure this project has already been bitten
    by — `create_all` runs at container start and does *not* alter an existing
    table, so a column the model has and the migration lacks fails only in
    production, and only on the query that needs it.
    """
    from sqlalchemy import inspect as sa_inspect

    from pestilentia.models.base import Base

    db = tmp_path / "drift.db"
    env = {**os.environ, "PEST_DB_URL": f"sqlite:///{db}"}
    r = subprocess.run(
        ["uv", "run", "alembic", "upgrade", "head"],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
    )
    assert r.returncode == 0, r.stderr

    engine = create_engine(f"sqlite:///{db}")
    inspector = sa_inspect(engine)
    for name in ("article_iocs", "article_ttps", "staged_findings", "article_sources"):
        migrated = {
            column["name"]: bool(column["nullable"]) for column in inspector.get_columns(name)
        }
        modelled = {
            column.name: bool(column.nullable) for column in Base.metadata.tables[name].columns
        }
        assert migrated == modelled, f"{name}: migration and model disagree"
    engine.dispose()


# --- 0020: the source grade replaces the unexplained float --------------------


def test_the_legacy_trust_weights_convert_to_the_grades_they_were_chosen_for():
    """The twelve weights in the field map onto four letters, and the mapping
    has to be the one the plan agreed: 0.9 is A, 0.85 and 0.8 are B, 0.6 is C.

    Written as a unit test on the function rather than as an assertion after a
    migration run because the conversion is the part a later hand will change,
    and it should fail here rather than after an upgrade that cannot be undone
    without losing the grades an analyst has since tuned.
    """
    grade_for = _load_0020().grade_for

    assert grade_for(0.9) == "A"
    assert grade_for(0.85) == "B"
    assert grade_for(0.8) == "B"
    assert grade_for(0.6) == "C"
    # The default nobody has touched: not good, not ungradeable.
    assert grade_for(0.5) == "D"
    assert grade_for(0.1) == "E"


def test_a_source_with_no_weight_at_all_is_ungradeable_rather_than_bad():
    """F means the source cannot be judged, and the gate stages what it cannot
    judge instead of scoring it low. A missing weight is missing knowledge; a
    weight of 0.1 is knowledge, and poor."""
    grade_for = _load_0020().grade_for

    assert grade_for(None) == "F"
    assert grade_for(0.0) == "E"


def _load_0020():
    """Import the revision file by path — the versions directory is not a package."""
    import importlib.util

    path = REPO_ROOT / "alembic" / "versions" / "0020_add_staged_findings.py"
    spec = importlib.util.spec_from_file_location("migration_0020", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
