"""stored likelihood terms move to the first row of the ICD 203 table

The adversary sketch's `likelihood` field offered "remote" at the bottom of the
scale and "nearly certain" at the top. Both come from the second row of the
ICD 203 table, while the five terms between them come from the first row: the
scale mixed two vocabularies. The enum now uses the first row throughout,
"almost no chance" and "almost certain".

The value lives inside `article_analysis_runs.raw_output_json`, so a sketch
stored before the change would no longer validate against its own schema when
the machine rehydrates it, and a resumed article would re-run a state that had
already been paid for. This rewrites the two terms in place; nothing else in
the stored output is touched.

Revision ID: 0022
Revises: 0021
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0022"
down_revision: str | Sequence[str] | None = "0021"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

#: Old term -> new term. The downgrade applies the inverse.
RENAMES = {"remote": "almost no chance", "nearly certain": "almost certain"}

_runs = sa.table(
    "article_analysis_runs",
    sa.column("id", sa.Integer),
    sa.column("state", sa.String),
    sa.column("raw_output_json", sa.JSON),
)


def _rewrite(mapping: dict[str, str]) -> None:
    """Rename the stored sketch likelihood wherever it matches `mapping`.

    Row by row in Python rather than a JSON operator in SQL, because the
    development database is SQLite and production is PostgreSQL, and the
    sketches are few.
    """
    connection = op.get_bind()
    rows = connection.execute(
        sa.select(_runs.c.id, _runs.c.raw_output_json).where(_runs.c.state == "adversary_sketch")
    ).all()
    for row in rows:
        stored = row.raw_output_json
        if not isinstance(stored, dict):
            continue
        output = stored.get("output")
        if not isinstance(output, dict) or output.get("likelihood") not in mapping:
            continue
        updated = dict(stored)
        updated["output"] = {**output, "likelihood": mapping[output["likelihood"]]}
        connection.execute(
            _runs.update().where(_runs.c.id == row.id).values(raw_output_json=updated)
        )


def upgrade() -> None:
    """Upgrade schema."""
    _rewrite(RENAMES)


def downgrade() -> None:
    """Downgrade schema."""
    _rewrite({new: old for old, new in RENAMES.items()})
