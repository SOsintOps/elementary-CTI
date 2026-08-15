"""add staged_findings and article_sources.reliability_grade

Phase 5 step 2. Two changes, one purpose: give the confidence gate somewhere to
record why it decided what it decided.

`staged_findings` holds a row per finding whatever the outcome — `auto`,
`staged` or `rejected` — because roadmap criterion 1 asks for a gate that can
be recalibrated, and a table of only the rejected cannot say whether the
threshold is too high. `score_raw` is kept beside `score_total` so a new
grade→factor map can be applied to old rows without re-running anything, which
is the whole of what recalibrable means here.

`reliability_grade` turns the source's standing from a float nobody can account
for into a letter with written criteria behind it: UNODC, *Criminal
Intelligence: Manual for Analysts*, chapter 4, the 6x6 scale. `trust_weight`
stays and becomes derived, so nothing that reads it today breaks. The twelve
live weights convert mechanically — 0.9 to A, 0.85 and 0.8 to B, 0.6 to C — and
the conversion runs here as data rather than by hand in a console.

Applied to the development SQLite only. Production stays at 0013 by decision,
and migrating it is a separate, deliberate step.

Revision ID: 0020
Revises: 0019
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0020"
down_revision: str | Sequence[str] | None = "0019"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

#: The mechanical conversion of the twelve weights in the field, highest band
#: first: the first threshold a weight clears wins. The live values are 0.9,
#: 0.85, 0.8 and 0.6, so only the first three bands are exercised today; the
#: rest are there so a weight nobody anticipated still lands somewhere
#: defensible instead of failing the migration.
#:
#: F is deliberately not reachable from a number. It means the source cannot be
#: judged, which is a statement about missing knowledge, and a weight of 0.1 is
#: knowledge — poor knowledge, graded E.
WEIGHT_TO_GRADE = ((0.9, "A"), (0.8, "B"), (0.6, "C"), (0.4, "D"))
LOWEST_GRADE = "E"


def grade_for(weight: float | None) -> str:
    """The band a legacy trust weight falls in. No weight at all means F."""
    if weight is None:
        return "F"
    for threshold, grade in WEIGHT_TO_GRADE:
        if weight >= threshold:
            return grade
    return LOWEST_GRADE


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "staged_findings",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("article_id", sa.Integer(), nullable=False),
        sa.Column("run_id", sa.Integer(), nullable=True),
        sa.Column("finding_kind", sa.String(length=32), nullable=False),
        sa.Column("target_table", sa.String(length=64), nullable=True),
        sa.Column("target_row_id", sa.Integer(), nullable=True),
        sa.Column("payload_json", sa.JSON(), nullable=True),
        # Nullable on purpose: a component nobody asked for is not a zero.
        sa.Column("anchor_ratio", sa.Float(), nullable=True),
        sa.Column("critic_agreement", sa.Float(), nullable=True),
        sa.Column("schema_completeness", sa.Float(), nullable=True),
        sa.Column("self_assessed", sa.Float(), nullable=True),
        sa.Column("score_raw", sa.Float(), nullable=False),
        sa.Column("source_grade", sa.String(length=1), nullable=False),
        sa.Column("source_factor_applied", sa.Float(), nullable=False),
        sa.Column("info_grade", sa.String(length=1), nullable=False),
        sa.Column("info_factor_applied", sa.Float(), nullable=False),
        sa.Column("threshold_applied", sa.Float(), nullable=False),
        sa.Column("score_total", sa.Float(), nullable=False),
        sa.Column("decision", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="pending"),
        sa.Column("tlp", sa.String(length=16), nullable=False),
        sa.Column("model_name", sa.String(length=100), nullable=True),
        sa.Column("prompt_version", sa.String(length=50), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reviewed_by", sa.String(length=64), nullable=True),
        sa.Column("notes", sa.String(length=2048), nullable=True),
        sa.ForeignKeyConstraint(["article_id"], ["articles.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["run_id"], ["article_analysis_runs.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_staged_status", "staged_findings", ["status", "created_at"])
    op.create_index("ix_staged_article", "staged_findings", ["article_id"])
    op.create_index("ix_staged_target", "staged_findings", ["finding_kind", "target_row_id"])

    # Default D, "doubtful": an unrated feed is not a good one, and the seed
    # will set the real grades. F is reserved for cannot-be-judged, which the
    # gate treats as a reason to stage rather than a low score.
    op.add_column(
        "article_sources",
        sa.Column("reliability_grade", sa.String(length=1), nullable=False, server_default="D"),
    )

    sources = sa.table(
        "article_sources",
        sa.column("id", sa.Integer),
        sa.column("trust_weight", sa.Float),
        sa.column("reliability_grade", sa.String),
    )
    connection = op.get_bind()
    # Row by row rather than one UPDATE per band: banded updates have to exclude
    # the rows the earlier bands already claimed, and the sentinel that would
    # mark them is the same letter D that one of the bands legitimately assigns.
    # A dozen rows is not worth that trap.
    for row in connection.execute(sa.select(sources.c.id, sources.c.trust_weight)):
        connection.execute(
            sources.update()
            .where(sources.c.id == row.id)
            .values(reliability_grade=grade_for(row.trust_weight))
        )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column("article_sources", "reliability_grade")
    op.drop_index("ix_staged_target", table_name="staged_findings")
    op.drop_index("ix_staged_article", table_name="staged_findings")
    op.drop_index("ix_staged_status", table_name="staged_findings")
    op.drop_table("staged_findings")
