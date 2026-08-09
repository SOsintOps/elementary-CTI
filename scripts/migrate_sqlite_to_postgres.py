#!/usr/bin/env python
# "When you have eliminated the impossible..." — Sherlock Holmes, Elementary
"""Copy all rows from a SQLite database into a target database (Postgres).

The target schema must already exist (run ``alembic upgrade head`` against the
target first). Tables are copied in foreign-key-safe order; only columns present
in BOTH databases are transferred, so a newer ORM schema with extra columns/tables
(e.g. the AI tables absent from an older SQLite seed) migrates cleanly.

Usage:
    uv run python scripts/migrate_sqlite_to_postgres.py \
        --source sqlite:///elementaryctiDB.db \
        --target postgresql://user:pass@localhost:5432/pestilentia

Add --wipe to TRUNCATE target tables first (safe re-runs). Without it, the target
tables must be empty or the load will hit unique/PK conflicts.
"""

from __future__ import annotations

import argparse
import sys

from sqlalchemy import MetaData, create_engine, insert, select, text
from sqlalchemy.engine import Engine

import pestilentia.models.tables  # noqa: F401  (registers all tables)

# Importing the ORM registers every table on Base.metadata in FK-dependency order.
from pestilentia.models.base import Base

BATCH = 1000


def _reflect_source(engine: Engine) -> MetaData:
    md = MetaData()
    md.reflect(bind=engine)
    return md


def _copy_table(src: Engine, dst: Engine, table, src_md: MetaData) -> int:
    name = table.name
    src_table = src_md.tables.get(name)
    if src_table is None:
        return -1  # table absent in source (e.g. AI tables in an old seed)

    shared = [c.name for c in table.columns if c.name in src_table.columns]
    if not shared:
        return -1

    rows_copied = 0
    with src.connect() as sconn, dst.begin() as dconn:
        result = sconn.execution_options(stream_results=True).execute(
            select(*[src_table.c[col] for col in shared])
        )
        batch: list[dict] = []
        for row in result:
            batch.append(dict(zip(shared, row, strict=True)))
            if len(batch) >= BATCH:
                dconn.execute(insert(table), batch)
                rows_copied += len(batch)
                batch.clear()
        if batch:
            dconn.execute(insert(table), batch)
            rows_copied += len(batch)
    return rows_copied


def _reset_sequences(dst: Engine) -> None:
    """Postgres only: bump each id sequence past the max migrated id."""
    if dst.dialect.name != "postgresql":
        return
    with dst.begin() as conn:
        for table in Base.metadata.sorted_tables:
            if "id" not in table.columns:
                continue
            conn.execute(
                text(
                    "SELECT setval("
                    "  pg_get_serial_sequence(:tbl, 'id'),"
                    "  COALESCE((SELECT MAX(id) FROM " + table.name + "), 1),"
                    "  (SELECT MAX(id) IS NOT NULL FROM " + table.name + ")"
                    ")"
                ).bindparams(tbl=table.name)
            )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--source", required=True, help="source SQLAlchemy URL (SQLite)")
    ap.add_argument("--target", required=True, help="target SQLAlchemy URL (Postgres)")
    ap.add_argument("--wipe", action="store_true", help="TRUNCATE target tables first")
    args = ap.parse_args()

    src = create_engine(args.source)
    dst = create_engine(args.target)
    src_md = _reflect_source(src)

    ordered = Base.metadata.sorted_tables

    if args.wipe:
        with dst.begin() as conn:
            for table in reversed(ordered):
                if dst.dialect.name == "postgresql":
                    conn.execute(text(f'TRUNCATE TABLE "{table.name}" RESTART IDENTITY CASCADE'))
                else:
                    conn.execute(text(f'DELETE FROM "{table.name}"'))
        print("Target tables wiped.")

    total = 0
    for table in ordered:
        n = _copy_table(src, dst, table, src_md)
        if n < 0:
            print(f"  - {table.name:<28} (skipped — not in source)")
        else:
            print(f"  + {table.name:<28} {n:>8} rows")
            total += n

    _reset_sequences(dst)
    print(f"\nDone. {total} rows copied across {len(ordered)} tables.")
    print("Sequences reset." if dst.dialect.name == "postgresql" else "")
    return 0


if __name__ == "__main__":
    sys.exit(main())
