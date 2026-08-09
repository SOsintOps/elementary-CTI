# "A man's brain originally is like a little empty attic." — Sherlock, Elementary
from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


class Base(DeclarativeBase):
    pass


# One engine (and connection pool) per database URL for the process lifetime.
_engines: dict[str, Engine] = {}


# "A mind, once stretched by a new idea, never regains its dimensions." — Sherlock
def get_engine(db_url: str) -> Engine:
    engine = _engines.get(db_url)
    if engine is None:
        engine = create_engine(db_url, echo=False)
        if db_url.startswith("sqlite"):
            event.listen(engine, "connect", _enable_sqlite_wal)
        _engines[db_url] = engine
    return engine


def _enable_sqlite_wal(dbapi_connection, connection_record) -> None:
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    # SQLite doesn't enforce FOREIGN KEY constraints (incl. ON DELETE CASCADE)
    # unless asked — parity with PostgreSQL (REVIEW follow-up)
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


def dispose_engines() -> None:
    """Dispose all cached engines and clear the cache (used by tests)."""
    for engine in _engines.values():
        engine.dispose()
    _engines.clear()


def get_session_factory(db_url: str) -> sessionmaker[Session]:
    engine = get_engine(db_url)
    return sessionmaker(bind=engine)


def create_all(db_url: str) -> None:
    engine = get_engine(db_url)
    Base.metadata.create_all(engine)
