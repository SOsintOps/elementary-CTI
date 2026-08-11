from datetime import UTC, datetime

import pytest
from sqlalchemy import create_engine, event, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from pestilentia.models import AdminAudit, Base, User, UserActivity
from pestilentia.security import (
    UserRole,
    hash_password,
    needs_rehash,
    role_at_least,
    verify_password,
)


@pytest.fixture
def engine():
    eng = create_engine("sqlite:///:memory:")

    @event.listens_for(eng, "connect")
    def _fk_on(dbapi_conn, _record):
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(eng)
    return eng


# --- password hashing ---


def test_hash_password_is_argon2id_and_verifies():
    h = hash_password("correct horse battery staple")
    assert h.startswith("$argon2id$")
    assert h != "correct horse battery staple"
    assert verify_password(h, "correct horse battery staple")


def test_verify_password_rejects_wrong_password():
    h = hash_password("right")
    assert not verify_password(h, "wrong")


def test_verify_password_never_raises_on_malformed_hash():
    assert not verify_password("not-a-hash", "anything")
    assert not verify_password("", "anything")


def test_two_hashes_of_same_password_differ():
    assert hash_password("pw") != hash_password("pw")  # random salt


def test_fresh_hash_does_not_need_rehash():
    assert not needs_rehash(hash_password("pw"))


# --- role ordering ---


@pytest.mark.parametrize(
    ("role", "minimum", "expected"),
    [
        ("user", "user", True),
        ("user", "analyst", False),
        ("user", "admin", False),
        ("analyst", "user", True),
        ("analyst", "analyst", True),
        ("analyst", "admin", False),
        ("admin", "user", True),
        ("admin", "analyst", True),
        ("admin", "admin", True),
    ],
)
def test_role_matrix(role, minimum, expected):
    assert role_at_least(role, minimum) is expected


def test_unknown_role_is_default_deny():
    assert not role_at_least("superadmin", "user")
    assert not role_at_least("", "user")
    assert not role_at_least("admin", "root")


def test_role_enum_values():
    assert {r.value for r in UserRole} == {"user", "analyst", "admin"}


# --- models ---


def test_user_defaults_and_roundtrip(engine):
    with Session(engine) as s:
        s.add(User(username="alice", password_hash=hash_password("pw")))
        s.commit()
        u = s.execute(select(User)).scalar_one()
        assert u.role == "user"
        assert u.theme == "light"
        assert u.disabled is False
        assert u.created_at is not None
        assert u.last_login_at is None


def test_username_is_unique(engine):
    with Session(engine) as s:
        s.add(User(username="alice", password_hash="x"))
        s.commit()
        s.add(User(username="alice", password_hash="y"))
        with pytest.raises(IntegrityError):
            s.commit()


def test_admin_audit_survives_actor_deletion(engine):
    with Session(engine) as s:
        admin = User(username="root", password_hash="x", role="admin")
        s.add(admin)
        s.commit()
        s.add(
            AdminAudit(
                actor_id=admin.id,
                actor_name="root",
                action="user_create",
                target="bob",
            )
        )
        s.commit()
        s.delete(admin)
        s.commit()
        row = s.execute(select(AdminAudit)).scalar_one()
        assert row.actor_id is None  # FK went NULL
        assert row.actor_name == "root"  # snapshot survives


def test_user_activity_anonymous_row(engine):
    with Session(engine) as s:
        s.add(
            UserActivity(
                kind="access_denied",
                method="GET",
                route="/settings",
                status=401,
                client_ip="203.0.113.7",
            )
        )
        s.commit()
        row = s.execute(select(UserActivity)).scalar_one()
        assert row.actor_id is None and row.actor_name is None
        assert row.kind == "access_denied"
        assert row.ts.replace(tzinfo=UTC) <= datetime.now(UTC)


def test_user_activity_failed_login_records_attempted_username(engine):
    with Session(engine) as s:
        s.add(
            UserActivity(
                kind="login_fail",
                actor_name="alice",  # attempted username, no actor_id match required
                client_ip="203.0.113.7",
                user_agent="curl/8.0",
            )
        )
        s.commit()
        row = s.execute(select(UserActivity)).scalar_one()
        assert row.kind == "login_fail"
        assert row.actor_name == "alice"
        assert row.actor_id is None
