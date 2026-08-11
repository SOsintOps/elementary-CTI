"""Shared web-test helpers for the v0.7 auth era.

Since plan step 4 every non-public route requires a logged-in user, so web
tests authenticate their TestClient. `authenticate` seeds a user row and
mints a valid session cookie directly (the login flow itself is exercised
end-to-end in test_auth_web.py — repeating the POST in every fixture would
only re-test argon2).
"""

import pytest

from pestilentia.models.tables import User
from pestilentia.security import hash_password
from pestilentia.web import sessions


@pytest.fixture
def authenticate():
    def _auth(client, factory, role="user", username="tester"):
        from pestilentia.config import get_settings

        with factory() as s:
            row = s.query(User).filter(User.username == username).one_or_none()
            if row is None:
                row = User(username=username, password_hash=hash_password("test-pw"), role=role)
                s.add(row)
                s.commit()
            uid = row.id
        token = sessions.issue_session(get_settings().secret_key, uid)
        client.cookies.set(sessions.SESSION_COOKIE, token)
        return uid

    return _auth
