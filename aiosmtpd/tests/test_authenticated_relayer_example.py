# Copyright 2014-2021 The aiosmtpd Developers
# SPDX-License-Identifier: Apache-2.0

import sqlite3
from contextlib import closing

import pytest

from examples.authenticated_relayer.make_user_db import make_user_db
from examples.authenticated_relayer.server import Authenticator

from aiosmtpd.smtp import LoginPassword


def test_authenticator_uses_stored_salt(tmp_path):
    auth_db = tmp_path / "mail.db"
    make_user_db(auth_db, {"alice": b"correct password"})
    authenticator = Authenticator(auth_db)

    accepted = authenticator(
        None, None, None, "PLAIN", LoginPassword(b"alice", b"correct password")
    )
    wrong_password = authenticator(
        None, None, None, "PLAIN", LoginPassword(b"alice", b"wrong password")
    )
    unknown_user = authenticator(
        None, None, None, "PLAIN", LoginPassword(b"bob", b"correct password")
    )
    invalid_username = authenticator(
        None, None, None, "PLAIN", LoginPassword(b"\xff", b"correct password")
    )

    assert accepted.success
    assert not wrong_password.success
    assert not unknown_user.success
    assert not invalid_username.success


def test_authenticator_rejects_legacy_database(tmp_path):
    auth_db = tmp_path / "mail.db"
    with closing(sqlite3.connect(auth_db)) as conn:
        conn.execute("CREATE TABLE userauth (username text, hashpass text)")
        conn.commit()

    with pytest.raises(RuntimeError, match="recreate it with make_user_db.py"):
        Authenticator(auth_db)
