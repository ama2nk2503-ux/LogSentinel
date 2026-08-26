"""Shared fixtures: isolated SQLite DB per test session."""

import pytest

from core.config import settings
from core.storage import _local, init_db


@pytest.fixture(scope="session", autouse=True)
def isolated_db(tmp_path_factory):
    db_file = tmp_path_factory.mktemp("db") / "test.db"
    settings.db_path = db_file
    if getattr(_local, "conn", None) is not None:
        _local.conn.close()
        _local.conn = None
    init_db()
    yield db_file
    if getattr(_local, "conn", None) is not None:
        _local.conn.close()
        _local.conn = None
