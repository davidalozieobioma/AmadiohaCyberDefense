"""Database tests aligned with current database API."""

from pathlib import Path
import os
import tempfile

from amadioha import database


def _setup_temp_db():
    fd, path = tempfile.mkstemp()
    os.close(fd)
    database.DB_PATH = Path(path)
    database.init_db()
    return path


def _cleanup_temp_db(path):
    try:
        os.remove(path)
    except FileNotFoundError:
        pass


def test_create_and_get_user():
    db_path = _setup_temp_db()
    try:
        user_id = database.create_user(
            username="testuser",
            password_hash="hashed_password",
            email="test@example.com",
            role="user",
        )
        assert user_id > 0

        user_by_name = database.get_user_by_username("testuser")
        assert user_by_name is not None
        assert user_by_name["email"] == "test@example.com"

        user_by_id = database.get_user_by_id(user_id)
        assert user_by_id is not None
        assert user_by_id["username"] == "testuser"
    finally:
        _cleanup_temp_db(db_path)


def test_count_and_get_all_users():
    db_path = _setup_temp_db()
    try:
        database.create_user(
            username="user1",
            password_hash="hash1",
            email="user1@example.com",
            role="user",
        )
        database.create_user(
            username="user2",
            password_hash="hash2",
            email="user2@example.com",
            role="admin",
        )

        assert database.count_users() == 2
        users = database.get_all_users()
        assert len(users) == 2
    finally:
        _cleanup_temp_db(db_path)


def test_update_and_delete_user():
    db_path = _setup_temp_db()
    try:
        user_id = database.create_user(
            username="user3",
            password_hash="hash3",
            email="user3@example.com",
            role="user",
        )

        updated = database.update_user_role(user_id, "admin")
        assert updated is True

        user = database.get_user_by_id(user_id)
        assert user is not None
        assert user["role"] == "admin"

        deleted = database.delete_user(user_id)
        assert deleted is True
        assert database.get_user_by_id(user_id) is None
    finally:
        _cleanup_temp_db(db_path)


def test_log_and_get_activity_logs():
    db_path = _setup_temp_db()
    try:
        user_id = database.create_user(
            username="user4",
            password_hash="hash4",
            email="user4@example.com",
            role="user",
        )

        log_id = database.log_activity(
            user_id=user_id,
            action="login",
            details="user login",
            ip_address="127.0.0.1",
        )
        assert log_id > 0

        logs = database.get_activity_logs(limit=10)
        assert len(logs) >= 1
        assert any(log["action"] == "login" for log in logs)
    finally:
        _cleanup_temp_db(db_path)
