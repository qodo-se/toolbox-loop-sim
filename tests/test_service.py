import sqlite3
import pytest
from app import service

def setup_db():
    c = sqlite3.connect(":memory:")
    c.execute("CREATE TABLE users(id INTEGER PRIMARY KEY, email TEXT, password_hash TEXT)")
    c.execute("CREATE TABLE orders(id INTEGER PRIMARY KEY, user_id INT, amount REAL)")
    c.execute(
        "INSERT INTO users(email, password_hash) VALUES ('a@b.c', ?)",
        (service.hash_password("hunter2"),),
    )
    return c

def test_get_user():
    c = setup_db()
    assert service.get_user(c, 1)[1] == "a@b.c"

def test_create_order():
    c = setup_db()
    assert service.create_order(c, 1, 9.5) == 1

def test_create_order_rejects_nan():
    c = setup_db()
    with pytest.raises(ValueError):
        service.create_order(c, 1, float('nan'))

def test_update_amount():
    c = setup_db()
    oid = service.create_order(c, 1, 9.5)
    assert service.update_amount(c, oid, 12.0) is True
    assert c.execute("SELECT amount FROM orders WHERE id = ?", (oid,)).fetchone()[0] == 12.0

def test_update_amount_rejects_non_finite():
    c = setup_db()
    oid = service.create_order(c, 1, 9.5)
    for bad in (float('nan'), float('inf'), 0, -1):
        with pytest.raises(ValueError):
            service.update_amount(c, oid, bad)
    assert c.execute("SELECT amount FROM orders WHERE id = ?", (oid,)).fetchone()[0] == 9.5

def test_update_amount_missing_order():
    c = setup_db()
    with pytest.raises(LookupError):
        service.update_amount(c, 999, 5.0)

def test_hash_password_is_salted_per_call():
    assert service.hash_password("hunter2") != service.hash_password("hunter2")

def test_verify_password():
    record = service.hash_password("hunter2")
    assert service.verify_password("hunter2", record)
    assert not service.verify_password("wrong", record)
    assert not service.verify_password("hunter2", "not-a-record")

def test_legacy_hash_matches_hash_password_rules():
    assert service.verify_password("hunter2", service.legacy_hash("hunter2"))

def test_login():
    c = setup_db()
    assert service.login(c, 1, "hunter2")
    assert not service.login(c, 1, "wrong")
    assert not service.login(c, 999, "hunter2")

def test_safe_commit():
    c = setup_db()
    c.execute("INSERT INTO orders(user_id, amount) VALUES (1, 5.0)")
    assert service.safe_commit(c) is True

def test_safe_commit_reports_failure():
    class FailingConn:
        def __init__(self):
            self.rolled_back = False

        def commit(self):
            raise sqlite3.OperationalError("disk I/O error")

        def rollback(self):
            self.rolled_back = True

    conn = FailingConn()
    assert service.safe_commit(conn) is False
    assert conn.rolled_back
