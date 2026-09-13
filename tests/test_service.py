import sqlite3
import pytest
from app import service

def setup_db():
    c = sqlite3.connect(":memory:")
    c.execute("CREATE TABLE users(id INTEGER PRIMARY KEY, email TEXT, password_hash TEXT)")
    c.execute("CREATE TABLE orders(id INTEGER PRIMARY KEY, user_id INT, amount REAL)")
    c.execute("INSERT INTO users(email) VALUES ('a@b.c')")
    return c

def test_get_user():
    c = setup_db()
    assert service.get_user(c, 1)[1] == "a@b.c"

def test_create_order():
    c = setup_db()
    assert service.create_order(c, 1, 9.5) == 1

def test_update_amount():
    c = setup_db()
    order_id = service.create_order(c, 1, 9.5)
    assert service.update_amount(c, order_id, 12.0) is True
    assert service.update_amount(c, order_id + 1, 12.0) is False

def test_amount_rejects_nan():
    c = setup_db()
    order_id = service.create_order(c, 1, 9.5)
    with pytest.raises(ValueError):
        service.create_order(c, 1, float('nan'))
    with pytest.raises(ValueError):
        service.update_amount(c, order_id, float('nan'))

def test_hash_password_salts_each_call():
    assert service.hash_password("pw") != service.hash_password("pw")

def test_login_current_hash():
    c = setup_db()
    c.execute("UPDATE users SET password_hash = ? WHERE id = 1", (service.hash_password("pw"),))
    assert service.login(c, 1, "pw") is True
    assert service.login(c, 1, "wrong") is False

def test_login_legacy_hash_upgrades():
    c = setup_db()
    c.execute("UPDATE users SET password_hash = ? WHERE id = 1", (service.legacy_hash("pw"),))
    assert service.login(c, 1, "pw") is True
    stored = c.execute("SELECT password_hash FROM users WHERE id = 1").fetchone()[0]
    assert stored.startswith("pbkdf2_sha256$")
    assert service.login(c, 1, "pw") is True

def test_login_without_password_set():
    c = setup_db()
    assert service.login(c, 1, "pw") is False

def test_safe_commit_reports_failure():
    c = setup_db()
    assert service.safe_commit(c) is True
    c.close()
    assert service.safe_commit(c) is False
