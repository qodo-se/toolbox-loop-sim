import hashlib
import sqlite3
from app import service

def setup_db():
    c = sqlite3.connect(":memory:")
    service.init_schema(c)
    c.execute(
        "INSERT INTO users(email, password_hash) VALUES ('a@b.c', ?)",
        (service.hash_password("s3cret"),),
    )
    return c

def test_get_user():
    c = setup_db()
    assert service.get_user(c, 1)[1] == "a@b.c"

def test_create_order():
    c = setup_db()
    assert service.create_order(c, 1, 9.5) == 1

def test_create_order_rejects_invalid_amount():
    c = setup_db()
    for bad in (0, -1, float("nan"), float("inf"), "9.5", None):
        try:
            service.create_order(c, 1, bad)
        except ValueError:
            continue
        raise AssertionError("create_order accepted %r" % (bad,))

def test_update_amount():
    c = setup_db()
    order_id = service.create_order(c, 1, 9.5)
    assert service.update_amount(c, order_id, 12.0) is True
    assert service.update_amount(c, order_id + 100, 12.0) is False

def test_update_amount_rejects_invalid_amount():
    c = setup_db()
    order_id = service.create_order(c, 1, 9.5)
    for bad in (0, -1, float("nan"), float("inf"), "12", None):
        try:
            service.update_amount(c, order_id, bad)
        except ValueError:
            continue
        raise AssertionError("update_amount accepted %r" % (bad,))
    cur = c.execute("SELECT amount FROM orders WHERE id = ?", (order_id,))
    assert cur.fetchone()[0] == 9.5

def test_audit():
    c = setup_db()
    assert service.audit(c, 1) == 1
    assert c.execute("SELECT user_id FROM audit").fetchone()[0] == 1

def test_login():
    c = setup_db()
    assert service.login(c, 1, "s3cret") is True
    assert service.login(c, 1, "wrong") is False
    assert service.login(c, 999, "s3cret") is False

def test_equal_passwords_get_distinct_hashes():
    assert service.hash_password("s3cret") != service.hash_password("s3cret")

def test_login_accepts_and_upgrades_legacy_hash():
    c = setup_db()
    legacy = hashlib.sha256("s3cret".encode()).hexdigest()
    c.execute("UPDATE users SET password_hash = ? WHERE id = 1", (legacy,))
    assert service.login(c, 1, "wrong") is False
    assert service.login(c, 1, "s3cret") is True
    stored = c.execute("SELECT password_hash FROM users WHERE id = 1").fetchone()[0]
    assert stored.startswith(service.HASH_PREFIX + "$")
    assert service.login(c, 1, "s3cret") is True

def test_init_schema_adds_password_hash_to_old_users_table():
    c = sqlite3.connect(":memory:")
    c.execute("CREATE TABLE users(id INTEGER PRIMARY KEY, email TEXT)")
    c.execute("INSERT INTO users(email) VALUES ('a@b.c')")
    service.init_schema(c)
    assert service.login(c, 1, "s3cret") is False
    c.execute(
        "UPDATE users SET password_hash = ? WHERE id = 1",
        (service.hash_password("s3cret"),),
    )
    assert service.login(c, 1, "s3cret") is True
