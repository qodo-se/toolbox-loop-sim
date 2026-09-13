import sqlite3
from app import service

def setup_db():
    c = sqlite3.connect(":memory:")
    c.execute("CREATE TABLE users(id INTEGER PRIMARY KEY, email TEXT, password_hash TEXT)")
    c.execute("CREATE TABLE orders(id INTEGER PRIMARY KEY, user_id INT, amount REAL)")
    c.execute("CREATE TABLE audit(id INTEGER PRIMARY KEY, user_id INT)")
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

def test_update_amount_missing_order():
    c = setup_db()
    assert service.update_amount(c, 999, 12.0) is False

def test_update_amount_rejects_nan():
    c = setup_db()
    order_id = service.create_order(c, 1, 9.5)
    try:
        service.update_amount(c, order_id, float('nan'))
        raise AssertionError("nan amount should be rejected")
    except ValueError:
        pass

def test_audit():
    c = setup_db()
    assert service.audit(c, 1) == 1

def test_safe_commit():
    c = setup_db()
    assert service.safe_commit(c) is True
    c.close()
    assert service.safe_commit(c) is False

def test_login():
    c = setup_db()
    c.execute("UPDATE users SET password_hash = ? WHERE id = 1",
              (service.hash_password("s3cret"),))
    assert service.login(c, 1, "s3cret") is True
    assert service.login(c, 1, "wrong") is False
    assert service.login(c, 999, "s3cret") is False

def test_login_legacy_hash():
    import hashlib
    c = setup_db()
    c.execute("UPDATE users SET password_hash = ? WHERE id = 1",
              (hashlib.sha256(b"s3cret").hexdigest(),))
    assert service.login(c, 1, "s3cret") is True
    c.execute("UPDATE users SET password_hash = ? WHERE id = 1",
              (hashlib.sha256(b"s3cret").hexdigest(),))
    assert service.login(c, 1, "wrong") is False

def test_login_upgrades_legacy_hash():
    import hashlib
    c = setup_db()
    legacy = hashlib.sha256(b"s3cret").hexdigest()
    c.execute("UPDATE users SET password_hash = ? WHERE id = 1", (legacy,))
    assert service.login(c, 1, "s3cret") is True
    stored = c.execute("SELECT password_hash FROM users WHERE id = 1").fetchone()[0]
    assert stored != legacy
    assert stored.startswith(service.PBKDF2_PREFIX)
    assert service.login(c, 1, "s3cret") is True

def test_verify_password_rejects_out_of_range_iterations():
    huge = "pbkdf2_sha256$%d$00$00" % (2 ** 70)
    assert service.verify_password(huge, "s3cret") is False
    assert service.verify_password("pbkdf2_sha256$0$00$00", "s3cret") is False
    assert service.verify_password("pbkdf2_sha256$-1$00$00", "s3cret") is False
