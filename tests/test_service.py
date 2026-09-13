import hashlib
import sqlite3
from app import service

def setup_db():
    c = sqlite3.connect(":memory:")
    c.execute("CREATE TABLE users(id INTEGER PRIMARY KEY, email TEXT, password_hash TEXT)")
    c.execute("CREATE TABLE orders(id INTEGER PRIMARY KEY, user_id INT, amount REAL)")
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

def test_login_correct_password():
    c = setup_db()
    assert service.login(c, 1, "s3cret") is True

def test_login_wrong_password():
    c = setup_db()
    assert service.login(c, 1, "nope") is False

def test_login_unknown_user():
    c = setup_db()
    assert service.login(c, 99, "s3cret") is False

def test_hash_password_is_salted():
    first = service.hash_password("s3cret")
    second = service.hash_password("s3cret")
    assert first != second
    assert service.verify_password("s3cret", first) is True
    assert service.verify_password("s3cret", second) is True

def test_verify_password_rejects_malformed_hash():
    assert service.verify_password("s3cret", "") is False
    assert service.verify_password("s3cret", "deadbeef") is False

def test_verify_password_rejects_out_of_range_iterations():
    salt_hex = "00" * 16
    digest_hex = "11" * 32
    for iterations in ("0", "-1", str(service.MAX_PBKDF2_ITERATIONS + 1)):
        stored = "pbkdf2_sha256${}${}${}".format(iterations, salt_hex, digest_hex)
        assert service.verify_password("s3cret", stored) is False

def test_login_accepts_legacy_sha256_hash():
    c = setup_db()
    legacy = hashlib.sha256("s3cret".encode()).hexdigest()
    c.execute("UPDATE users SET password_hash = ? WHERE id = 1", (legacy,))
    assert service.login(c, 1, "nope") is False
    assert service.login(c, 1, "s3cret") is True

def test_login_upgrades_legacy_hash():
    c = setup_db()
    legacy = hashlib.sha256("s3cret".encode()).hexdigest()
    c.execute("UPDATE users SET password_hash = ? WHERE id = 1", (legacy,))
    assert service.login(c, 1, "s3cret") is True
    stored = c.execute("SELECT password_hash FROM users WHERE id = 1").fetchone()[0]
    assert stored.startswith("pbkdf2_sha256$")
    assert service.login(c, 1, "s3cret") is True
