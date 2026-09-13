import hashlib
import sqlite3
from app import service

PASSWORD = "s3cret"

def setup_db():
    c = sqlite3.connect(":memory:")
    service.ensure_schema(c)
    c.execute(
        "INSERT INTO users(email, password_hash) VALUES ('a@b.c', ?)",
        (service.hash_password(PASSWORD),),
    )
    return c

def setup_legacy_db():
    """A database on the pre-PR schema, holding a bare SHA-256 digest."""
    c = sqlite3.connect(":memory:")
    c.execute("CREATE TABLE users(id INTEGER PRIMARY KEY, email TEXT)")
    c.execute("INSERT INTO users(email) VALUES ('a@b.c')")
    return c

def test_get_user():
    c = setup_db()
    assert service.get_user(c, 1)[1] == "a@b.c"

def test_create_order():
    c = setup_db()
    assert service.create_order(c, 1, 9.5) == 1

def test_hash_password_is_salted_and_not_plaintext():
    first = service.hash_password(PASSWORD)
    second = service.hash_password(PASSWORD)
    assert first != second  # per-user salt, so identical passwords never collide
    assert PASSWORD not in first
    assert service.verify_password(PASSWORD, first)
    assert service.verify_password(PASSWORD, second)
    assert not service.verify_password("other", first)

def test_verify_password_accepts_legacy_sha256_digest():
    legacy = hashlib.sha256(PASSWORD.encode()).hexdigest()
    assert service.verify_password(PASSWORD, legacy)
    assert not service.verify_password("other", legacy)

def test_verify_password_rejects_malformed_verifier():
    assert not service.verify_password(PASSWORD, "pbkdf2_sha256$notanint$zz$zz")

def test_login_correct_password():
    c = setup_db()
    assert service.login(c, 1, PASSWORD) is True

def test_login_wrong_password():
    c = setup_db()
    assert service.login(c, 1, "wrong") is False

def test_login_unknown_user():
    c = setup_db()
    assert service.login(c, 99, PASSWORD) is False

def test_login_user_without_password_hash():
    c = setup_db()
    c.execute("INSERT INTO users(email) VALUES ('n@b.c')")
    assert service.login(c, 2, PASSWORD) is False

def test_ensure_schema_migrates_pre_pr_database():
    c = setup_legacy_db()
    service.ensure_schema(c)
    columns = {row[1] for row in c.execute("PRAGMA table_info(users)").fetchall()}
    assert "password_hash" in columns
    assert service.get_user(c, 1)[1] == "a@b.c"  # existing rows survive

def test_login_works_for_legacy_hash_and_upgrades_it():
    c = setup_legacy_db()
    service.ensure_schema(c)
    legacy = hashlib.sha256(PASSWORD.encode()).hexdigest()
    c.execute("UPDATE users SET password_hash = ? WHERE id = 1", (legacy,))

    assert service.login(c, 1, PASSWORD) is True

    stored = c.execute("SELECT password_hash FROM users WHERE id = 1").fetchone()[0]
    assert stored != legacy
    assert stored.startswith(service.PBKDF2_SCHEME + "$")
    assert service.login(c, 1, PASSWORD) is True  # still valid after the upgrade
    assert service.login(c, 1, "wrong") is False
