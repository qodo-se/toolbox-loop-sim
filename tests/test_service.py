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

def test_verify_password_rejects_out_of_range_iteration_counts():
    salt = b"\x00" * service.SALT_BYTES
    digest = hashlib.pbkdf2_hmac("sha256", PASSWORD.encode(), salt, 1).hex()
    # Oversized counts would overflow pbkdf2_hmac; zero/negative ones are nonsense.
    for rounds in (10 ** 30, service.MAX_PBKDF2_ITERATIONS + 1, 0, -1):
        stored = f"{service.PBKDF2_SCHEME}${rounds}${salt.hex()}${digest}"
        assert not service.verify_password(PASSWORD, stored)

def test_verify_password_rejects_non_string_verifiers():
    # Corrupt column values are truthy, so login's falsey check lets them through.
    for stored in (12345, b"deadbeef", 0.5, ["x"], {"a": 1}):
        assert service.verify_password(PASSWORD, stored) is False

def test_max_iterations_is_bounded_relative_to_the_written_work_factor():
    # The ceiling caps attacker-controllable hashing work per login attempt.
    assert service.PBKDF2_ITERATIONS <= service.MAX_PBKDF2_ITERATIONS
    assert service.MAX_PBKDF2_ITERATIONS <= 5 * service.PBKDF2_ITERATIONS

def test_login_rejects_corrupt_non_string_password_hash():
    c = setup_db()
    # A BLOB survives the column's TEXT affinity (an int would be coerced to
    # text), so this is the corrupt value that reaches verify_password as bytes.
    c.execute("UPDATE users SET password_hash = ? WHERE id = 1", (memoryview(b"deadbeef"),))
    assert c.execute("SELECT typeof(password_hash) FROM users WHERE id = 1").fetchone()[0] == "blob"
    assert service.login(c, 1, PASSWORD) is False  # returns, rather than raising

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

def test_legacy_upgrade_does_not_overwrite_a_concurrent_password_reset():
    """The legacy upgrade must not resurrect the old credential."""
    c = setup_legacy_db()
    service.ensure_schema(c)
    legacy = hashlib.sha256(PASSWORD.encode()).hexdigest()
    c.execute("UPDATE users SET password_hash = ? WHERE id = 1", (legacy,))

    reset = service.hash_password("new-password")
    original_hash_password = service.hash_password

    def reset_then_hash(pw, salt=None):
        # Stand in for a reset committing between login's SELECT and its UPDATE.
        c.execute("UPDATE users SET password_hash = ? WHERE id = 1", (reset,))
        c.commit()
        return original_hash_password(pw, salt)

    service.hash_password = reset_then_hash
    try:
        # The compare-and-swap matches nothing, which proves the credential we
        # verified was superseded mid-request. That request must not authenticate.
        assert service.login(c, 1, PASSWORD) is False
    finally:
        service.hash_password = original_hash_password

    stored = c.execute("SELECT password_hash FROM users WHERE id = 1").fetchone()[0]
    assert stored == reset  # the reset survives
    assert service.login(c, 1, "new-password") is True
    assert service.login(c, 1, PASSWORD) is False  # old password is dead
