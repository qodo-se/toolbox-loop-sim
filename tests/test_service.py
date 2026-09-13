import hashlib
import sqlite3
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

def test_equal_passwords_get_distinct_hashes():
    a = service.hash_password("hunter2")
    b = service.hash_password("hunter2")
    assert a != b
    assert service.verify_password("hunter2", a)
    assert service.verify_password("hunter2", b)
    assert not service.verify_password("hunter3", a)

def test_login_accepts_current_hash():
    c = setup_db()
    c.execute("UPDATE users SET password_hash = ? WHERE id = 1", (service.hash_password("pw"),))
    assert service.login(c, 1, "pw")
    assert not service.login(c, 1, "wrong")

def test_login_accepts_and_upgrades_legacy_hash():
    c = setup_db()
    legacy = hashlib.sha256(b"pw").hexdigest()
    c.execute("UPDATE users SET password_hash = ? WHERE id = 1", (legacy,))
    assert service.login(c, 1, "pw")
    stored = c.execute("SELECT password_hash FROM users WHERE id = 1").fetchone()[0]
    assert stored.startswith(service.PBKDF2_PREFIX + "$")
    assert service.login(c, 1, "pw")

class _RacingCursor:
    """Commits a password reset between login's read and its upgrade write."""
    def __init__(self, cur, conn, new_hash):
        self._cur, self._conn, self._new_hash = cur, conn, new_hash

    def execute(self, sql, params=()):
        return self._cur.execute(sql, params)

    def fetchone(self):
        row = self._cur.fetchone()
        self._conn.execute("UPDATE users SET password_hash = ? WHERE id = 1", (self._new_hash,))
        return row

class _RacingConn:
    def __init__(self, conn, new_hash):
        self._conn, self._new_hash = conn, new_hash

    def cursor(self):
        return _RacingCursor(self._conn.cursor(), self._conn, self._new_hash)

    def commit(self):
        self._conn.commit()

def test_legacy_upgrade_does_not_clobber_concurrent_reset():
    c = setup_db()
    c.execute("UPDATE users SET password_hash = ? WHERE id = 1", (hashlib.sha256(b"pw").hexdigest(),))
    reset = service.hash_password("new-pw")
    service.login(_RacingConn(c, reset), 1, "pw")
    assert c.execute("SELECT password_hash FROM users WHERE id = 1").fetchone()[0] == reset
    assert not service.login(c, 1, "pw")
    assert service.login(c, 1, "new-pw")

def test_verify_password_rejects_out_of_range_iterations():
    stored = f"{service.PBKDF2_PREFIX}${10 ** 40}${'00' * 16}${'ab' * 32}"
    assert not service.verify_password("pw", stored)
