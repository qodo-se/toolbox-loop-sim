import hashlib
import os
import sqlite3
import tempfile
import pytest
from app import service

# Credential formats written by releases before the self-describing record.
LEGACY_MD5 = hashlib.md5(b"hunter2").hexdigest()
LEGACY_SHA256 = hashlib.sha256(b"hunter2").hexdigest()
# Pinned to the literal historical salt and work factor, not the service
# constants, so a change to either side of the legacy contract shows up as a
# failure here.
LEGACY_STATIC_SALT = b"static-demo-salt"
LEGACY_STATIC_PBKDF2 = hashlib.pbkdf2_hmac(
    "sha256", b"hunter2", LEGACY_STATIC_SALT, 200_000
).hex()

def setup_db(path=":memory:", password="hunter2"):
    c = sqlite3.connect(path)
    c.execute("CREATE TABLE users(id INTEGER PRIMARY KEY, email TEXT, password_hash TEXT)")
    c.execute("CREATE TABLE orders(id INTEGER PRIMARY KEY, user_id INT, amount REAL)")
    c.execute("CREATE TABLE audit(id INTEGER PRIMARY KEY, user_id INT)")
    c.execute(
        "INSERT INTO users(email, password_hash) VALUES ('a@b.c', ?)",
        (service.hash_password(password),),
    )
    c.commit()
    return c

def add_user(conn, email, password_hash):
    cur = conn.execute(
        "INSERT INTO users(email, password_hash) VALUES (?, ?)", (email, password_hash)
    )
    return cur.lastrowid

def stored_hash(conn, user_id):
    return conn.execute(
        "SELECT password_hash FROM users WHERE id = ?", (user_id,)
    ).fetchone()[0]

def test_get_user():
    c = setup_db()
    assert service.get_user(c, 1)[1] == "a@b.c"

def test_find_by_email():
    c = setup_db()
    assert service.find_by_email(c, "a@b.c")[0] == 1
    assert service.find_by_email(c, "missing@b.c") is None

def test_create_order():
    c = setup_db()
    assert service.create_order(c, 1, 9.5) == 1

def test_create_order_rejects_nan():
    c = setup_db()
    with pytest.raises(ValueError):
        service.create_order(c, 1, float('nan'))

def test_check_amount_rejects_non_numeric_and_bools():
    for bad in (None, "5", True, False, [1], object()):
        with pytest.raises(ValueError):
            service.check_amount(bad)

def test_create_order_rejects_bool_amount():
    c = setup_db()
    with pytest.raises(ValueError):
        service.create_order(c, 1, True)
    assert c.execute("SELECT COUNT(*) FROM orders").fetchone()[0] == 0

def test_update_amount():
    c = setup_db()
    oid = service.create_order(c, 1, 9.5)
    assert service.update_amount(c, oid, 12.0) is True
    assert c.execute("SELECT amount FROM orders WHERE id = ?", (oid,)).fetchone()[0] == 12.0
    assert service.update_amount(c, oid + 1, 12.0) is False

def test_update_amount_rejects_non_finite():
    c = setup_db()
    oid = service.create_order(c, 1, 9.5)
    for bad in (float('nan'), float('inf'), 0, -1):
        with pytest.raises(ValueError):
            service.update_amount(c, oid, bad)
    assert c.execute("SELECT amount FROM orders WHERE id = ?", (oid,)).fetchone()[0] == 9.5

def test_update_amount_missing_order():
    c = setup_db()
    oid = service.create_order(c, 1, 9.5)
    assert service.update_amount(c, oid, 12.0) is True
    assert service.update_amount(c, oid + 100, 12.0) is False

def test_update_amount_unchanged_value_succeeds():
    c = setup_db()
    oid = service.create_order(c, 1, 9.5)
    assert service.update_amount(c, oid, 9.5) is True

def test_update_amount_missing_order_keeps_caller_writes():
    c = setup_db()
    oid = service.create_order(c, 1, 9.5)
    c.execute("INSERT INTO users(email) VALUES ('pending@b.c')")
    assert service.update_amount(c, oid + 1, 5.0) is False
    assert service.find_by_email(c, "pending@b.c") is not None

def test_update_amount_strict_missing_order_raises():
    c = setup_db()
    with pytest.raises(LookupError):
        service.update_amount_strict(c, 999, 5.0)

def test_update_amount_strict_missing_order_rolls_back():
    c = setup_db()
    oid = service.create_order(c, 1, 9.5)
    with pytest.raises(LookupError):
        service.update_amount_strict(c, oid + 1, 5.0)
    assert not c.in_transaction
    assert service.get_user(c, 1)[1] == "a@b.c"

def test_update_amount_strict_unchanged_value_succeeds():
    c = setup_db()
    oid = service.create_order(c, 1, 9.5)
    assert service.update_amount_strict(c, oid, 9.5) is True

def test_update_amount_strict_deleted_order_is_not_reported_as_updated():
    c = setup_db()
    oid = service.create_order(c, 1, 9.5)
    c.execute("DELETE FROM orders WHERE id = ?", (oid,))
    c.commit()
    with pytest.raises(LookupError):
        service.update_amount_strict(c, oid, 5.0)

def test_update_amount_strict_missing_order_keeps_caller_writes():
    c = setup_db()
    oid = service.create_order(c, 1, 9.5)
    c.execute("INSERT INTO users(email) VALUES ('pending@b.c')")
    with pytest.raises(LookupError):
        service.update_amount_strict(c, oid + 1, 5.0)
    assert service.find_by_email(c, "pending@b.c") is not None

def test_hash_password_is_salted_per_call():
    assert service.hash_password("hunter2") != service.hash_password("hunter2")

def test_hash_password_is_salted_and_verifiable():
    h = service.hash_password("hunter2")
    assert h != service.hash_password("hunter2")
    assert service.verify_password("hunter2", h)
    assert not service.verify_password("wrong", h)
    assert not service.verify_password("hunter2", "not-a-hash")

def test_equal_passwords_get_distinct_hashes():
    a = service.hash_password("hunter2")
    b = service.hash_password("hunter2")
    assert a != b
    assert service.verify_password("hunter2", a)
    assert service.verify_password("hunter2", b)
    assert not service.verify_password("hunter3", a)

def test_verify_password():
    record = service.hash_password("hunter2")
    assert service.verify_password("hunter2", record)
    assert not service.verify_password("wrong", record)
    assert not service.verify_password("hunter2", "not-a-record")

def test_verify_password_rejects_out_of_range_iterations():
    record = service.hash_password("hunter2")
    _, _, salt, digest = record.split('$')
    out_of_range = (0, -1, service.MAX_PBKDF2_ITERATIONS + 1, 10 ** 40)
    for iterations in out_of_range:
        bad = f"{service.PBKDF2_PREFIX}${iterations}${salt}${digest}"
        assert not service.verify_password("hunter2", bad)

def test_verify_password_rejects_excessive_work_factor():
    huge = service.MAX_PBKDF2_ITERATIONS + 1
    stored = "pbkdf2_sha256${}${}${}".format(huge, "00" * 16, "ff" * 32)
    assert service.verify_password("hunter2", stored) is False

def test_verify_password_rejects_malformed_records():
    for bad in ("not-a-record", "", "$$$", "z" * 64, "pbkdf2_sha256$x$aa$bb", None, 7):
        assert not service.verify_password("hunter2", bad)

def test_verify_password_rejects_malformed_hash():
    assert service.verify_password("s3cret", "") is False
    assert service.verify_password("s3cret", "deadbeef") is False

def test_verify_password_rejects_malformed_hashes():
    for stored in (None, 123, b"salt$digest", "", "nodollar", "a$b$c$d", "1000$zz$ff"):
        assert service.verify_password("s3cret", stored) is False

def test_verify_password_rejects_corrupt_records():
    for stored in (
        "pbkdf2_sha256$1$00$é",                # non-ASCII digest
        "pbkdf2_sha256$1$00$zz",               # non-hex digest
        "pbkdf2_sha256$0$00$00",               # iteration count below the allowed range
        f"pbkdf2_sha256${service.MAX_PBKDF2_ITERATIONS + 1}$00$00",
    ):
        assert not service.verify_password("hunter2", stored)

def test_verify_password_honors_stored_work_factor():
    stored = service.hash_password("s3cret", iterations=1000)
    assert stored.startswith("pbkdf2_sha256$1000$")
    # Still verifies after the default work factor moves on.
    assert service.PBKDF2_ITERATIONS != 1000
    assert service.verify_password("s3cret", stored) is True
    assert service.verify_password("wrong", stored) is False

def test_verify_password_honors_explicit_salt():
    salt = bytes(range(service.SALT_BYTES))
    assert service.hash_password("s3cret", salt=salt) == service.hash_password("s3cret", salt=salt)

def test_verify_password_accepts_legacy_records():
    for record in (LEGACY_MD5, LEGACY_SHA256, LEGACY_STATIC_PBKDF2):
        assert service.verify_password("hunter2", record)
        assert not service.verify_password("wrong", record)

def test_legacy_hash_matches_hash_password_rules():
    assert service.verify_password("hunter2", service.legacy_hash("hunter2"))

def test_legacy_hash_delegates():
    assert service.verify_password("hunter2", service.legacy_hash("hunter2"))

def test_legacy_hash_alias():
    stored = service.legacy_hash("s3cret")
    assert stored.startswith("pbkdf2_sha256$")
    assert service.verify_password("s3cret", stored) is True

def test_legacy_credential_recipe_is_frozen():
    # These constants describe credentials already stored in the database.
    # Editing either one orphans their owners, so pin both to the literals.
    assert service.LEGACY_STATIC_SALT == LEGACY_STATIC_SALT
    assert service.LEGACY_PBKDF2_ITERATIONS == 200_000

def test_legacy_verification_survives_iteration_policy_bump(monkeypatch):
    # Raising the policy work factor must not orphan credentials already stored
    # under the frozen legacy one.
    assert service.LEGACY_PBKDF2_ITERATIONS == 200_000
    monkeypatch.setattr(service, "PBKDF2_ITERATIONS", service.PBKDF2_ITERATIONS + 50_000)
    assert service.verify_password("hunter2", LEGACY_STATIC_PBKDF2)
    assert not service.verify_password("wrong", LEGACY_STATIC_PBKDF2)

def test_login():
    c = setup_db()
    assert service.login(c, 1, "hunter2")
    assert not service.login(c, 1, "wrong")
    assert not service.login(c, 999, "hunter2")

def test_login_correct_password():
    c = setup_db(password="s3cret")
    assert service.login(c, 1, "s3cret") is True

def test_login_wrong_password():
    c = setup_db(password="s3cret")
    assert service.login(c, 1, "nope") is False

def test_login_unknown_user():
    c = setup_db(password="s3cret")
    assert service.login(c, 99, "s3cret") is False

def test_login_accepts_current_hash():
    c = setup_db()
    c.execute("UPDATE users SET password_hash = ? WHERE id = 1", (service.hash_password("pw"),))
    assert service.login(c, 1, "pw")
    assert not service.login(c, 1, "wrong")

def test_login_accepts_and_upgrades_legacy_hashes():
    c = setup_db()
    for i, record in enumerate((LEGACY_MD5, LEGACY_SHA256, LEGACY_STATIC_PBKDF2)):
        uid = add_user(c, f"legacy{i}@b.c", record)
        assert service.login(c, uid, "hunter2")
        upgraded = stored_hash(c, uid)
        assert upgraded.startswith("pbkdf2_sha256$")
        assert service.verify_password("hunter2", upgraded)
        # The upgraded credential keeps working on later sign-ins.
        assert service.login(c, uid, "hunter2")
        assert not service.login(c, uid, "wrong")

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
    stored = stored_hash(c, 1)
    assert stored.startswith(service.PBKDF2_PREFIX + "$")
    assert service.login(c, 1, "s3cret") is True

def test_login_leaves_legacy_hash_alone_on_bad_password():
    c = setup_db()
    uid = add_user(c, "legacy@b.c", LEGACY_SHA256)
    assert not service.login(c, uid, "wrong")
    assert stored_hash(c, uid) == LEGACY_SHA256

def test_login_does_not_rehash_current_format():
    c = setup_db()
    before = stored_hash(c, 1)
    assert service.login(c, 1, "hunter2")
    assert stored_hash(c, 1) == before

def test_login_upgrade_does_not_commit_caller_transaction():
    c = setup_db()
    uid = add_user(c, "legacy@b.c", LEGACY_SHA256)
    c.commit()
    # A pending write the caller has not committed yet.
    c.execute("INSERT INTO orders(user_id, amount) VALUES (1, 5.0)")
    assert c.in_transaction
    assert service.login(c, uid, "hunter2")
    assert c.in_transaction
    c.rollback()
    assert c.execute("SELECT COUNT(*) FROM orders").fetchone()[0] == 0

def test_login_upgrade_survives_failing_update():
    c = setup_db()
    uid = add_user(c, "legacy@b.c", LEGACY_SHA256)
    c.commit()
    c.execute("PRAGMA query_only = ON")
    try:
        assert service.login(c, uid, "hunter2")
    finally:
        c.execute("PRAGMA query_only = OFF")
    assert stored_hash(c, uid) == LEGACY_SHA256

def test_upgrade_rolls_back_transaction_it_opened():
    class FailingCursor:
        def execute(self, *args):
            raise sqlite3.OperationalError("database is locked")

    class FailingConn:
        in_transaction = False

        def __init__(self):
            self.rolled_back = False

        def cursor(self):
            return FailingCursor()

        def rollback(self):
            self.rolled_back = True

    conn = FailingConn()
    service.upgrade_password_hash(conn, 1, "hunter2", LEGACY_SHA256)
    assert conn.rolled_back

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
    assert stored_hash(c, 1) == reset
    assert not service.login(c, 1, "pw")
    assert service.login(c, 1, "new-pw")

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

def test_audit():
    c = setup_db()
    assert service.audit(c, 1) == 1

def test_audit_records_event():
    # Use an on-disk database and a second connection so the assertion only
    # passes when the insert was actually committed.
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "audit.db")
        c = setup_db(path)
        try:
            assert service.audit(c, 1) == 1
        finally:
            c.close()
        verify = sqlite3.connect(path)
        try:
            assert verify.execute("SELECT user_id FROM audit").fetchall() == [(1,)]
        finally:
            verify.close()

def test_calc_rejects_booleans_and_deep_expressions():
    assert service.calc("1 + 2") == 3
    for expr in ("True + True", "+".join(["1"] * 200)):
        with pytest.raises(ValueError):
            service.calc(expr)

def test_issuer_token_requires_config():
    original = os.environ.pop("API_TOKEN", None)
    try:
        with pytest.raises(RuntimeError):
            service.issuer_token()
        os.environ["API_TOKEN"] = "t"
        assert service.issuer_token() == "t"
    finally:
        if original is None:
            os.environ.pop("API_TOKEN", None)
        else:
            os.environ["API_TOKEN"] = original
