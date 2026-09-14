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

PASSWORD = "s3cret"

def setup_db(path=":memory:", password="hunter2"):
    c = sqlite3.connect(path)
    service.ensure_schema(c)
    # ensure_schema owns users/orders; audit is only exercised by the tests.
    c.execute("CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, user_id INT)")
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

def setup_legacy_db():
    """A database on the pre-PR schema, holding a bare SHA-256 digest."""
    c = sqlite3.connect(":memory:")
    c.execute("CREATE TABLE users(id INTEGER PRIMARY KEY, email TEXT)")
    c.execute("INSERT INTO users(email) VALUES ('a@b.c')")
    return c

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
    c = setup_db(password=PASSWORD)
    # A BLOB survives the column's TEXT affinity (an int would be coerced to
    # text), so this is the corrupt value that reaches verify_password as bytes.
    c.execute("UPDATE users SET password_hash = ? WHERE id = 1", (memoryview(b"deadbeef"),))
    assert c.execute("SELECT typeof(password_hash) FROM users WHERE id = 1").fetchone()[0] == "blob"
    assert service.login(c, 1, PASSWORD) is False  # returns, rather than raising

def test_login_user_without_password_hash():
    c = setup_db(password=PASSWORD)
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
    for record in (LEGACY_SHA256, LEGACY_STATIC_PBKDF2):
        assert service.verify_password("hunter2", record)
        assert not service.verify_password("wrong", record)

def test_verify_password_rejects_md5_records():
    # An unsalted MD5 digest is crackable at brute-force speed once disclosed,
    # so the right password must not be enough to verify against one.
    assert not service.verify_password("hunter2", LEGACY_MD5)
    assert not service.verify_password("wrong", LEGACY_MD5)
    assert not service.verify_legacy_password("hunter2", LEGACY_MD5)

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
    for i, record in enumerate((LEGACY_SHA256, LEGACY_STATIC_PBKDF2)):
        uid = add_user(c, f"legacy{i}@b.c", record)
        assert service.login(c, uid, "hunter2")
        upgraded = stored_hash(c, uid)
        assert upgraded.startswith("pbkdf2_sha256$")
        assert service.verify_password("hunter2", upgraded)
        # The upgraded credential keeps working on later sign-ins.
        assert service.login(c, uid, "hunter2")
        assert not service.login(c, uid, "wrong")

def test_login_rejects_md5_hash_and_leaves_it_stored():
    c = setup_db()
    uid = add_user(c, "md5@b.c", LEGACY_MD5)
    # The correct password must not sign in, so a digest recovered by brute
    # force cannot either. The record is left for a password reset to replace.
    assert service.login(c, uid, "hunter2") is False
    assert stored_hash(c, uid) == LEGACY_MD5

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

    @property
    def rowcount(self):
        # login's compare-and-swap reads this to detect that the reset won.
        return self._cur.rowcount

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
    # The credential we verified was superseded mid-request, so the request
    # must not authenticate and must not resurrect the old password.
    assert service.login(_RacingConn(c, reset), 1, "pw") is False
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

def test_hash_password_is_salted():
    first = service.hash_password("s3cret")
    second = service.hash_password("s3cret")
    assert first != second
    assert service.verify_password("s3cret", first) is True
    assert service.verify_password("s3cret", second) is True

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
