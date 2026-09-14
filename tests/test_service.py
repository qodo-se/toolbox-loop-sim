import hashlib
import os
import sqlite3
import tempfile
import pytest
from app import service

def setup_db(path=":memory:"):
    c = sqlite3.connect(path)
    c.execute("CREATE TABLE users(id INTEGER PRIMARY KEY, email TEXT, password_hash TEXT)")
    c.execute("CREATE TABLE orders(id INTEGER PRIMARY KEY, user_id INT, amount REAL)")
    c.execute("CREATE TABLE audit(id INTEGER PRIMARY KEY, user_id INT)")
    c.execute(
        "INSERT INTO users(email, password_hash) VALUES ('a@b.c', ?)",
        (service.hash_password("s3cret"),),
    )
    c.commit()
    return c

def test_get_user():
    c = setup_db()
    assert service.get_user(c, 1)[1] == "a@b.c"

def test_create_order():
    c = setup_db()
    assert service.create_order(c, 1, 9.5) == 1

def test_hash_password_is_salted_and_verifiable():
    h = service.hash_password("hunter2")
    assert h != service.hash_password("hunter2")
    assert service.verify_password("hunter2", h)
    assert not service.verify_password("wrong", h)
    assert not service.verify_password("hunter2", "not-a-hash")

def test_verify_password_rejects_corrupt_records():
    for stored in (
        "pbkdf2_sha256$1$00$é",           # non-ASCII digest
        "pbkdf2_sha256$1$00$zz",               # non-hex digest
        "pbkdf2_sha256$0$00$00",               # iteration count below the allowed range
        f"pbkdf2_sha256${service.MAX_PBKDF2_ITERATIONS + 1}$00$00",
    ):
        assert not service.verify_password("hunter2", stored)

def test_legacy_hash_delegates():
    assert service.verify_password("hunter2", service.legacy_hash("hunter2"))

def test_calc_rejects_booleans_and_deep_expressions():
    assert service.calc("1 + 2") == 3
    for expr in ("True + True", "+".join(["1"] * 200)):
        try:
            service.calc(expr)
        except ValueError:
            continue
        raise AssertionError(f"expected ValueError for {expr!r}")

def test_find_by_email():
    c = setup_db()
    assert service.find_by_email(c, "a@b.c")[0] == 1
    assert service.find_by_email(c, "missing@b.c") is None

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

def test_update_amount():
    c = setup_db()
    order_id = service.create_order(c, 1, 9.5)
    assert service.update_amount(c, order_id, 12.0) is True
    assert service.update_amount(c, order_id + 1, 12.0) is False

def test_update_amount_missing_order():
    c = setup_db()
    oid = service.create_order(c, 1, 9.5)
    assert service.update_amount(c, oid, 12.0) is True
    assert service.update_amount(c, oid + 100, 12.0) is False

def test_update_amount_rejects_non_finite():
    c = setup_db()
    order_id = service.create_order(c, 1, 9.5)
    for bad in (float("nan"), float("inf")):
        try:
            service.update_amount(c, order_id, bad)
        except ValueError:
            pass
        else:
            raise AssertionError("expected ValueError for %r" % bad)

def test_amount_rejects_nan():
    c = setup_db()
    order_id = service.create_order(c, 1, 9.5)
    with pytest.raises(ValueError):
        service.create_order(c, 1, float('nan'))
    with pytest.raises(ValueError):
        service.update_amount(c, order_id, float('nan'))

def test_update_amount_unchanged_value_succeeds():
    c = setup_db()
    oid = service.create_order(c, 1, 9.5)
    assert service.update_amount(c, oid, 9.5) is True

def test_update_amount_strict_missing_order_rolls_back():
    c = setup_db()
    oid = service.create_order(c, 1, 9.5)
    raised = False
    try:
        service.update_amount_strict(c, oid + 1, 5.0)
    except LookupError:
        raised = True
    assert raised
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
    raised = False
    try:
        service.update_amount_strict(c, oid, 5.0)
    except LookupError:
        raised = True
    assert raised

def test_update_amount_strict_missing_order_keeps_caller_writes():
    c = setup_db()
    oid = service.create_order(c, 1, 9.5)
    c.execute("INSERT INTO users(email) VALUES ('pending@b.c')")
    raised = False
    try:
        service.update_amount_strict(c, oid + 1, 5.0)
    except LookupError:
        raised = True
    assert raised
    assert service.find_by_email(c, "pending@b.c") is not None

def test_update_amount_missing_order_keeps_caller_writes():
    c = setup_db()
    oid = service.create_order(c, 1, 9.5)
    c.execute("INSERT INTO users(email) VALUES ('pending@b.c')")
    assert service.update_amount(c, oid + 1, 5.0) is False
    assert service.find_by_email(c, "pending@b.c") is not None

def test_safe_commit():
    c = setup_db()
    assert service.safe_commit(c) is True

def test_safe_commit_reports_failure():
    c = setup_db()
    assert service.safe_commit(c) is True
    c.close()
    assert service.safe_commit(c) is False

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

def test_login_correct_password():
    c = setup_db()
    assert service.login(c, 1, "s3cret") is True

def test_login_wrong_password():
    c = setup_db()
    assert service.login(c, 1, "nope") is False

def test_login_unknown_user():
    c = setup_db()
    assert service.login(c, 99, "s3cret") is False

def test_login_without_password_set():
    c = setup_db()
    c.execute("UPDATE users SET password_hash = NULL WHERE id = 1")
    assert service.login(c, 1, "pw") is False
    c.execute("UPDATE users SET password_hash = '' WHERE id = 1")
    assert service.login(c, 1, "pw") is False

def test_hash_password_is_salted():
    first = service.hash_password("s3cret")
    second = service.hash_password("s3cret")
    assert first != second
    assert service.verify_password("s3cret", first) is True
    assert service.verify_password("s3cret", second) is True

def test_hash_password_salts_each_call():
    assert service.hash_password("pw") != service.hash_password("pw")

def test_legacy_hash_alias():
    stored = service.legacy_hash("s3cret")
    assert stored.startswith("pbkdf2_sha256$")
    assert service.verify_password("s3cret", stored) is True

def test_verify_password_rejects_malformed_hash():
    assert service.verify_password("s3cret", "") is False
    assert service.verify_password("s3cret", "deadbeef") is False

def test_verify_password_rejects_malformed_hashes():
    for stored in (None, 123, b"salt$digest", "", "nodollar", "a$b$c$d", "1000$zz$ff"):
        assert service.verify_password("s3cret", stored) is False

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

def test_verify_password_rejects_excessive_work_factor():
    huge = service.MAX_PBKDF2_ITERATIONS + 1
    stored = "pbkdf2_sha256${}${}${}".format(huge, "00" * 16, "ff" * 32)
    assert service.verify_password("s3cret", stored) is False

def test_verify_password_rejects_out_of_range_iterations():
    salt_hex = "00" * 16
    digest_hex = "11" * 32
    out_of_range = ("0", "-1", str(service.MAX_PBKDF2_ITERATIONS + 1), str(10 ** 40))
    for iterations in out_of_range:
        stored = "{}${}${}${}".format(
            service.PBKDF2_PREFIX, iterations, salt_hex, digest_hex
        )
        assert service.verify_password("s3cret", stored) is False

def test_login_rejects_excessive_work_factor():
    c = setup_db()
    huge = f"{service.PBKDF2_PREFIX}${service.MAX_PBKDF2_ITERATIONS + 1}$00$ff"
    assert service.verify_password("pw", huge) is False
    c.execute("UPDATE users SET password_hash = ? WHERE id = 1", (huge,))
    assert service.login(c, 1, "pw") is False

def test_verify_password_rejects_oversized_salt(monkeypatch):
    oversized = f"{service.PBKDF2_PREFIX}$1${'ab' * (service.MAX_SALT_BYTES + 1)}$ff"

    def fail(*args, **kwargs):
        raise AssertionError("derivation ran on an unbounded salt")

    monkeypatch.setattr(service, "_derive", fail)
    assert service.verify_password("pw", oversized) is False
    assert service.verify_password("pw", f"{service.PBKDF2_PREFIX}$1$$ff") is False

def test_login_rejects_oversized_salt():
    c = setup_db()
    oversized = f"{service.PBKDF2_PREFIX}$1${'ab' * (service.MAX_SALT_BYTES + 1)}$ff"
    c.execute("UPDATE users SET password_hash = ? WHERE id = 1", (oversized,))
    assert service.login(c, 1, "pw") is False

def test_needs_rehash_flags_weak_work_factor():
    weak = service.hash_password("pw", salt=b"\x01" * 16, iterations=1_000)
    assert service.verify_password("pw", weak) is True
    assert service.needs_rehash(weak) is True
    current = service.hash_password("pw")
    assert service.verify_password("pw", current) is True
    assert service.needs_rehash(current) is False

def test_needs_rehash_flags_legacy_digests():
    assert service.needs_rehash(hashlib.sha256(b"pw").hexdigest()) is True
    assert service.needs_rehash("not-a-hash") is False
    # A 32-char hex digest is not an authenticable format, so there is nothing to
    # upgrade on login.
    assert service.needs_rehash(hashlib.md5(b"pw").hexdigest()) is False

def test_needs_rehash_flags_undersized_salt():
    short = service.hash_password("pw", salt=b"\x01", iterations=service.PBKDF2_ITERATIONS)
    assert short.split("$")[1] == str(service.PBKDF2_ITERATIONS)
    # The row still authenticates, which is what makes the upgrade reachable.
    assert service.verify_password("pw", short) is True
    assert service.needs_rehash(short) is True

def test_login_upgrades_undersized_salt():
    c = setup_db()
    short = service.hash_password("pw", salt=b"\x01", iterations=service.PBKDF2_ITERATIONS)
    c.execute("UPDATE users SET password_hash = ? WHERE id = 1", (short,))
    assert service.login(c, 1, "pw") is True
    stored = c.execute("SELECT password_hash FROM users WHERE id = 1").fetchone()[0]
    assert len(bytes.fromhex(stored.split("$")[2])) == service.SALT_BYTES
    assert service.needs_rehash(stored) is False
    assert service.login(c, 1, "pw") is True

def test_login_upgrades_weak_work_factor():
    c = setup_db()
    weak = service.hash_password("pw", salt=b"\x01" * 16, iterations=1_000)
    c.execute("UPDATE users SET password_hash = ? WHERE id = 1", (weak,))
    assert service.login(c, 1, "pw") is True
    stored = c.execute("SELECT password_hash FROM users WHERE id = 1").fetchone()[0]
    assert stored.split("$")[1] == str(service.PBKDF2_ITERATIONS)
    assert service.needs_rehash(stored) is False
    assert service.login(c, 1, "pw") is True

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

def test_md5_digest_is_not_an_accepted_credential():
    # An unsalted MD5 digest cannot be verified slowly, so the correct password
    # must not authenticate against one and the row must be left untouched for a
    # password reset rather than upgraded in place.
    md5 = hashlib.md5(b"pw").hexdigest()
    assert service.is_legacy_hash(md5) is False
    assert service.verify_password("pw", md5) is False
    c = setup_db()
    c.execute("UPDATE users SET password_hash = ? WHERE id = 1", (md5,))
    assert service.login(c, 1, "pw") is False
    assert c.execute("SELECT password_hash FROM users WHERE id = 1").fetchone()[0] == md5

def test_verify_password_rejects_oversized_digest(monkeypatch):
    # A huge stored digest must be refused on length alone, without being decoded
    # or derived against on every login attempt.
    oversized = "{}$1${}${}".format(service.PBKDF2_PREFIX, "00" * 16, "ab" * 100_000)

    def fail(*args, **kwargs):
        raise AssertionError("derivation ran on an unbounded digest")

    monkeypatch.setattr(service, "_derive", fail)
    assert service.verify_password("pw", oversized) is False
    assert service.needs_rehash(oversized) is False
    assert len(oversized) > service.MAX_PBKDF2_RECORD_LENGTH

def test_verify_password_rejects_wrong_length_digest():
    salt_hex = "00" * service.SALT_BYTES
    for digest_hex in ("", "ff", "ff" * 31, "ff" * 33):
        stored = "{}$1${}${}".format(service.PBKDF2_PREFIX, salt_hex, digest_hex)
        assert service.verify_password("pw", stored) is False

def test_login_rejects_oversized_digest():
    c = setup_db()
    oversized = "{}$1${}${}".format(service.PBKDF2_PREFIX, "00" * 16, "ab" * 100_000)
    c.execute("UPDATE users SET password_hash = ? WHERE id = 1", (oversized,))
    assert service.login(c, 1, "pw") is False

def test_weak_factor_upgrade_does_not_clobber_concurrent_reset():
    c = setup_db()
    weak = service.hash_password("pw", iterations=1_000)
    c.execute("UPDATE users SET password_hash = ? WHERE id = 1", (weak,))
    reset = service.hash_password("new-pw")
    real_hash_password = service.hash_password

    # Land a password reset between login's read and its upgrade write.
    def reset_then_hash(pw):
        c.execute("UPDATE users SET password_hash = ? WHERE id = 1", (reset,))
        return real_hash_password(pw)

    service.hash_password = reset_then_hash
    try:
        service.login(c, 1, "pw")
    finally:
        service.hash_password = real_hash_password
    assert c.execute("SELECT password_hash FROM users WHERE id = 1").fetchone()[0] == reset
    assert service.login(c, 1, "pw") is False
    assert service.login(c, 1, "new-pw") is True

def test_issuer_token_requires_config():
    original = os.environ.pop("API_TOKEN", None)
    try:
        try:
            service.issuer_token()
        except RuntimeError:
            pass
        else:
            raise AssertionError("expected RuntimeError when API_TOKEN is unset")
        os.environ["API_TOKEN"] = "t"
        assert service.issuer_token() == "t"
    finally:
        if original is None:
            os.environ.pop("API_TOKEN", None)
        else:
            os.environ["API_TOKEN"] = original
