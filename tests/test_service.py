import hashlib
import os
import sqlite3
import tempfile
from app import service

def setup_db(path=":memory:"):
    c = sqlite3.connect(path)
    service.init_schema(c)
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

def test_create_order_rejects_invalid_amount():
    c = setup_db()
    for bad in (0, -1, float("nan"), float("inf"), "9.5", None):
        try:
            service.create_order(c, 1, bad)
        except ValueError:
            continue
        raise AssertionError("create_order accepted %r" % (bad,))

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
    assert service.login(c, 1, "wrong") is False
    assert service.login(c, 1, "pw")
    stored = c.execute("SELECT password_hash FROM users WHERE id = 1").fetchone()[0]
    assert stored.startswith(service.PBKDF2_PREFIX + "$")
    assert stored.startswith(service.HASH_PREFIX + "$")
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

def test_legacy_upgrade_does_not_clobber_reset_landing_mid_write():
    # Same guarantee as above, but the reset lands inside login's own
    # hash_password call rather than inside its read.
    c = setup_db()
    legacy = hashlib.sha256("s3cret".encode()).hexdigest()
    c.execute("UPDATE users SET password_hash = ? WHERE id = 1", (legacy,))
    reset = service.hash_password("brand-new")
    real_hash_password = service.hash_password

    def reset_lands_first(pw, *args, **kwargs):
        # Fires inside login's read/write window, standing in for a concurrent reset.
        c.execute("UPDATE users SET password_hash = ? WHERE id = 1", (reset,))
        return real_hash_password(pw, *args, **kwargs)

    service.hash_password = reset_lands_first
    try:
        service.login(c, 1, "s3cret")
    finally:
        service.hash_password = real_hash_password
    assert c.execute("SELECT password_hash FROM users WHERE id = 1").fetchone()[0] == reset
    assert service.login(c, 1, "brand-new") is True

def test_update_amount():
    c = setup_db()
    order_id = service.create_order(c, 1, 9.5)
    assert service.update_amount(c, order_id, 12.0) is True
    assert service.update_amount(c, order_id + 1, 12.0) is False
    assert service.update_amount(c, order_id + 100, 12.0) is False

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

def test_audit():
    c = setup_db()
    assert service.audit(c, 1) == 1
    assert c.execute("SELECT user_id FROM audit").fetchone()[0] == 1

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

def test_login():
    c = setup_db()
    assert service.login(c, 1, "s3cret") is True
    assert service.login(c, 1, "wrong") is False
    assert service.login(c, 999, "s3cret") is False

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

def test_login_rejects_malformed_stored_hashes():
    c = setup_db()
    for bad in (12345, b"bytes", "pbkdf2_sha256$notanint$aa$bb", "pbkdf2_sha256$200000$zz$bb",
                "pbkdf2_sha256$" + str(10 ** 400) + "$aa$bb", "pbkdf2_sha256$0$aa$bb", "é"):
        c.execute("UPDATE users SET password_hash = ? WHERE id = 1", (bad,))
        assert service.login(c, 1, "s3cret") is False

def test_check_amount_rejects_huge_int_without_overflow():
    c = setup_db()
    order_id = service.create_order(c, 1, 9.5)
    for huge in (10 ** 400, -(10 ** 400)):
        for name, call in (("create_order", lambda a: service.create_order(c, 1, a)),
                           ("update_amount", lambda a: service.update_amount(c, order_id, a))):
            try:
                call(huge)
            except ValueError:
                continue
            except OverflowError:
                raise AssertionError("amount check raised OverflowError for %r" % (huge,))
            raise AssertionError("%s accepted %r" % (name, huge))
    # The rejected writes must not have touched the stored total.
    assert c.execute("SELECT amount FROM orders WHERE id = ?", (order_id,)).fetchone()[0] == 9.5
    assert c.execute("SELECT COUNT(*) FROM orders").fetchone()[0] == 1


def test_order_writes_accept_large_finite_int_amount():
    # 10 ** 20 is finite and positive but outside SQLite's 64-bit integer range,
    # so binding the caller's int directly used to raise OverflowError.
    c = setup_db()
    big = 10 ** 20
    order_id = service.create_order(c, 1, big)
    assert c.execute("SELECT amount FROM orders WHERE id = ?", (order_id,)).fetchone()[0] == float(big)
    assert service.update_amount(c, order_id, big * 10) is True
    assert c.execute("SELECT amount FROM orders WHERE id = ?", (order_id,)).fetchone()[0] == float(big * 10)


def test_order_writes_reject_inexact_int_amount():
    # 2 ** 63 + 1 is finite and positive, but float rounds it down to 2 ** 63.
    # Both writers must refuse it rather than persist a different total.
    c = setup_db()
    order_id = service.create_order(c, 1, 9.5)
    for inexact in (2 ** 63 + 1, 2 ** 53 + 1):
        for name, call in (("create_order", lambda a: service.create_order(c, 1, a)),
                           ("update_amount", lambda a: service.update_amount(c, order_id, a))):
            try:
                call(inexact)
            except ValueError:
                continue
            raise AssertionError("%s accepted %r" % (name, inexact))
    assert c.execute("SELECT amount FROM orders WHERE id = ?", (order_id,)).fetchone()[0] == 9.5
    assert c.execute("SELECT COUNT(*) FROM orders").fetchone()[0] == 1
    # An exactly representable large int is still accepted and round-trips.
    exact = 2 ** 63
    assert service.update_amount(c, order_id, exact) is True
    assert c.execute("SELECT amount FROM orders WHERE id = ?", (order_id,)).fetchone()[0] == exact


def test_hash_password_rejects_salt_it_could_not_verify():
    # A salt the reader's bound would refuse must not produce a storable record.
    for bad in (b"", b"\x01" * (service.MAX_SALT_BYTES + 1)):
        try:
            service.hash_password("s3cret", salt=bad)
        except ValueError:
            continue
        raise AssertionError("hash_password accepted %d-byte salt" % len(bad))
    # Every salt it does accept verifies, including one at the bound.
    for ok in (b"\x01", b"\x01" * service.MAX_SALT_BYTES):
        assert service.verify_password("s3cret", service.hash_password("s3cret", salt=ok)) is True


def test_hash_password_rejects_work_factor_it_could_not_verify():
    # Same invariant for the work factor: a record verify_password would refuse
    # on its iteration bound must never be storable in the first place.
    for bad in (0, -1, service.MAX_PBKDF2_ITERATIONS + 1):
        try:
            service.hash_password("s3cret", iterations=bad)
        except ValueError:
            continue
        raise AssertionError("hash_password accepted %r iterations" % (bad,))
    at_bound = service.hash_password("s3cret", iterations=1)
    assert service.verify_password("s3cret", at_bound) is True


def test_login_rejects_oversized_salt_record():
    c = setup_db()
    oversized = "$".join((service.HASH_PREFIX, "1", "ab" * 1_000_000, "bb"))
    c.execute("UPDATE users SET password_hash = ? WHERE id = 1", (oversized,))
    assert service.login(c, 1, "s3cret") is False
    # Just over the bound is rejected; a real-length salt still verifies.
    just_over = "$".join(
        (service.HASH_PREFIX, "1", "a" * (service.MAX_SALT_HEX_CHARS + 1), "bb")
    )
    assert service.verify_password("s3cret", just_over) is False
    at_bound = service.hash_password("s3cret", salt=b"\x01" * (service.MAX_SALT_HEX_CHARS // 2))
    assert service.verify_password("s3cret", at_bound) is True
    assert service.verify_password("wrong", at_bound) is False

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
