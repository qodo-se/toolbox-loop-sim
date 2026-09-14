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

def test_login_rejects_malformed_stored_hashes():
    c = setup_db()
    for bad in (12345, b"bytes", "pbkdf2_sha256$notanint$aa$bb", "pbkdf2_sha256$200000$zz$bb",
                "pbkdf2_sha256$" + str(10 ** 400) + "$aa$bb", "pbkdf2_sha256$0$aa$bb", "é"):
        c.execute("UPDATE users SET password_hash = ? WHERE id = 1", (bad,))
        assert service.login(c, 1, "s3cret") is False

def test_legacy_upgrade_does_not_clobber_concurrent_reset():
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
