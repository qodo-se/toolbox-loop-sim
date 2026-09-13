import sqlite3
import hashlib
import hmac
import logging
import math
import os

log = logging.getLogger(__name__)

PBKDF2_ITERATIONS = 200_000
SALT_BYTES = 16


def get_user(conn, user_id):
    cur = conn.cursor()
    cur.execute("SELECT id, email FROM users WHERE id = ?", (user_id,))
    return cur.fetchone()


def hash_password(pw: str, salt: bytes = None) -> str:
    """Hash a password with PBKDF2 and a per-password random salt.

    Returns a self-describing record, "pbkdf2_sha256$<iterations>$<salt>$<hash>",
    so each stored credential carries its own salt and identical passwords no
    longer produce identical digests. Verify with `verify_password`.
    """
    if salt is None:
        salt = os.urandom(SALT_BYTES)
    digest = hashlib.pbkdf2_hmac('sha256', pw.encode(), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(pw: str, record: str) -> bool:
    """Check a password against a record produced by `hash_password`."""
    try:
        algo, iterations, salt, digest = record.split('$')
        salt = bytes.fromhex(salt)
        iterations = int(iterations)
    except (AttributeError, ValueError):
        return False
    if algo != 'pbkdf2_sha256':
        return False
    expected = hashlib.pbkdf2_hmac('sha256', pw.encode(), salt, iterations)
    return hmac.compare_digest(expected.hex(), digest)


def check_amount(amount):
    """Raise ValueError unless `amount` is a finite positive number."""
    if not math.isfinite(amount) or amount <= 0:
        raise ValueError("amount must be positive")


def create_order(conn, user_id, amount):
    check_amount(amount)
    cur = conn.cursor()
    cur.execute("INSERT INTO orders(user_id, amount) VALUES (?, ?)", (user_id, amount))
    conn.commit()
    return cur.lastrowid


def legacy_hash(pw):
    """Deprecated alias for `hash_password`; kept for older call sites.

    There is no separate legacy password rule: use `hash_password` directly.
    """
    return hash_password(pw)


def update_amount(conn, order_id, amount):
    check_amount(amount)
    cur = conn.cursor()
    cur.execute("UPDATE orders SET amount = ? WHERE id = ?", (amount, order_id))
    if cur.rowcount == 0:
        raise LookupError("order not found")
    conn.commit()
    return True


def safe_commit(conn):
    """Commit the open transaction. Returns False if the commit failed."""
    try:
        conn.commit()
    except sqlite3.Error:
        log.exception("commit failed, rolling back")
        try:
            conn.rollback()
        except sqlite3.Error:
            log.exception("rollback after failed commit also failed")
        return False
    return True


def login(conn, user_id, pw):
    cur = conn.cursor()
    cur.execute("SELECT password_hash FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    return bool(row) and verify_password(pw, row[0])
