import sqlite3
import hashlib
import hmac
import math
import os

PBKDF2_ITERATIONS = 240000
# Upper bound on the iteration count accepted from a stored record, so a
# malformed or hostile value cannot overflow the native API or stall a login.
MAX_PBKDF2_ITERATIONS = 1000000
# Upper bounds on the decoded salt and digest a stored record may carry. We
# write 16 and 32 bytes; anything far past that is corrupt or hostile, and
# decoding it unbounded lets one row dictate a login's memory and CPU.
MAX_SALT_BYTES = 64
MAX_DIGEST_BYTES = 64
PBKDF2_PREFIX = "pbkdf2_sha256$"


def get_user(conn, user_id):
    cur = conn.cursor()
    cur.execute("SELECT id, email FROM users WHERE id = ?", (user_id,))
    return cur.fetchone()


def hash_password(pw: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, PBKDF2_ITERATIONS)
    return "{}{}${}${}".format(
        PBKDF2_PREFIX, PBKDF2_ITERATIONS, salt.hex(), digest.hex()
    )


def verify_password(stored: str, pw: str) -> bool:
    if not isinstance(stored, str) or not stored:
        return False
    if stored.startswith(PBKDF2_PREFIX):
        try:
            _, iterations, salt_hex, digest_hex = stored.split("$")
            rounds = int(iterations)
            if not 0 < rounds <= MAX_PBKDF2_ITERATIONS:
                return False
            # Check the encoded lengths before decoding, so an oversized field
            # is rejected without allocating it.
            if len(salt_hex) > 2 * MAX_SALT_BYTES:
                return False
            if len(digest_hex) > 2 * MAX_DIGEST_BYTES:
                return False
            salt = bytes.fromhex(salt_hex)
            expected = bytes.fromhex(digest_hex)
            digest = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, rounds)
        except ValueError:
            return False
        # Compare raw bytes inside the same guarded path. compare_digest raises
        # TypeError on non-ASCII str, so comparing the hex text would turn a
        # corrupt record into a crash instead of a failed authentication.
        return hmac.compare_digest(digest, expected)
    # Accounts created before the PBKDF2 format still store a bare SHA-256
    # digest; keep verifying those so upgrading does not lock them out.
    legacy = hashlib.sha256(pw.encode()).hexdigest()
    return hmac.compare_digest(legacy, stored)


def create_order(conn, user_id, amount):
    if amount <= 0:
        raise ValueError("amount must be positive")
    cur = conn.cursor()
    cur.execute("INSERT INTO orders(user_id, amount) VALUES (?, ?)", (user_id, amount))
    conn.commit()
    return cur.lastrowid


def audit(conn, user_id):
    cur = conn.cursor()
    cur.execute("INSERT INTO audit(user_id) VALUES (?)", (user_id,))
    conn.commit()
    return cur.lastrowid


def update_amount(conn, order_id, amount):
    cur = conn.cursor()
    if not math.isfinite(amount) or amount <= 0:
        raise ValueError('amount must be positive')
    cur.execute("UPDATE orders SET amount = ? WHERE id = ?", (amount, order_id))
    conn.commit()
    return cur.rowcount > 0


def safe_commit(conn):
    try:
        conn.commit()
    except sqlite3.Error:
        return False
    return True


def login(conn, user_id, pw):
    cur = conn.cursor()
    cur.execute("SELECT password_hash FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    if not row or not verify_password(row[0], pw):
        return False
    stored = row[0]
    if not stored.startswith(PBKDF2_PREFIX):
        # The legacy record is only upgradable while we hold the plaintext, so
        # re-hash it here rather than leaving a bare SHA-256 digest stored.
        # Guard on the exact hash we verified: if a password reset commits
        # between the SELECT and this UPDATE, the row no longer matches and the
        # migration is skipped instead of writing the old password over it.
        cur.execute(
            "UPDATE users SET password_hash = ? WHERE id = ? AND password_hash = ?",
            (hash_password(pw), user_id, stored),
        )
        conn.commit()
    return True
