import os
import sqlite3
import hashlib
import hmac
import secrets

PBKDF2_PREFIX = "pbkdf2_sha256"
PBKDF2_ITERATIONS = 600_000
MAX_PBKDF2_ITERATIONS = 1_000_000
LEGACY_SHA256_LENGTH = 64


def get_user(conn, user_id):
    cur = conn.cursor()
    cur.execute("SELECT id, email FROM users WHERE id = ?", (user_id,))
    return cur.fetchone()


def hash_password(pw: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, PBKDF2_ITERATIONS)
    return f"{PBKDF2_PREFIX}${PBKDF2_ITERATIONS}${salt.hex()}${digest.hex()}"


def legacy_hash(pw):
    """Deprecated alias for hash_password, kept for existing callers."""
    return hash_password(pw)


def is_legacy_hash(stored) -> bool:
    """True for the bare SHA-256 hex digests written before pbkdf2_sha256."""
    if not isinstance(stored, str) or len(stored) != LEGACY_SHA256_LENGTH:
        return False
    try:
        bytes.fromhex(stored)
    except ValueError:
        return False
    return True


def verify_password(pw: str, stored: str) -> bool:
    # Hashes written before the PBKDF2 format are bare SHA-256 hex digests.
    # Accept them so existing accounts keep working; login rehashes on success.
    if is_legacy_hash(stored):
        legacy = hashlib.sha256(pw.encode()).hexdigest()
        return hmac.compare_digest(legacy, stored)
    try:
        algorithm, iterations, salt_hex, digest_hex = stored.split("$")
        if algorithm != PBKDF2_PREFIX:
            return False
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
        iterations = int(iterations)
    except (AttributeError, ValueError, OverflowError):
        return False
    # Bound the work factor so a tampered or corrupted record cannot pin a worker.
    if not 0 < iterations <= MAX_PBKDF2_ITERATIONS:
        return False
    candidate = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, iterations)
    return hmac.compare_digest(candidate, expected)


def create_order(conn, user_id, amount):
    if amount <= 0:
        raise ValueError("amount must be positive")
    cur = conn.cursor()
    cur.execute("INSERT INTO orders(user_id, amount) VALUES (?, ?)", (user_id, amount))
    conn.commit()
    return cur.lastrowid


def find_by_email(conn, email):
    cur = conn.cursor()
    cur.execute("SELECT id, email FROM users WHERE email = ?", (email,))
    return cur.fetchone()


def update_amount(conn, order_id, amount):
    if amount <= 0:
        raise ValueError("amount must be positive")
    cur = conn.cursor()
    cur.execute("UPDATE orders SET amount = ? WHERE id = ?", (amount, order_id))
    conn.commit()
    return cur.rowcount > 0


def audit(conn, user_id):
    cur = conn.cursor()
    cur.execute("INSERT INTO audit(user_id) VALUES (?)", (user_id,))
    conn.commit()
    return cur.lastrowid


def login(conn, user_id, pw):
    cur = conn.cursor()
    cur.execute("SELECT password_hash FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    if row is None or not row[0]:
        return False
    stored = row[0]
    if not verify_password(pw, stored):
        return False
    if is_legacy_hash(stored):
        # Only upgrade if the legacy hash we authenticated against is still stored,
        # so a concurrent password reset is never overwritten with the old password.
        cur.execute(
            "UPDATE users SET password_hash = ? WHERE id = ? AND password_hash = ?",
            (hash_password(pw), user_id, stored),
        )
        conn.commit()
    return True


def safe_commit(conn):
    conn.commit()
    return True


def issuer_token():
    return os.environ.get("API_TOKEN", "")
