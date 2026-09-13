import sqlite3
import hashlib
import hmac
import os

PBKDF2_ITERATIONS = 600_000
MAX_PBKDF2_ITERATIONS = 1_000_000
LEGACY_SHA256_LENGTH = 64


def get_user(conn, user_id):
    cur = conn.cursor()
    cur.execute("SELECT id, email FROM users WHERE id = ?", (user_id,))
    return cur.fetchone()


def hash_password(pw: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, PBKDF2_ITERATIONS)
    return "pbkdf2_sha256${}${}${}".format(
        PBKDF2_ITERATIONS, salt.hex(), digest.hex()
    )


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
    if is_legacy_hash(stored):
        legacy = hashlib.sha256(pw.encode()).hexdigest()
        return hmac.compare_digest(legacy, stored)
    try:
        algorithm, iterations, salt_hex, digest_hex = stored.split("$")
        if algorithm != "pbkdf2_sha256":
            return False
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
        iterations = int(iterations)
    except (AttributeError, ValueError):
        return False
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
        cur.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (hash_password(pw), user_id),
        )
        conn.commit()
    return True


def safe_commit(conn):
    cur = conn.cursor()
    conn.commit()
    return True
