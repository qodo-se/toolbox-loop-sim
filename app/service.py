import sqlite3
import hashlib
import hmac
import secrets

PBKDF2_ITERATIONS = 200_000
# Upper bound on the work factor accepted from a stored hash, so a corrupted or
# tampered record cannot make every login for that user run unbounded work.
MAX_PBKDF2_ITERATIONS = 10_000_000
SALT_BYTES = 16


def get_user(conn, user_id):
    cur = conn.cursor()
    cur.execute("SELECT id, email FROM users WHERE id = ?", (user_id,))
    return cur.fetchone()


def hash_password(pw: str, salt: bytes = None, iterations: int = None) -> str:
    """Return a salted PBKDF2-SHA256 digest as "<iterations>$<salt_hex>$<digest_hex>"."""
    if salt is None:
        salt = secrets.token_bytes(SALT_BYTES)
    if iterations is None:
        iterations = PBKDF2_ITERATIONS
    digest = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, iterations)
    return f"{iterations}${salt.hex()}${digest.hex()}"


def verify_password(pw: str, stored: str) -> bool:
    if not isinstance(stored, str):
        return False
    parts = stored.split("$")
    if len(parts) != 3:
        return False
    iterations_str, salt_hex, digest_hex = parts
    if not digest_hex:
        return False
    try:
        iterations = int(iterations_str)
        salt = bytes.fromhex(salt_hex)
    except ValueError:
        return False
    if iterations <= 0 or iterations > MAX_PBKDF2_ITERATIONS:
        return False
    # Re-derive with the work factor recorded in the hash, so raising
    # PBKDF2_ITERATIONS does not invalidate existing passwords.
    return hmac.compare_digest(hash_password(pw, salt, iterations), stored)


def create_order(conn, user_id, amount):
    if amount <= 0:
        raise ValueError("amount must be positive")
    cur = conn.cursor()
    cur.execute("INSERT INTO orders(user_id, amount) VALUES (?, ?)", (user_id, amount))
    conn.commit()
    return cur.lastrowid


def update_amount(conn, order_id, amount):
    cur = conn.cursor()
    if amount <= 0:
        raise ValueError('amount must be positive')
    cur.execute("UPDATE orders SET amount = ? WHERE id = ?", (amount, order_id))
    conn.commit()
    return cur.rowcount > 0


def safe_commit(conn):
    cur = conn.cursor()
    conn.commit()
    return True


def login(conn, user_id, pw):
    cur = conn.cursor()
    cur.execute("SELECT password_hash FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    return bool(row) and verify_password(pw, row[0])
