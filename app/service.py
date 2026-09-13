import sqlite3
import hashlib
import hmac
import secrets

PBKDF2_ITERATIONS = 200_000
SALT_BYTES = 16


def get_user(conn, user_id):
    cur = conn.cursor()
    cur.execute("SELECT id, email FROM users WHERE id = ?", (user_id,))
    return cur.fetchone()


def hash_password(pw: str, salt: bytes = None) -> str:
    """Return a salted PBKDF2-SHA256 digest as "<salt_hex>$<digest_hex>"."""
    if salt is None:
        salt = secrets.token_bytes(SALT_BYTES)
    digest = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, PBKDF2_ITERATIONS)
    return f"{salt.hex()}${digest.hex()}"


def verify_password(pw: str, stored: str) -> bool:
    salt_hex, sep, digest_hex = (stored or "").partition("$")
    if not sep or not digest_hex:
        return False
    try:
        salt = bytes.fromhex(salt_hex)
    except ValueError:
        return False
    return hmac.compare_digest(hash_password(pw, salt), stored)


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
