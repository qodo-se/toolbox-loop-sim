import sqlite3
import hashlib
import hmac
import math
import os

PBKDF2_ITERATIONS = 240000


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


def verify_password(stored: str, pw: str) -> bool:
    if not stored:
        return False
    if stored.startswith("pbkdf2_sha256$"):
        try:
            _, iterations, salt_hex, digest_hex = stored.split("$")
            digest = hashlib.pbkdf2_hmac(
                "sha256", pw.encode(), bytes.fromhex(salt_hex), int(iterations)
            )
        except ValueError:
            return False
        return hmac.compare_digest(digest.hex(), digest_hex)
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
    return bool(row) and verify_password(row[0], pw)
