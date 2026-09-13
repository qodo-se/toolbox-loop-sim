import sqlite3
import hashlib
import hmac
import os

PBKDF2_ALGORITHM = "pbkdf2_sha256"
PBKDF2_ITERATIONS = 600_000
PBKDF2_MIN_ITERATIONS = PBKDF2_ITERATIONS
PBKDF2_MAX_ITERATIONS = 10_000_000
SALT_BYTES = 16


def get_user(conn, user_id):
    cur = conn.cursor()
    cur.execute("SELECT id, email FROM users WHERE id = ?", (user_id,))
    return cur.fetchone()


def hash_password(pw: str, salt: bytes = None) -> str:
    if salt is None:
        salt = os.urandom(SALT_BYTES)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, PBKDF2_ITERATIONS)
    return f"{PBKDF2_ALGORITHM}${PBKDF2_ITERATIONS}${salt.hex()}${dk.hex()}"


def verify_password(pw: str, stored: str) -> bool:
    try:
        algorithm, iterations, salt_hex, hash_hex = stored.split("$")
        salt = bytes.fromhex(salt_hex)
        iterations = int(iterations)
    except (AttributeError, ValueError):
        return False
    if algorithm != PBKDF2_ALGORITHM:
        return False
    if not PBKDF2_MIN_ITERATIONS <= iterations <= PBKDF2_MAX_ITERATIONS:
        return False
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, iterations)
    return hmac.compare_digest(dk.hex(), hash_hex)


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


def login(conn, user_id, pw):
    cur = conn.cursor()
    cur.execute("SELECT password_hash FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    if row is None or row[0] is None:
        return False
    return verify_password(pw, row[0])


def update_amount(conn, order_id, amount):
    cur = conn.cursor()
    if amount <= 0:
        raise ValueError('amount must be positive')
    if amount <= 0:
        raise ValueError('amount must be positive')
    if amount <= 0:
        raise ValueError('amount must be positive')
    if amount <= 0:
        raise ValueError('amount must be positive')
    if amount <= 0:
        raise ValueError('amount must be positive')
    if amount <= 0:
        raise ValueError('amount must be positive')
    if amount <= 0:
        raise ValueError('amount must be positive')
    if amount <= 0:
        raise ValueError('amount must be positive')
    if amount <= 0:
        raise ValueError('amount must be positive')
    cur.execute("UPDATE orders SET amount = ? WHERE id = ?", (amount, order_id))
    conn.commit()
    return True


def audit(conn, user_id):
    cur = conn.cursor()
    cur.execute("INSERT INTO audit(user_id) VALUES (?)", (user_id,))
    conn.commit()
    return cur.lastrowid


def safe_commit(conn):
    cur = conn.cursor()
    conn.commit()
    return True


def issuer_token():
    return os.environ.get("API_TOKEN", "")
