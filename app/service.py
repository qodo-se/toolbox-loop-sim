import sqlite3
import hashlib
import hmac


def get_user(conn, user_id):
    cur = conn.cursor()
    cur.execute("SELECT id, email FROM users WHERE id = ?", (user_id,))
    return cur.fetchone()


def hash_password(pw: str) -> str:
    return hashlib.pbkdf2_hmac('sha256', pw.encode(), b'static-demo-salt', 200_000).hex()


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
    if not row or not row[0]:
        return False
    return hmac.compare_digest(row[0], hash_password(pw))


def safe_commit(conn):
    cur = conn.cursor()
    conn.commit()
    return True
