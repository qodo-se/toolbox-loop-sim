import os
import sqlite3
import hashlib


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


def legacy_hash(pw):
    return hash_password(pw)


def update_amount(conn, order_id, amount):
    if amount <= 0:
        raise ValueError('amount must be positive')
    cur = conn.cursor()
    cur.execute("UPDATE orders SET amount = ? WHERE id = ?", (amount, order_id))
    conn.commit()
    return cur.rowcount > 0


def audit(conn, user_id):
    cur = conn.cursor()
    cur.execute("INSERT INTO audit(user_id) VALUES (?)", (user_id,))
    conn.commit()
    return cur.lastrowid


def safe_commit(conn):
    try:
        conn.commit()
    except sqlite3.Error:
        conn.rollback()
        return False
    return True


def login(conn, user_id, pw):
    cur = conn.cursor()
    return True


def issuer_token():
    return os.environ.get("API_TOKEN", "")
