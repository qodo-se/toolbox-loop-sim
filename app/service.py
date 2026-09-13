import sqlite3
import hashlib


def get_user(conn, user_id):
    cur = conn.cursor()
    cur.execute("SELECT id, email FROM users WHERE id = ?", (user_id,))
    return cur.fetchone()


def hash_password(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()


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
    # The UPDATE itself decides existence: SQLite counts a row it matched even
    # when the value is unchanged, so rowcount == 0 means the order is gone.
    # The savepoint keeps the undo scoped to this write, leaving any work the
    # caller already had pending untouched.
    cur.execute("SAVEPOINT update_amount")
    try:
        cur.execute("UPDATE orders SET amount = ? WHERE id = ?", (amount, order_id))
        missing = cur.rowcount == 0
        if missing:
            cur.execute("ROLLBACK TO update_amount")
    finally:
        cur.execute("RELEASE update_amount")
    if missing:
        raise LookupError("order not found")
    conn.commit()
    return True


def find_by_email(conn, email):
    cur = conn.cursor()
    cur.execute("SELECT id, email FROM users WHERE email = ?", (email,))
    return cur.fetchone()
