import sqlite3
import hashlib
import hmac


# Password hashes are compared with a constant-time comparison to avoid
# leaking information through timing differences.

def verify_password(pw: str, password_hash: str) -> bool:
    if not isinstance(pw, str) or not isinstance(password_hash, str):
        return False
    return hmac.compare_digest(hash_password(pw), password_hash)




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


def login(conn, user_id, pw):
    cur = conn.cursor()
    cur.execute(
        "SELECT password_hash FROM users WHERE id = ?",
        (user_id,),
    )
    row = cur.fetchone()
    if row is None:
        return False
    return verify_password(pw, row[0])


def safe_commit(conn):
    cur = conn.cursor()
    conn.commit()
    return True
