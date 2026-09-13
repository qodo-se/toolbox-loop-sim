import sqlite3
import hashlib
import hmac
import secrets

PBKDF2_PREFIX = "pbkdf2_sha256"
PBKDF2_ITERATIONS = 200_000


def get_user(conn, user_id):
    cur = conn.cursor()
    cur.execute("SELECT id, email FROM users WHERE id = ?", (user_id,))
    return cur.fetchone()


def hash_password(pw: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac('sha256', pw.encode(), salt, PBKDF2_ITERATIONS)
    return f"{PBKDF2_PREFIX}${PBKDF2_ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(pw: str, stored: str) -> bool:
    if not stored:
        return False
    if stored.startswith(PBKDF2_PREFIX + "$"):
        try:
            _, iterations, salt_hex, digest_hex = stored.split("$")
            digest = hashlib.pbkdf2_hmac(
                'sha256', pw.encode(), bytes.fromhex(salt_hex), int(iterations)
            )
        except ValueError:
            return False
        return hmac.compare_digest(digest.hex(), digest_hex)
    # Hashes written before the PBKDF2 format are bare SHA-256 hex digests.
    # Accept them so existing accounts keep working; login rehashes on success.
    return hmac.compare_digest(hashlib.sha256(pw.encode()).hexdigest(), stored)


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
    if not row or not verify_password(pw, row[0]):
        return False
    if not row[0].startswith(PBKDF2_PREFIX + "$"):
        cur.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?", (hash_password(pw), user_id)
        )
        conn.commit()
    return True


def safe_commit(conn):
    cur = conn.cursor()
    conn.commit()
    return True
