import sqlite3
import hashlib
import hmac
import math
import os

PBKDF2_ITERATIONS = 200_000
SALT_BYTES = 16
HASH_PREFIX = "pbkdf2_sha256"

_dummy_record = None


def init_schema(conn):
    """Create the tables the service needs and upgrade older ones. Idempotent."""
    cur = conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, email TEXT, password_hash TEXT)")
    cur.execute("CREATE TABLE IF NOT EXISTS orders(id INTEGER PRIMARY KEY, user_id INT, amount REAL)")
    cur.execute("CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, user_id INT)")
    columns = {row[1] for row in cur.execute("PRAGMA table_info(users)")}
    if "password_hash" not in columns:
        cur.execute("ALTER TABLE users ADD COLUMN password_hash TEXT")
    conn.commit()


def get_user(conn, user_id):
    cur = conn.cursor()
    cur.execute("SELECT id, email FROM users WHERE id = ?", (user_id,))
    return cur.fetchone()


def hash_password(pw: str, salt: bytes = None, iterations: int = PBKDF2_ITERATIONS) -> str:
    """Derive a self-describing password record with a fresh per-password salt."""
    if salt is None:
        salt = os.urandom(SALT_BYTES)
    digest = hashlib.pbkdf2_hmac('sha256', pw.encode(), salt, iterations).hex()
    return "{}${}${}${}".format(HASH_PREFIX, iterations, salt.hex(), digest)


def verify_password(pw: str, stored: str) -> bool:
    """Check pw against a stored record, accepting the legacy bare SHA-256 format."""
    if not stored:
        return False
    parts = stored.split("$")
    if len(parts) == 4 and parts[0] == HASH_PREFIX:
        try:
            candidate = hashlib.pbkdf2_hmac(
                'sha256', pw.encode(), bytes.fromhex(parts[2]), int(parts[1])
            ).hex()
        except ValueError:
            return False
        return hmac.compare_digest(candidate, parts[3])
    # Records written before PBKDF2 held a bare SHA-256 hexdigest.
    return hmac.compare_digest(hashlib.sha256(pw.encode()).hexdigest(), stored)


def _dummy_hash():
    """A throwaway record so an unknown user costs the same derivation as a real one."""
    global _dummy_record
    if _dummy_record is None:
        _dummy_record = hash_password(os.urandom(SALT_BYTES).hex())
    return _dummy_record


def _check_amount(amount):
    if isinstance(amount, bool) or not isinstance(amount, (int, float)):
        raise ValueError("amount must be a number")
    if not math.isfinite(amount):
        raise ValueError("amount must be finite")
    if amount <= 0:
        raise ValueError("amount must be positive")


def create_order(conn, user_id, amount):
    _check_amount(amount)
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
    _check_amount(amount)
    cur = conn.cursor()
    cur.execute("UPDATE orders SET amount = ? WHERE id = ?", (amount, order_id))
    updated = cur.rowcount > 0
    conn.commit()
    return updated


def safe_commit(conn):
    cur = conn.cursor()
    conn.commit()
    return True


def login(conn, user_id, pw):
    cur = conn.cursor()
    cur.execute("SELECT password_hash FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    stored = row[0] if row else None
    if not stored:
        # Derive anyway so a missing user is not distinguishable by response time.
        verify_password(pw, _dummy_hash())
        return False
    if not verify_password(pw, stored):
        return False
    if not stored.startswith(HASH_PREFIX + "$"):
        # The password checked out against a legacy record, so re-store it salted.
        cur.execute("UPDATE users SET password_hash = ? WHERE id = ?", (hash_password(pw), user_id))
        conn.commit()
    return True
