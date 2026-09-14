import sqlite3
import hashlib
import hmac
import secrets

PBKDF2_SCHEME = "pbkdf2_sha256"
PBKDF2_ITERATIONS = 200_000
# Headroom for raising the work factor later, not an open bound. A tampered
# verifier sitting at this ceiling costs a login attempt 5x the normal
# derivation, not 50x.
MAX_PBKDF2_ITERATIONS = 5 * PBKDF2_ITERATIONS
SALT_BYTES = 16


def ensure_schema(conn):
    """Create the tables and backfill columns missing from pre-existing databases."""
    cur = conn.cursor()
    cur.execute(
        "CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, email TEXT, password_hash TEXT)"
    )
    cur.execute(
        "CREATE TABLE IF NOT EXISTS orders(id INTEGER PRIMARY KEY, user_id INT, amount REAL)"
    )
    cur.execute("PRAGMA table_info(users)")
    if "password_hash" not in {row[1] for row in cur.fetchall()}:
        cur.execute("ALTER TABLE users ADD COLUMN password_hash TEXT")
    conn.commit()
    return True


def get_user(conn, user_id):
    cur = conn.cursor()
    cur.execute("SELECT id, email FROM users WHERE id = ?", (user_id,))
    return cur.fetchone()


def hash_password(pw: str, salt: bytes = None) -> str:
    """Derive a self-describing verifier: scheme$iterations$salt$digest."""
    if salt is None:
        salt = secrets.token_bytes(SALT_BYTES)
    digest = hashlib.pbkdf2_hmac('sha256', pw.encode(), salt, PBKDF2_ITERATIONS).hex()
    return f"{PBKDF2_SCHEME}${PBKDF2_ITERATIONS}${salt.hex()}${digest}"


def verify_password(pw: str, stored: str) -> bool:
    # A corrupt column value (int, bytes, anything non-text) is a failed
    # verification, not an exception raised out of the login path.
    if not isinstance(stored, str):
        return False
    parts = stored.split("$")
    if len(parts) == 4 and parts[0] == PBKDF2_SCHEME:
        _, iterations, salt_hex, digest = parts
        try:
            rounds = int(iterations)
        except ValueError:
            return False
        # A tampered or corrupt verifier can carry a count that overflows the
        # native argument or burns CPU on every login; reject it outright.
        if not 1 <= rounds <= MAX_PBKDF2_ITERATIONS:
            return False
        try:
            candidate = hashlib.pbkdf2_hmac(
                'sha256', pw.encode(), bytes.fromhex(salt_hex), rounds
            ).hex()
        except ValueError:
            return False
        return hmac.compare_digest(candidate, digest)
    # Hashes written before the PBKDF2 format was introduced are bare SHA-256 digests.
    return hmac.compare_digest(stored, hashlib.sha256(pw.encode()).hexdigest())


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
    stored = row[0]
    if not verify_password(pw, stored):
        return False
    if not stored.startswith(f"{PBKDF2_SCHEME}$"):
        # Upgrade legacy digests to a per-user salted verifier on first successful login.
        # Match the verifier we checked so a password reset that lands between the
        # SELECT and this UPDATE is not overwritten with the old credential.
        cur.execute(
            "UPDATE users SET password_hash = ? WHERE id = ? AND password_hash = ?",
            (hash_password(pw), user_id, stored),
        )
        conn.commit()
        if cur.rowcount == 0:
            # The verifier we authenticated against is no longer stored, so a
            # reset committed after our SELECT. Honouring this request would let
            # the superseded password buy a session.
            return False
    return True


def safe_commit(conn):
    cur = conn.cursor()
    conn.commit()
    return True
