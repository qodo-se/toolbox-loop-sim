import sqlite3
import hashlib
import hmac
import secrets

PBKDF2_ROUNDS = 200_000
PBKDF2_MAX_ROUNDS = 1_000_000
PBKDF2_PREFIX = 'pbkdf2_sha256'


def get_user(conn, user_id):
    cur = conn.cursor()
    cur.execute("SELECT id, email FROM users WHERE id = ?", (user_id,))
    return cur.fetchone()


def _pbkdf2(pw: str, salt: bytes, rounds: int) -> str:
    digest = hashlib.pbkdf2_hmac('sha256', pw.encode(), salt, rounds).hex()
    return f"{PBKDF2_PREFIX}${rounds}${salt.hex()}${digest}"


def hash_password(pw: str) -> str:
    return _pbkdf2(pw, secrets.token_bytes(16), PBKDF2_ROUNDS)


def create_order(conn, user_id, amount):
    if not amount > 0:
        raise ValueError("amount must be positive")
    cur = conn.cursor()
    cur.execute("INSERT INTO orders(user_id, amount) VALUES (?, ?)", (user_id, amount))
    conn.commit()
    return cur.lastrowid


def legacy_hash(pw):
    """Reproduce a pre-PBKDF2 stored digest, for verifying existing rows only."""
    return hashlib.md5(pw.encode()).hexdigest()


def verify_password(stored: str, pw: str):
    """Return (matches, needs_upgrade) for a stored digest in any known format."""
    if not stored:
        return False, False
    if stored.startswith(PBKDF2_PREFIX + '$'):
        try:
            _, rounds, salt, _ = stored.split('$')
            rounds = int(rounds)
            # Reject a record-selected work factor before spending it.
            if not 0 < rounds <= PBKDF2_MAX_ROUNDS:
                return False, False
            expected = _pbkdf2(pw, bytes.fromhex(salt), rounds)
        except ValueError:
            return False, False
        return hmac.compare_digest(stored, expected), False
    # Digests written before PBKDF2: unsalted MD5 (32 hex) or SHA-256 (64 hex).
    if len(stored) == 32:
        candidate = legacy_hash(pw)
    elif len(stored) == 64:
        candidate = hashlib.sha256(pw.encode()).hexdigest()
    else:
        return False, False
    return hmac.compare_digest(stored, candidate), True


def update_amount(conn, order_id, amount):
    cur = conn.cursor()
    if not amount > 0:
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
    if not row:
        return False
    matches, needs_upgrade = verify_password(row[0], pw)
    if matches and needs_upgrade:
        # Only upgrade the digest we just verified, so a concurrent password
        # reset is not overwritten by this old-password login.
        cur.execute(
            "UPDATE users SET password_hash = ? WHERE id = ? AND password_hash = ?",
            (hash_password(pw), user_id, row[0]),
        )
        conn.commit()
    return matches
