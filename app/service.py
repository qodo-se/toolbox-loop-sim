import sqlite3
import hashlib
import hmac
import math
import os

PBKDF2_ITERATIONS = 200_000
MAX_PBKDF2_ITERATIONS = 10_000_000
SALT_BYTES = 16
# Upper bound on the encoded salt accepted from a stored record. Records this
# service writes hold SALT_BYTES * 2 hex chars; the slack covers older or
# longer salts without letting a corrupted field size the allocation.
MAX_SALT_HEX_CHARS = 128
# The writer's own limit, kept in step with the reader's bound so hash_password
# can never serialize a record that verify_password would refuse to decode.
MAX_SALT_BYTES = MAX_SALT_HEX_CHARS // 2
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
    """Derive a self-describing password record with a fresh per-password salt.

    Raises ValueError for a caller-supplied salt verify_password would reject,
    so a record that can be stored can always authenticate.
    """
    if salt is None:
        salt = os.urandom(SALT_BYTES)
    if not salt:
        raise ValueError("salt must not be empty")
    if len(salt) > MAX_SALT_BYTES:
        raise ValueError("salt must be at most %d bytes" % MAX_SALT_BYTES)
    digest = hashlib.pbkdf2_hmac('sha256', pw.encode(), salt, iterations).hex()
    return "{}${}${}${}".format(HASH_PREFIX, iterations, salt.hex(), digest)


def verify_password(pw: str, stored: str) -> bool:
    """Check pw against a stored record, accepting the legacy bare SHA-256 format."""
    # A corrupted or unexpectedly typed record must fail the check, not raise.
    if not stored or not isinstance(stored, str) or not stored.isascii():
        return False
    parts = stored.split("$")
    if len(parts) == 4 and parts[0] == HASH_PREFIX:
        # Bound the salt field before decoding it: an oversized but valid hex
        # salt would otherwise size both the allocation and the PBKDF2 input.
        if not parts[2] or len(parts[2]) > MAX_SALT_HEX_CHARS:
            return False
        try:
            iterations = int(parts[1])
            if not 1 <= iterations <= MAX_PBKDF2_ITERATIONS:
                return False
            candidate = hashlib.pbkdf2_hmac(
                'sha256', pw.encode(), bytes.fromhex(parts[2]), iterations
            ).hex()
        except (ValueError, OverflowError):
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
    """Validate an amount and return the value to bind to the REAL column.

    Returns a float rather than the caller's object: the column has REAL
    affinity anyway, and an int outside SQLite's 64-bit range cannot be bound
    at all, so normalising here keeps large finite totals storable.

    An int that float cannot hold exactly is rejected instead of rounded, so a
    write never persists a total different from the one the caller passed.
    """
    if isinstance(amount, bool) or not isinstance(amount, (int, float)):
        raise ValueError("amount must be a number")
    try:
        as_float = float(amount)
    except OverflowError:
        # An int too large for a float is not a storable total; keep the ValueError contract.
        raise ValueError("amount is out of range")
    if not math.isfinite(as_float):
        raise ValueError("amount must be finite")
    if isinstance(amount, int) and as_float != amount:
        # e.g. 2**63 + 1 rounds down to 2**63; storing that would silently
        # change the caller's total, so refuse the write instead.
        raise ValueError("amount cannot be stored exactly")
    if as_float <= 0:
        raise ValueError("amount must be positive")
    return as_float


def create_order(conn, user_id, amount):
    amount = _check_amount(amount)
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
    amount = _check_amount(amount)
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
        # Match on the hash we read so a password reset that landed in the meantime
        # is not overwritten with the old credential.
        cur.execute(
            "UPDATE users SET password_hash = ? WHERE id = ? AND password_hash = ?",
            (hash_password(pw), user_id, stored),
        )
        conn.commit()
    return True
