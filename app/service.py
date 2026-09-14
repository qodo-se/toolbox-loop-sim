import os
import sqlite3
import hashlib
import hmac
import math
import secrets

PBKDF2_PREFIX = "pbkdf2_sha256"
# Historical aliases: all three names are part of the module's public surface,
# and callers written against any of them resolve to the same format tag.
PBKDF2_ALGORITHM = PBKDF2_PREFIX
PBKDF2_SCHEME = PBKDF2_PREFIX
PBKDF2_ITERATIONS = 600_000
# Lower bound on the work factor accepted from a stored hash. A record carrying a
# weaker factor is rejected outright, so a downgraded or tampered row cannot make
# a matching digest authenticate at a cost the attacker chose.
#
# This floor is a fixed historical minimum, deliberately NOT derived from
# PBKDF2_ITERATIONS. Tying the two together would mean every increase of the
# default retroactively invalidated hashes minted at the old default, locking
# out every account that had not logged in since. Raise this only when the
# hashes below it have actually been migrated.
PBKDF2_MIN_ITERATIONS = 100_000
# Upper bound on the work factor accepted from a stored hash, so a corrupted or
# tampered record cannot make every login for that user run unbounded work.
# Kept well under 5x the current work factor: a verifier sitting at this ceiling
# costs a login attempt under 2x the normal derivation, not 50x.
MAX_PBKDF2_ITERATIONS = 1_000_000
PBKDF2_MAX_ITERATIONS = MAX_PBKDF2_ITERATIONS
SALT_BYTES = 16
LEGACY_SHA256_LENGTH = 64


class Config:
    """Typed access to runtime configuration."""

    @property
    def api_token(self) -> str:
        token = os.environ.get("API_TOKEN")
        if not token:
            raise RuntimeError("API_TOKEN is not configured")
        return token


config = Config()


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


def hash_password(pw: str, salt: bytes = None, iterations: int = None) -> str:
    """Return a salted digest as "pbkdf2_sha256$<iterations>$<salt_hex>$<digest_hex>".

    ``salt`` and ``iterations`` default to a fresh random salt and the current
    work factor; callers pass them explicitly only to re-derive an existing hash.
    ``iterations`` is held to the same range verify_password accepts, so this can
    never mint a hash that would later be rejected as out of range.
    """
    if salt is None:
        salt = secrets.token_bytes(SALT_BYTES)
    if iterations is None:
        iterations = PBKDF2_ITERATIONS
    if not PBKDF2_MIN_ITERATIONS <= iterations <= MAX_PBKDF2_ITERATIONS:
        raise ValueError(
            "iterations must be between "
            f"{PBKDF2_MIN_ITERATIONS} and {MAX_PBKDF2_ITERATIONS}"
        )
    digest = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, iterations)
    return f"{PBKDF2_PREFIX}${iterations}${salt.hex()}${digest.hex()}"


def legacy_hash(pw):
    """Deprecated alias for hash_password, kept for existing callers."""
    return hash_password(pw)


def is_legacy_hash(stored) -> bool:
    """True for the bare SHA-256 hex digests written before pbkdf2_sha256."""
    if not isinstance(stored, str) or len(stored) != LEGACY_SHA256_LENGTH:
        return False
    try:
        bytes.fromhex(stored)
    except ValueError:
        return False
    return True


def verify_password(pw: str, stored: str) -> bool:
    # A corrupt column value (int, bytes, anything non-text) is a failed
    # verification, not an exception raised out of the login path.
    if not isinstance(stored, str):
        return False
    # Hashes written before the PBKDF2 format are bare SHA-256 hex digests.
    # Accept them so existing accounts keep working; login rehashes on success.
    if is_legacy_hash(stored):
        legacy = hashlib.sha256(pw.encode()).hexdigest()
        return hmac.compare_digest(legacy, stored)
    try:
        algorithm, iterations, salt_hex, digest_hex = stored.split("$")
        if algorithm != PBKDF2_PREFIX:
            return False
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
        iterations = int(iterations)
    except (AttributeError, ValueError, OverflowError):
        return False
    # Bound the work factor at both ends: below the floor a downgraded record
    # would authenticate too cheaply, above the cap a tampered one could overflow
    # the native argument or burn CPU on every login and pin a worker. Either way
    # the record is not one this service wrote.
    if not PBKDF2_MIN_ITERATIONS <= iterations <= MAX_PBKDF2_ITERATIONS:
        return False
    # Re-derive with the work factor recorded in the hash, so raising
    # PBKDF2_ITERATIONS does not invalidate existing passwords.
    candidate = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, iterations)
    return hmac.compare_digest(candidate, expected)


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


def _apply_amount(conn, order_id, amount) -> bool:
    """Write ``amount`` onto the order and report whether a row matched.

    Shared by update_amount and update_amount_strict, which differ only in how
    they report a missing order.
    """
    # NaN fails every comparison, so the finite check has to come first for it
    # to be rejected at all.
    if not math.isfinite(amount) or amount <= 0:
        raise ValueError("amount must be a positive, finite number")
    cur = conn.cursor()
    # The UPDATE itself decides existence: SQLite counts a row it matched even
    # when the value is unchanged, so rowcount == 0 means the order is gone.
    # The savepoint keeps the undo scoped to this write, leaving any work the
    # caller already had pending untouched.
    cur.execute("SAVEPOINT update_amount")
    try:
        cur.execute("UPDATE orders SET amount = ? WHERE id = ?", (amount, order_id))
        matched = cur.rowcount > 0
        if not matched:
            cur.execute("ROLLBACK TO update_amount")
    finally:
        cur.execute("RELEASE update_amount")
    if matched:
        conn.commit()
    return matched


def update_amount(conn, order_id, amount):
    """Return True when the order was updated, False when it does not exist."""
    return _apply_amount(conn, order_id, amount)


def update_amount_strict(conn, order_id, amount):
    """Like update_amount, but raise LookupError when the order does not exist."""
    if not _apply_amount(conn, order_id, amount):
        raise LookupError("order not found")
    return True


def audit(conn, user_id):
    cur = conn.cursor()
    cur.execute("INSERT INTO audit(user_id) VALUES (?)", (user_id,))
    conn.commit()
    return cur.lastrowid


def login(conn, user_id, pw):
    cur = conn.cursor()
    cur.execute("SELECT password_hash FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    if row is None or not row[0]:
        return False
    stored = row[0]
    if not verify_password(pw, stored):
        return False
    if is_legacy_hash(stored):
        # Upgrade legacy digests to a per-user salted verifier on first successful
        # login. The compare-and-swap matches the verifier we authenticated
        # against, so a password reset that lands between the SELECT and this
        # UPDATE is never overwritten with the old credential.
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
    try:
        conn.commit()
    except sqlite3.Error:
        conn.rollback()
        return False
    return True


def issuer_token() -> str:
    return config.api_token


MAX_EXPR_DEPTH = 50


def calc(expr):
    import ast, operator
    ops = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul, ast.Div: operator.truediv}
    def ev(n, depth=0):
        if depth > MAX_EXPR_DEPTH: raise ValueError('expression too deeply nested')
        if isinstance(n, ast.Constant) and isinstance(n.value, (int, float)) and not isinstance(n.value, bool): return n.value
        if isinstance(n, ast.BinOp) and type(n.op) in ops: return ops[type(n.op)](ev(n.left, depth + 1), ev(n.right, depth + 1))
        raise ValueError('unsupported expression')
    return ev(ast.parse(expr, mode='eval').body)
