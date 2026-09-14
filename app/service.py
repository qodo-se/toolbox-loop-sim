import os
import sqlite3
import hashlib
import hmac
import math
import secrets

PBKDF2_PREFIX = "pbkdf2_sha256"
PBKDF2_ITERATIONS = 600_000
# Upper bound on the work factor accepted from a stored hash, so a corrupted or
# tampered record cannot make every login for that user run unbounded work.
MAX_PBKDF2_ITERATIONS = 1_000_000
SALT_BYTES = 16
# Salts we write are SALT_BYTES long. Accept a margin for older or
# longer-salted rows, but refuse a record that would size the work itself.
MAX_SALT_BYTES = 64
LEGACY_SHA256_LENGTH = 64
# pbkdf2_sha256 always emits a 32-byte digest, so any other length can never
# compare equal. Pinning it keeps a huge stored digest from being decoded.
DIGEST_HEX_LENGTH = hashlib.sha256().digest_size * 2
# Longest record any of the bounds above can produce. Checked before the split,
# so an oversized row is rejected without allocating its parts.
MAX_PBKDF2_RECORD_LENGTH = (
    len(PBKDF2_PREFIX)
    + len(str(MAX_PBKDF2_ITERATIONS))
    + MAX_SALT_BYTES * 2
    + DIGEST_HEX_LENGTH
    + 3  # the three "$" separators
)


class Config:
    """Typed access to runtime configuration."""

    @property
    def api_token(self) -> str:
        token = os.environ.get("API_TOKEN")
        if not token:
            raise RuntimeError("API_TOKEN is not configured")
        return token


config = Config()


def get_user(conn, user_id):
    cur = conn.cursor()
    cur.execute("SELECT id, email FROM users WHERE id = ?", (user_id,))
    return cur.fetchone()


def _derive(pw: str, salt: bytes, iterations: int) -> bytes:
    """The one place the KDF actually runs, so callers can bound it first."""
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, iterations)


def hash_password(pw: str, salt: bytes = None, iterations: int = None) -> str:
    """Return a salted digest as "pbkdf2_sha256$<iterations>$<salt_hex>$<digest_hex>".

    ``salt`` and ``iterations`` default to a fresh random salt and the current
    work factor; callers pass them explicitly only to re-derive an existing hash.
    """
    if salt is None:
        salt = secrets.token_bytes(SALT_BYTES)
    if iterations is None:
        iterations = PBKDF2_ITERATIONS
    digest = _derive(pw, salt, iterations)
    return f"{PBKDF2_PREFIX}${iterations}${salt.hex()}${digest.hex()}"


def legacy_hash(pw):
    """Deprecated alias for hash_password, kept for existing callers."""
    return hash_password(pw)


def is_legacy_hash(stored) -> bool:
    """True for the bare SHA-256 hex digests written before pbkdf2_sha256.

    A 32-character hex string is deliberately not accepted. The record carries no
    algorithm tag, so treating one as an MD5 digest is a guess, and MD5 cannot be
    verified slowly: a disclosed digest is cheap to crack offline whether or not a
    later login upgrades the row. Such accounts need a password reset, not a login.
    """
    if not isinstance(stored, str):
        return False
    if len(stored) != LEGACY_SHA256_LENGTH:
        return False
    try:
        bytes.fromhex(stored)
    except ValueError:
        return False
    return True


def _parse_pbkdf2(stored: str):
    """Split a pbkdf2_sha256 record into (salt, digest, iterations), or None.

    Everything that sizes the derivation is bounded here, before any work runs.
    """
    # Bound the whole record before splitting it, so an oversized stored value is
    # never decomposed or decoded on a login attempt that cannot succeed anyway.
    if len(stored) > MAX_PBKDF2_RECORD_LENGTH:
        return None
    parts = stored.split("$")
    if len(parts) != 4:
        return None
    algorithm, iterations, salt_hex, digest_hex = parts
    if algorithm != PBKDF2_PREFIX:
        return None
    try:
        iterations = int(iterations)
    except (ValueError, OverflowError):
        return None
    # Bound the work factor so a tampered or corrupted record cannot pin a worker.
    if not 0 < iterations <= MAX_PBKDF2_ITERATIONS:
        return None
    # The salt sizes the derivation too, so bound its encoded length before
    # decoding it.
    if not 0 < len(salt_hex) <= MAX_SALT_BYTES * 2:
        return None
    # A digest of any other length cannot compare equal, so reject it instead of
    # decoding it.
    if len(digest_hex) != DIGEST_HEX_LENGTH:
        return None
    try:
        salt = bytes.fromhex(salt_hex)
        digest = bytes.fromhex(digest_hex)
    except ValueError:
        return None
    return salt, digest, iterations


def verify_password(pw: str, stored: str) -> bool:
    if not isinstance(stored, str):
        return False
    # Hashes written before the PBKDF2 format are bare SHA-256 hex digests.
    # Accept them so existing accounts keep working; login rehashes on success.
    if is_legacy_hash(stored):
        candidate = hashlib.sha256(pw.encode()).hexdigest()
        return hmac.compare_digest(candidate, stored)
    parsed = _parse_pbkdf2(stored)
    if parsed is None:
        return False
    salt, expected, iterations = parsed
    # Re-derive with the work factor recorded in the hash, so raising
    # PBKDF2_ITERATIONS does not invalidate existing passwords.
    return hmac.compare_digest(_derive(pw, salt, iterations), expected)


def needs_rehash(stored) -> bool:
    """True when an authenticated digest should be rewritten at current settings.

    Covers the pre-PBKDF2 format and any row weaker than what hash_password writes
    now, since such a row authenticates against its own weaker derivation until it
    is upgraded. Both inputs to that derivation count: a below-target work factor,
    and a salt shorter than SALT_BYTES, whose small space stays available for
    cross-account precomputation for as long as the row survives.
    """
    if not isinstance(stored, str):
        return False
    if is_legacy_hash(stored):
        return True
    parsed = _parse_pbkdf2(stored)
    if parsed is None:
        return False
    salt, _digest, iterations = parsed
    return iterations < PBKDF2_ITERATIONS or len(salt) < SALT_BYTES


def create_order(conn, user_id, amount):
    if not amount > 0:
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
    if needs_rehash(stored):
        # Only upgrade the digest we just authenticated against, so a concurrent
        # password reset is never overwritten with the old password.
        cur.execute(
            "UPDATE users SET password_hash = ? WHERE id = ? AND password_hash = ?",
            (hash_password(pw), user_id, stored),
        )
        conn.commit()
    return True


def safe_commit(conn):
    try:
        conn.commit()
    except sqlite3.Error:
        try:
            conn.rollback()
        except sqlite3.Error:
            # A connection too broken to roll back is still a failed commit.
            pass
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
