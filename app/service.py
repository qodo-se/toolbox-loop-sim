import hashlib
import hmac
import math
import os
import secrets
import sqlite3

PBKDF2_PREFIX = "pbkdf2_sha256"
# Historical alias: both names are part of the module's public surface.
PBKDF2_SCHEME = PBKDF2_PREFIX
PBKDF2_ITERATIONS = 600_000
# Upper bound on the work factor accepted from a stored hash, so a corrupted or
# tampered record cannot make every login for that user run unbounded work.
# Kept well under 5x the current work factor: a verifier sitting at this ceiling
# costs a login attempt under 2x the normal derivation, not 50x.
MAX_PBKDF2_ITERATIONS = 1_000_000
SALT_BYTES = 16
# Upper bounds on the decoded salt and digest a stored record may carry. We
# write 16 and 32 bytes; anything far past that is corrupt or hostile, and
# decoding it unbounded lets one row dictate a login's memory and CPU.
MAX_SALT_BYTES = 64
MAX_DIGEST_BYTES = 64
# Legacy records are bare SHA-256 hex digests, so exactly 64 hex characters.
LEGACY_SHA256_LENGTH = 64


class Config:
    """Typed access to runtime configuration."""

    @property
    def api_token(self) -> str:
        token = os.environ.get("API_TOKEN")
        if not token:
            raise RuntimeError("API_TOKEN is not configured")
        return token

    @property
    def provider_api_key(self) -> str:
        key = os.environ.get("PROVIDER_API_KEY")
        if not key:
            raise RuntimeError("PROVIDER_API_KEY is not configured")
        return key


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


def find_by_email(conn, email):
    cur = conn.cursor()
    cur.execute("SELECT id, email FROM users WHERE email = ?", (email,))
    return cur.fetchone()


def hash_password(pw: str, salt: bytes = None, iterations: int = None) -> str:
    """Return a salted digest as "pbkdf2_sha256$<iterations>$<salt_hex>$<digest_hex>".

    ``salt`` and ``iterations`` default to a fresh random salt and the current
    work factor; callers pass them explicitly only to re-derive an existing hash.
    """
    if salt is None:
        salt = secrets.token_bytes(SALT_BYTES)
    if iterations is None:
        iterations = PBKDF2_ITERATIONS
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
    # verification, not an exception raised out of the login path. An empty
    # string is corrupt too, and is rejected here rather than parsed.
    if not isinstance(stored, str) or not stored:
        return False
    # Hashes written before the PBKDF2 format are bare SHA-256 hex digests.
    # Accept them so existing accounts keep working; login rehashes on success.
    if is_legacy_hash(stored):
        # Compare the decoded bytes, so a field that decodes short (fromhex
        # skips ASCII whitespace) fails the comparison on length rather than
        # matching, and a non-ASCII field cannot reach compare_digest -- it
        # raises TypeError on non-ASCII str, which would surface out of login
        # as a crash instead of a failed authentication.
        legacy = hashlib.sha256(pw.encode()).digest()
        return hmac.compare_digest(legacy, bytes.fromhex(stored))
    # A non-prefixed value that is not one of those digests is corrupt rather
    # than legacy, and falls through to the PBKDF2 parse below, which rejects it.
    try:
        algorithm, iterations, salt_hex, digest_hex = stored.split("$")
    except (AttributeError, ValueError):
        return False
    if algorithm != PBKDF2_PREFIX:
        return False
    try:
        rounds = int(iterations)
    except (ValueError, OverflowError):
        return False
    # A tampered or corrupt verifier can carry a count that overflows the native
    # argument or burns CPU on every login; bound it so it cannot pin a worker.
    if not 0 < rounds <= MAX_PBKDF2_ITERATIONS:
        return False
    # Check the encoded lengths before decoding, so an oversized field is
    # rejected without allocating it.
    if len(salt_hex) > 2 * MAX_SALT_BYTES:
        return False
    if len(digest_hex) > 2 * MAX_DIGEST_BYTES:
        return False
    try:
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
    except ValueError:
        return False
    # Re-derive with the work factor recorded in the hash, so raising
    # PBKDF2_ITERATIONS does not invalidate existing passwords. Compare raw
    # bytes: compare_digest raises TypeError on non-ASCII str, so comparing the
    # hex text would turn a corrupt record into a crash instead of a failed
    # authentication.
    candidate = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, rounds)
    return hmac.compare_digest(candidate, expected)


def create_order(conn, user_id, amount):
    if amount <= 0:
        raise ValueError("amount must be positive")
    cur = conn.cursor()
    cur.execute("INSERT INTO orders(user_id, amount) VALUES (?, ?)", (user_id, amount))
    conn.commit()
    return cur.lastrowid


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
        # The legacy record is only upgradable while we hold the plaintext, so
        # re-hash it here into a per-user salted verifier rather than leaving a
        # bare SHA-256 digest stored. The compare-and-swap guards on the exact
        # hash we authenticated against: if a password reset commits between the
        # SELECT and this UPDATE, the row no longer matches and the migration is
        # skipped instead of writing the old credential over it.
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
        # Drop the failed transaction so the connection is not left mid-write.
        # A connection too broken to commit may also be too broken to roll
        # back, and that must still report failure rather than raise.
        try:
            conn.rollback()
        except sqlite3.Error:
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


def legacy_password_digest(pw: str) -> str:
    """Deprecated alias for hash_password, kept for existing callers.

    Named "digest" for historical reasons, but the stored value is the salted,
    work-factored pbkdf2_sha256 verifier, not a bare digest. A fast unsalted
    hash here would make repeated passwords identifiable across rows and leave
    stolen values cheap to recover offline, so this delegates rather than
    hashing on its own.
    """
    return hash_password(pw)


def provider_api_key() -> str:
    """Return the provider credential from the runtime environment.

    The value is never embedded in the module: a literal in version control
    leaks with the source, the build output, and the deployed bytecode, and
    rotating it would mean a code change and a redeploy.
    """
    return config.provider_api_key


# --- Standing gate demo. Each function violates one enforced rule. ---

def demo_password_digest(pw: str) -> str:
    """Rule 2907 — Sonar python:S5344, OWASP A02:2021, CWE-916.
    Return the salted, work-factored password verifier."""
    return hash_password(pw)


def demo_provider_key() -> str:
    """Rule 2908 — Sonar python:S2068, OWASP A07:2021, CWE-798.
    Read the credential from runtime configuration."""
    return config.provider_api_key


def demo_lookup_by_owner(conn, owner):
    """Rule 2909 — Sonar python:S2077, OWASP A03:2021, CWE-89.
    Bind caller input as a SQL parameter."""
    cur = conn.cursor()
    cur.execute("SELECT id, amount FROM orders WHERE user_id = ?", (owner,))
    return cur.fetchall()
