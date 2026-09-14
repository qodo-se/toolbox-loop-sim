import hashlib
import hmac
import math
import os
import secrets
import sqlite3

PBKDF2_PREFIX = "pbkdf2_sha256"
# Historical aliases, kept so callers written against any of these names keep
# working. All three are part of the module's public surface.
HASH_PREFIX = PBKDF2_PREFIX
PBKDF2_SCHEME = PBKDF2_PREFIX
PBKDF2_ITERATIONS = 600_000
# Upper bound on the work factor accepted from a stored hash, so a corrupted or
# tampered record cannot make every login for that user run unbounded work.
# Kept well under 5x the current work factor: a verifier sitting at this ceiling
# costs a login attempt under 2x the normal derivation, not 50x.
MAX_PBKDF2_ITERATIONS = 1_000_000
SALT_BYTES = 16
# Upper bound on the encoded salt accepted from a stored record. Records this
# service writes hold SALT_BYTES * 2 hex chars; the slack covers older or
# longer salts without letting a corrupted field size the allocation.
MAX_SALT_HEX_CHARS = 128
# The writer's own limit, kept in step with the reader's bound so hash_password
# can never serialize a record that verify_password would refuse to decode.
MAX_SALT_BYTES = MAX_SALT_HEX_CHARS // 2
LEGACY_SHA256_LENGTH = 64

_dummy_record = None


class Config:
    """Typed access to runtime configuration."""

    @property
    def api_token(self) -> str:
        token = os.environ.get("API_TOKEN")
        if not token:
            raise RuntimeError("API_TOKEN is not configured")
        return token


config = Config()


def init_schema(conn):
    """Create the tables the service needs and backfill columns missing from
    pre-existing databases. Idempotent; returns True once the schema is current.
    """
    cur = conn.cursor()
    cur.execute(
        "CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, email TEXT, password_hash TEXT)"
    )
    cur.execute(
        "CREATE TABLE IF NOT EXISTS orders(id INTEGER PRIMARY KEY, user_id INT, amount REAL)"
    )
    cur.execute("CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, user_id INT)")
    cur.execute("PRAGMA table_info(users)")
    if "password_hash" not in {row[1] for row in cur.fetchall()}:
        cur.execute("ALTER TABLE users ADD COLUMN password_hash TEXT")
    conn.commit()
    return True


# Historical alias: both names are part of the module's public surface.
ensure_schema = init_schema


def get_user(conn, user_id):
    cur = conn.cursor()
    cur.execute("SELECT id, email FROM users WHERE id = ?", (user_id,))
    return cur.fetchone()


def hash_password(pw: str, salt: bytes = None, iterations: int = None) -> str:
    """Return a salted record as "pbkdf2_sha256$<iterations>$<salt_hex>$<digest_hex>".

    ``salt`` and ``iterations`` default to a fresh random salt and the current
    work factor; callers pass them explicitly only to re-derive an existing hash.
    Values verify_password would reject raise ValueError, so a record that can be
    stored can always authenticate.
    """
    if salt is None:
        salt = secrets.token_bytes(SALT_BYTES)
    if iterations is None:
        iterations = PBKDF2_ITERATIONS
    if not salt:
        raise ValueError("salt must not be empty")
    if len(salt) > MAX_SALT_BYTES:
        raise ValueError("salt must be at most %d bytes" % MAX_SALT_BYTES)
    # bool passes the range check as 0/1 but serializes as "True", which
    # verify_password parses with int() and refuses, locking the account out of
    # a record that stored cleanly. Reject the type before the range.
    if isinstance(iterations, bool) or not isinstance(iterations, int):
        raise ValueError("iterations must be an int")
    if not 1 <= iterations <= MAX_PBKDF2_ITERATIONS:
        raise ValueError("iterations must be between 1 and %d" % MAX_PBKDF2_ITERATIONS)
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
    """Check pw against a stored record, accepting the legacy bare SHA-256 format."""
    # A corrupt column value (int, bytes, anything non-text, empty, or carrying
    # non-ASCII where only hex belongs) is a failed verification, not an
    # exception raised out of the login path.
    if not stored or not isinstance(stored, str) or not stored.isascii():
        return False
    # Hashes written before the PBKDF2 format are bare SHA-256 hex digests.
    # Accept them so existing accounts keep working; login rehashes on success.
    if is_legacy_hash(stored):
        legacy = hashlib.sha256(pw.encode()).hexdigest()
        return hmac.compare_digest(legacy, stored)
    parts = stored.split("$")
    if len(parts) != 4 or parts[0] != PBKDF2_PREFIX:
        return False
    _, iterations_text, salt_hex, digest_hex = parts
    # Bound the salt field before decoding it: an oversized but valid hex salt
    # would otherwise size both the allocation and the PBKDF2 input.
    if not salt_hex or len(salt_hex) > MAX_SALT_HEX_CHARS:
        return False
    try:
        iterations = int(iterations_text)
    except ValueError:
        return False
    # A tampered or corrupt verifier can carry a count that overflows the native
    # argument or burns CPU on every login; bound it so it cannot pin a worker.
    if not 1 <= iterations <= MAX_PBKDF2_ITERATIONS:
        return False
    try:
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
    except (ValueError, OverflowError):
        return False
    # Re-derive with the work factor recorded in the hash, so raising
    # PBKDF2_ITERATIONS does not invalidate existing passwords.
    candidate = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, iterations)
    return hmac.compare_digest(candidate, expected)


def _dummy_hash():
    """A throwaway record so an unknown user costs the same derivation as a real one."""
    global _dummy_record
    if _dummy_record is None:
        _dummy_record = hash_password(secrets.token_bytes(SALT_BYTES).hex())
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
    # NaN fails every comparison, so the finite check has to come first for it
    # to be rejected at all.
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


def find_by_email(conn, email):
    cur = conn.cursor()
    cur.execute("SELECT id, email FROM users WHERE email = ?", (email,))
    return cur.fetchone()


def _apply_amount(conn, order_id, amount) -> bool:
    """Write ``amount`` onto the order and report whether a row matched.

    Shared by update_amount and update_amount_strict, which differ only in how
    they report a missing order.
    """
    amount = _check_amount(amount)
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


def safe_commit(conn):
    try:
        conn.commit()
    except sqlite3.Error:
        conn.rollback()
        return False
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
    if is_legacy_hash(stored):
        # The password checked out against a legacy record, so re-store it salted.
        # The compare-and-swap matches the verifier we authenticated against, so a
        # password reset that lands between the SELECT and this UPDATE is never
        # overwritten with the old credential.
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
