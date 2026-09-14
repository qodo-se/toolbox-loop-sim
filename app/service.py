import os
import sqlite3
import hashlib
import hmac
import logging
import math
import secrets

log = logging.getLogger(__name__)

PBKDF2_PREFIX = "pbkdf2_sha256"
PBKDF2_ITERATIONS = 600_000
SALT_BYTES = 16

# Bounds on a record-supplied iteration count. Anything outside this range is
# treated as a corrupt record rather than run through PBKDF2, so a tampered or
# corrupted row cannot make every login for that user run unbounded work.
MIN_PBKDF2_ITERATIONS = 1
MAX_PBKDF2_ITERATIONS = 1_000_000

# Digest lengths of the credential formats written before the record format.
LEGACY_MD5_LENGTH = 32
LEGACY_SHA256_LENGTH = 64

# Salt used by the pre-record-format credentials still present in older rows.
LEGACY_STATIC_SALT = b'static-demo-salt'

# Work factor those pre-record-format PBKDF2 credentials were derived with. It
# is history, not policy: raising `PBKDF2_ITERATIONS` must not change it, or the
# stored digests stop matching and their owners can no longer sign in.
LEGACY_PBKDF2_ITERATIONS = 200_000


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


def find_by_email(conn, email):
    cur = conn.cursor()
    cur.execute("SELECT id, email FROM users WHERE email = ?", (email,))
    return cur.fetchone()


def hash_password(pw: str, salt: bytes = None, iterations: int = None) -> str:
    """Hash a password with PBKDF2 and a per-password random salt.

    Returns a self-describing record, "pbkdf2_sha256$<iterations>$<salt_hex>$<digest_hex>",
    so each stored credential carries its own salt and work factor and identical
    passwords no longer produce identical digests. Verify with `verify_password`.

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
    """Deprecated alias for `hash_password`; kept for older call sites.

    There is no separate legacy password rule: use `hash_password` directly.
    """
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


def needs_rehash(record) -> bool:
    """True if `record` is a legacy credential that should be re-hashed.

    Broader than `is_legacy_hash`: it also covers the shorter MD5-era digests,
    which `verify_legacy_password` still accepts.
    """
    return isinstance(record, str) and '$' not in record


def verify_legacy_password(pw: str, record: str) -> bool:
    """Check a password against a credential stored before the record format.

    Older releases wrote a bare hex digest with no algorithm prefix: an MD5 or
    SHA-256 digest of the password, or PBKDF2-SHA256 over `LEGACY_STATIC_SALT`.
    These are accepted so existing accounts can still sign in; `login` replaces
    them with a current-format hash on the next successful sign-in.
    """
    try:
        bytes.fromhex(record)
    except ValueError:
        return False
    encoded = pw.encode()
    if len(record) == LEGACY_MD5_LENGTH:
        candidates = [hashlib.md5(encoded).hexdigest()]
    elif len(record) == LEGACY_SHA256_LENGTH:
        candidates = [
            hashlib.sha256(encoded).hexdigest(),
            hashlib.pbkdf2_hmac(
                'sha256', encoded, LEGACY_STATIC_SALT, LEGACY_PBKDF2_ITERATIONS
            ).hex(),
        ]
    else:
        return False
    matched = False
    for candidate in candidates:
        matched |= hmac.compare_digest(candidate, record)
    return matched


def verify_password(pw: str, record: str) -> bool:
    """Check a password against a record produced by `hash_password`.

    Legacy credentials predating the record format are also accepted; see
    `verify_legacy_password`.
    """
    if not isinstance(record, str):
        return False
    if needs_rehash(record):
        return verify_legacy_password(pw, record)
    try:
        algorithm, iterations, salt_hex, digest_hex = record.split("$")
        if algorithm != PBKDF2_PREFIX:
            return False
        # Parsing the digest here keeps a non-hex or non-ASCII field a rejected
        # record rather than a comparison that raises.
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
        iterations = int(iterations)
    except (AttributeError, ValueError, OverflowError):
        return False
    if not MIN_PBKDF2_ITERATIONS <= iterations <= MAX_PBKDF2_ITERATIONS:
        return False
    # Re-derive with the work factor recorded in the hash, so raising
    # PBKDF2_ITERATIONS does not invalidate existing passwords.
    candidate = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, iterations)
    return hmac.compare_digest(candidate, expected)


def check_amount(amount):
    """Raise ValueError unless `amount` is a finite positive number."""
    if isinstance(amount, bool) or not isinstance(amount, (int, float)):
        raise ValueError("amount must be positive")
    # NaN fails every comparison, so the finite check has to come first for it
    # to be rejected at all.
    if not math.isfinite(amount) or amount <= 0:
        raise ValueError("amount must be positive")


def create_order(conn, user_id, amount):
    check_amount(amount)
    cur = conn.cursor()
    cur.execute("INSERT INTO orders(user_id, amount) VALUES (?, ?)", (user_id, amount))
    conn.commit()
    return cur.lastrowid


def _apply_amount(conn, order_id, amount) -> bool:
    """Write ``amount`` onto the order and report whether a row matched.

    Shared by update_amount and update_amount_strict, which differ only in how
    they report a missing order.
    """
    check_amount(amount)
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
    """Commit the open transaction. Returns False if the commit failed."""
    try:
        conn.commit()
    except sqlite3.Error:
        log.exception("commit failed, rolling back")
        try:
            conn.rollback()
        except sqlite3.Error:
            log.exception("rollback after failed commit also failed")
        return False
    return True


def upgrade_password_hash(conn, user_id, pw, old_record):
    """Re-store an already verified password in the current hash format.

    The update is conditional on `old_record` still being the stored value so a
    credential changed concurrently is never clobbered. The rehash is
    opportunistic: any failure is logged and the sign-in itself still stands.

    The commit is only ours to make when the rehash opened the transaction. If
    the caller already had writes pending, this joins their transaction and
    leaves committing (or rolling back) to them, rather than finalizing or
    discarding work that has nothing to do with authentication.
    """
    owns_transaction = not getattr(conn, "in_transaction", False)
    try:
        cur = conn.cursor()
        cur.execute(
            "UPDATE users SET password_hash = ? WHERE id = ? AND password_hash = ?",
            (hash_password(pw), user_id, old_record),
        )
    except sqlite3.Error:
        log.exception("could not rehash credential for user %s", user_id)
        # A failing statement can still have opened the transaction. Close it
        # when it is ours, so the caller's later work does not silently join a
        # transaction this rehash left behind.
        if owns_transaction:
            try:
                conn.rollback()
            except sqlite3.Error:
                log.exception("rollback after failed rehash also failed")
        return
    if owns_transaction and not safe_commit(conn):
        log.warning("could not persist rehashed credential for user %s", user_id)


def login(conn, user_id, pw):
    cur = conn.cursor()
    cur.execute("SELECT password_hash FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    if not row or not row[0]:
        return False
    stored = row[0]
    if not verify_password(pw, stored):
        return False
    if needs_rehash(stored):
        upgrade_password_hash(conn, user_id, pw, stored)
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
