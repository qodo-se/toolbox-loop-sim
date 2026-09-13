import sqlite3
import hashlib
import hmac
import logging
import math
import os

log = logging.getLogger(__name__)

PBKDF2_ITERATIONS = 200_000
SALT_BYTES = 16

# Bounds on a record-supplied iteration count. Anything outside this range is
# treated as a corrupt record rather than run through PBKDF2.
MIN_PBKDF2_ITERATIONS = 1
MAX_PBKDF2_ITERATIONS = 10_000_000

# Salt used by the pre-record-format credentials still present in older rows.
LEGACY_STATIC_SALT = b'static-demo-salt'


def get_user(conn, user_id):
    cur = conn.cursor()
    cur.execute("SELECT id, email FROM users WHERE id = ?", (user_id,))
    return cur.fetchone()


def hash_password(pw: str, salt: bytes = None) -> str:
    """Hash a password with PBKDF2 and a per-password random salt.

    Returns a self-describing record, "pbkdf2_sha256$<iterations>$<salt>$<hash>",
    so each stored credential carries its own salt and identical passwords no
    longer produce identical digests. Verify with `verify_password`.
    """
    if salt is None:
        salt = os.urandom(SALT_BYTES)
    digest = hashlib.pbkdf2_hmac('sha256', pw.encode(), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt.hex()}${digest.hex()}"


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
    if len(record) == 32:
        candidates = [hashlib.md5(encoded).hexdigest()]
    elif len(record) == 64:
        candidates = [
            hashlib.sha256(encoded).hexdigest(),
            hashlib.pbkdf2_hmac(
                'sha256', encoded, LEGACY_STATIC_SALT, PBKDF2_ITERATIONS
            ).hex(),
        ]
    else:
        return False
    matched = False
    for candidate in candidates:
        matched |= hmac.compare_digest(candidate, record)
    return matched


def needs_rehash(record: str) -> bool:
    """True if `record` is a legacy credential that should be re-hashed."""
    return isinstance(record, str) and '$' not in record


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
        algo, iterations, salt, digest = record.split('$')
        salt = bytes.fromhex(salt)
        iterations = int(iterations)
    except ValueError:
        return False
    if algo != 'pbkdf2_sha256':
        return False
    if not MIN_PBKDF2_ITERATIONS <= iterations <= MAX_PBKDF2_ITERATIONS:
        return False
    expected = hashlib.pbkdf2_hmac('sha256', pw.encode(), salt, iterations)
    return hmac.compare_digest(expected.hex(), digest)


def check_amount(amount):
    """Raise ValueError unless `amount` is a finite positive number."""
    if isinstance(amount, bool) or not isinstance(amount, (int, float)):
        raise ValueError("amount must be positive")
    if not math.isfinite(amount) or amount <= 0:
        raise ValueError("amount must be positive")


def create_order(conn, user_id, amount):
    check_amount(amount)
    cur = conn.cursor()
    cur.execute("INSERT INTO orders(user_id, amount) VALUES (?, ?)", (user_id, amount))
    conn.commit()
    return cur.lastrowid


def legacy_hash(pw):
    """Deprecated alias for `hash_password`; kept for older call sites.

    There is no separate legacy password rule: use `hash_password` directly.
    """
    return hash_password(pw)


def update_amount(conn, order_id, amount):
    check_amount(amount)
    cur = conn.cursor()
    cur.execute("UPDATE orders SET amount = ? WHERE id = ?", (amount, order_id))
    if cur.rowcount == 0:
        raise LookupError("order not found")
    conn.commit()
    return True


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
    credential changed concurrently is never clobbered. A failed commit is
    logged and rolled back by `safe_commit`; the sign-in itself still stands.
    """
    cur = conn.cursor()
    cur.execute(
        "UPDATE users SET password_hash = ? WHERE id = ? AND password_hash = ?",
        (hash_password(pw), user_id, old_record),
    )
    if not safe_commit(conn):
        log.warning("could not persist rehashed credential for user %s", user_id)


def login(conn, user_id, pw):
    cur = conn.cursor()
    cur.execute("SELECT password_hash FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    if not row or not verify_password(pw, row[0]):
        return False
    if needs_rehash(row[0]):
        upgrade_password_hash(conn, user_id, pw, row[0])
    return True
