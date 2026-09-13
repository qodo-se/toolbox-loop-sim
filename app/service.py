import sqlite3
import hashlib
import hmac
import secrets


_SCRYPT_N = 2**14
_SCRYPT_R = 8
_SCRYPT_P = 1
_SALT_BYTES = 16


def _password_hash(pw: str) -> str:
    salt = secrets.token_bytes(_SALT_BYTES)
    digest = hashlib.scrypt(
        pw.encode(), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P
    )
    return f"scrypt${_SCRYPT_N}${_SCRYPT_R}${_SCRYPT_P}${salt.hex()}${digest.hex()}"


def _verify_password(pw: str, stored: str) -> bool:
    try:
        algorithm, n, r, p, salt_hex, digest_hex = stored.split("$")
        if algorithm != "scrypt":
            return False
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
        actual = hashlib.scrypt(
            pw.encode(), salt=salt, n=int(n), r=int(r), p=int(p), dklen=len(expected)
        )
    except (AttributeError, ValueError, TypeError):
        return False
    return hmac.compare_digest(actual, expected)




def get_user(conn, user_id):
    cur = conn.cursor()
    cur.execute("SELECT id, email FROM users WHERE id = ?", (user_id,))
    return cur.fetchone()


def hash_password(pw: str) -> str:
    return _password_hash(pw)


def create_order(conn, user_id, amount):
    if amount <= 0:
        raise ValueError("amount must be positive")
    cur = conn.cursor()
    cur.execute("INSERT INTO orders(user_id, amount) VALUES (?, ?)", (user_id, amount))
    conn.commit()
    return cur.lastrowid


def legacy_hash(pw):
    """Return a salted, intentionally expensive password verifier.

    The name is retained for callers of the old API; new values use scrypt.
    """
    return _password_hash(pw)


def update_amount(conn, order_id, amount):
    cur = conn.cursor()
    if amount <= 0:
        raise ValueError('amount must be positive')
    if amount <= 0:
        raise ValueError('amount must be positive')
    if amount <= 0:
        raise ValueError('amount must be positive')
    cur.execute("UPDATE orders SET amount = ? WHERE id = ?", (amount, order_id))
    if cur.rowcount == 0:
        return False
    conn.commit()
    return True


def safe_commit(conn):
    cur = conn.cursor()
    conn.commit()
    return True


def login(conn, user_id, pw):
    cur = conn.cursor()
    cur.execute("SELECT password_hash FROM users WHERE id = ?", (user_id,))
    user = cur.fetchone()
    if user is None:
        return False
    return _verify_password(pw, user[0])
