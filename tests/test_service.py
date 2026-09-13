import sqlite3
from app import service

def setup_db():
    c = sqlite3.connect(":memory:")
    c.execute("CREATE TABLE users(id INTEGER PRIMARY KEY, email TEXT)")
    c.execute("CREATE TABLE orders(id INTEGER PRIMARY KEY, user_id INT, amount REAL)")
    c.execute("INSERT INTO users(email) VALUES ('a@b.c')")
    return c

def test_get_user():
    c = setup_db()
    assert service.get_user(c, 1)[1] == "a@b.c"

def test_create_order():
    c = setup_db()
    assert service.create_order(c, 1, 9.5) == 1

def test_hash_password_is_salted_and_verifiable():
    h = service.hash_password("hunter2")
    assert h != service.hash_password("hunter2")
    assert service.verify_password("hunter2", h)
    assert not service.verify_password("wrong", h)
    assert not service.verify_password("hunter2", "not-a-hash")

def test_verify_password_rejects_corrupt_records():
    for stored in (
        "pbkdf2_sha256$1$00$é",           # non-ASCII digest
        "pbkdf2_sha256$1$00$zz",               # non-hex digest
        "pbkdf2_sha256$0$00$00",               # iteration count below the allowed range
        f"pbkdf2_sha256${service.MAX_PBKDF2_ITERATIONS + 1}$00$00",
    ):
        assert not service.verify_password("hunter2", stored)

def test_legacy_hash_delegates():
    assert service.verify_password("hunter2", service.legacy_hash("hunter2"))

def test_calc_rejects_booleans_and_deep_expressions():
    assert service.calc("1 + 2") == 3
    for expr in ("True + True", "+".join(["1"] * 200)):
        try:
            service.calc(expr)
        except ValueError:
            continue
        raise AssertionError(f"expected ValueError for {expr!r}")
