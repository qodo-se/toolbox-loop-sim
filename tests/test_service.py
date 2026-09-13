import sqlite3
from app import service

def setup_db():
    c = sqlite3.connect(":memory:")
    c.execute("CREATE TABLE users(id INTEGER PRIMARY KEY, email TEXT, password_hash TEXT)")
    c.execute("CREATE TABLE orders(id INTEGER PRIMARY KEY, user_id INT, amount REAL)")
    c.execute(
        "INSERT INTO users(email, password_hash) VALUES ('a@b.c', ?)",
        (service.hash_password("s3cret"),),
    )
    return c

def test_get_user():
    c = setup_db()
    assert service.get_user(c, 1)[1] == "a@b.c"

def test_create_order():
    c = setup_db()
    assert service.create_order(c, 1, 9.5) == 1

def test_login():
    c = setup_db()
    assert service.login(c, 1, "s3cret") is True
    assert service.login(c, 1, "wrong") is False
    assert service.login(c, 99, "s3cret") is False

def test_hash_password_is_salted():
    assert service.hash_password("s3cret") != service.hash_password("s3cret")

def test_update_amount_missing_order():
    c = setup_db()
    oid = service.create_order(c, 1, 9.5)
    assert service.update_amount(c, oid, 12.0) is True
    assert service.update_amount(c, oid + 100, 12.0) is False
