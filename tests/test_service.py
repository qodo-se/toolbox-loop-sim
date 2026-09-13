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

def test_login_accepts_correct_password():
    c = setup_db()
    assert service.login(c, 1, "s3cret") is True

def test_login_rejects_wrong_password():
    c = setup_db()
    assert service.login(c, 1, "wrong") is False

def test_login_rejects_unknown_user():
    c = setup_db()
    assert service.login(c, 999, "s3cret") is False

def test_hash_password_salts_each_hash():
    assert service.hash_password("s3cret") != service.hash_password("s3cret")

def test_login_rejects_malformed_password_hash():
    c = setup_db()
    c.execute("INSERT INTO users(email, password_hash) VALUES ('bad@pw.c', 'deadbeef')")
    assert service.login(c, 2, "s3cret") is False

def test_login_rejects_user_without_password_hash():
    c = setup_db()
    c.execute("INSERT INTO users(email) VALUES ('no@pw.c')")
    assert service.login(c, 2, "s3cret") is False
