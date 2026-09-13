import sqlite3
from app import service

PASSWORD = "s3cret"

def setup_db():
    c = sqlite3.connect(":memory:")
    c.execute("CREATE TABLE users(id INTEGER PRIMARY KEY, email TEXT, password_hash TEXT)")
    c.execute("CREATE TABLE orders(id INTEGER PRIMARY KEY, user_id INT, amount REAL)")
    c.execute(
        "INSERT INTO users(email, password_hash) VALUES ('a@b.c', ?)",
        (service.hash_password(PASSWORD),),
    )
    return c

def test_get_user():
    c = setup_db()
    assert service.get_user(c, 1)[1] == "a@b.c"

def test_create_order():
    c = setup_db()
    assert service.create_order(c, 1, 9.5) == 1

def test_hash_password_is_deterministic_and_not_plaintext():
    digest = service.hash_password(PASSWORD)
    assert digest == service.hash_password(PASSWORD)
    assert digest != service.hash_password("other")
    assert PASSWORD not in digest

def test_login_correct_password():
    c = setup_db()
    assert service.login(c, 1, PASSWORD) is True

def test_login_wrong_password():
    c = setup_db()
    assert service.login(c, 1, "wrong") is False

def test_login_unknown_user():
    c = setup_db()
    assert service.login(c, 99, PASSWORD) is False

def test_login_user_without_password_hash():
    c = setup_db()
    c.execute("INSERT INTO users(email) VALUES ('n@b.c')")
    assert service.login(c, 2, PASSWORD) is False
