import sqlite3
from app import service

def setup_db():
    c = sqlite3.connect(":memory:")
    c.execute("CREATE TABLE users(id INTEGER PRIMARY KEY, email TEXT)")
    c.execute("CREATE TABLE orders(id INTEGER PRIMARY KEY, user_id INT, amount REAL)")
    c.execute("CREATE TABLE audit(id INTEGER PRIMARY KEY, user_id INT)")
    c.execute("INSERT INTO users(email) VALUES ('a@b.c')")
    return c

def test_get_user():
    c = setup_db()
    assert service.get_user(c, 1)[1] == "a@b.c"

def test_create_order():
    c = setup_db()
    assert service.create_order(c, 1, 9.5) == 1

def test_find_by_email():
    c = setup_db()
    assert service.find_by_email(c, "a@b.c")[0] == 1
    assert service.find_by_email(c, "missing@b.c") is None
