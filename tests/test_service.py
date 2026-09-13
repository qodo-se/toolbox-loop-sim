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

def test_find_by_email():
    c = setup_db()
    assert service.find_by_email(c, "a@b.c")[0] == 1
    assert service.find_by_email(c, "nobody@b.c") is None

def test_update_amount_missing_order_rolls_back():
    c = setup_db()
    oid = service.create_order(c, 1, 9.5)
    raised = False
    try:
        service.update_amount(c, oid + 1, 5.0)
    except LookupError:
        raised = True
    assert raised
    assert not c.in_transaction
    assert service.get_user(c, 1)[1] == "a@b.c"

def test_update_amount_unchanged_value_succeeds():
    c = setup_db()
    oid = service.create_order(c, 1, 9.5)
    assert service.update_amount(c, oid, 9.5) is True

def test_update_amount_deleted_order_is_not_reported_as_updated():
    c = setup_db()
    oid = service.create_order(c, 1, 9.5)
    c.execute("DELETE FROM orders WHERE id = ?", (oid,))
    c.commit()
    raised = False
    try:
        service.update_amount(c, oid, 5.0)
    except LookupError:
        raised = True
    assert raised

def test_update_amount_missing_order_keeps_caller_writes():
    c = setup_db()
    oid = service.create_order(c, 1, 9.5)
    c.execute("INSERT INTO users(email) VALUES ('pending@b.c')")
    raised = False
    try:
        service.update_amount(c, oid + 1, 5.0)
    except LookupError:
        raised = True
    assert raised
    assert service.find_by_email(c, "pending@b.c") is not None
