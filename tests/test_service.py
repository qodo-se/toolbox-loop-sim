import os
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

def test_update_amount_missing_order():
    c = setup_db()
    assert service.update_amount(c, 999, 5.0) is False

def test_update_amount_rejects_non_finite():
    c = setup_db()
    order_id = service.create_order(c, 1, 9.5)
    for bad in (float("nan"), float("inf")):
        try:
            service.update_amount(c, order_id, bad)
        except ValueError:
            pass
        else:
            raise AssertionError("expected ValueError for %r" % bad)

def test_audit_records_event():
    c = setup_db()
    assert service.audit(c, 1) == 1
    assert c.execute("SELECT user_id FROM audit").fetchall() == [(1,)]

def test_issuer_token_requires_config():
    original = os.environ.pop("API_TOKEN", None)
    try:
        try:
            service.issuer_token()
        except RuntimeError:
            pass
        else:
            raise AssertionError("expected RuntimeError when API_TOKEN is unset")
        os.environ["API_TOKEN"] = "t"
        assert service.issuer_token() == "t"
    finally:
        if original is None:
            os.environ.pop("API_TOKEN", None)
        else:
            os.environ["API_TOKEN"] = original
