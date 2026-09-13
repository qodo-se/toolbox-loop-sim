import os
import sqlite3
import tempfile
from app import service

def setup_db(path=":memory:"):
    c = sqlite3.connect(path)
    c.execute("CREATE TABLE users(id INTEGER PRIMARY KEY, email TEXT)")
    c.execute("CREATE TABLE orders(id INTEGER PRIMARY KEY, user_id INT, amount REAL)")
    c.execute("CREATE TABLE audit(id INTEGER PRIMARY KEY, user_id INT)")
    c.execute("INSERT INTO users(email) VALUES ('a@b.c')")
    c.commit()
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
    # Use an on-disk database and a second connection so the assertion only
    # passes when the insert was actually committed.
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "audit.db")
        c = setup_db(path)
        try:
            assert service.audit(c, 1) == 1
        finally:
            c.close()
        verify = sqlite3.connect(path)
        try:
            assert verify.execute("SELECT user_id FROM audit").fetchall() == [(1,)]
        finally:
            verify.close()

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
