Refactor the following toy codebase to extract a clean repository layer.

Setup (the orchestrator should create these files in the workspace before delegating):

```python
# app.py
import sqlite3

def get_user(user_id: int):
    conn = sqlite3.connect("app.db")
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return row

def list_users():
    conn = sqlite3.connect("app.db")
    rows = conn.execute("SELECT * FROM users").fetchall()
    conn.close()
    return rows

def create_user(name: str, email: str):
    conn = sqlite3.connect("app.db")
    cur = conn.execute("INSERT INTO users(name, email) VALUES(?, ?)", (name, email))
    conn.commit()
    user_id = cur.lastrowid
    conn.close()
    return user_id
```

```python
# test_app.py
import os, pytest
from app import get_user, list_users, create_user

@pytest.fixture(autouse=True)
def _db():
    if os.path.exists("app.db"): os.remove("app.db")
    import sqlite3
    conn = sqlite3.connect("app.db")
    conn.execute("CREATE TABLE users(id INTEGER PRIMARY KEY, name TEXT, email TEXT)")
    conn.commit()
    conn.close()
    yield
    if os.path.exists("app.db"): os.remove("app.db")

def test_create_and_get():
    uid = create_user("Alice", "a@example.com")
    row = get_user(uid)
    assert row[1] == "Alice"

def test_list():
    create_user("A", "a@a")
    create_user("B", "b@b")
    assert len(list_users()) == 2
```

Goal:
  - Extract a `UserRepository` class into `repository.py` that holds the connection and exposes `get`, `list`, `create` methods.
  - Update `app.py` to delegate to `UserRepository` via a single module-level instance.
  - Tests in `test_app.py` must continue to pass without modification.
  - Add a `connection-string` parameter so callers can override the DB path.
  - The orchestrator verifies pytest exits zero after the refactor.

This exercises the recursive swarm in a way single-shot prompting struggles with: requires a planner (orchestrator), a coder for the refactor, a verifier that runs the tests, and a revisor on test failure.

Budget: $3, 30 minutes wall-clock.
