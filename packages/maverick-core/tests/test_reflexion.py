"""Tests for the reflexion library (maverick.reflexion) and its recall."""
from __future__ import annotations

import builtins
import time

from maverick import reflexion

# --- reflexion recall prefers recent + dedups --------------------

def test_recall_prefers_recent_on_equal_similarity(tmp_path):
    path = tmp_path / "reflexions.ndjson"
    now = time.time()
    # Two equally-similar lessons; the fresher one must rank first.
    reflexion.record(
        goal_text="fix the parser bug now",
        failure_class="agent_error",
        failure_msg="stale",
        reflection="old lesson",
        path=path,
    )
    # Force timestamps: rewrite with explicit ts so the test is deterministic.
    import json
    lines = [
        json.dumps({"owner": "", "goal_id": 0,
            "ts": now - 10_000, "goal_text": "fix the parser bug now",
            "failure_class": "agent_error", "failure_msg": "stale",
            "reflection": "old lesson", "tools_used": [],
            "channel": None, "user_id": None,
        }),
        json.dumps({"owner": "", "goal_id": 0,
            "ts": now, "goal_text": "fix the parser bug now please",
            "failure_class": "agent_error", "failure_msg": "fresh",
            "reflection": "new lesson", "tools_used": [],
            "channel": None, "user_id": None,
        }),
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    hits = reflexion.recall("fix the parser bug now", path=path, k=2)
    assert hits
    # The fresher lesson outranks the older one despite similar similarity.
    assert hits[0][1].failure_msg == "fresh"


def test_recall_dedupes_near_identical_lessons(tmp_path):
    path = tmp_path / "reflexions.ndjson"
    import json
    now = time.time()
    rows = [
        {"owner": "", "goal_id": 0, "ts": now, "goal_text": "deploy the service to staging",
         "failure_class": "agent_error", "failure_msg": "dup-a",
         "reflection": "x", "tools_used": [], "channel": None, "user_id": None},
        {"owner": "", "goal_id": 0, "ts": now - 1, "goal_text": "deploy the service to staging",
         "failure_class": "agent_error", "failure_msg": "dup-b",
         "reflection": "x", "tools_used": [], "channel": None, "user_id": None},
        {"owner": "", "goal_id": 0, "ts": now - 2, "goal_text": "deploy the service to staging area zone",
         "failure_class": "agent_error", "failure_msg": "dup-c",
         "reflection": "x", "tools_used": [], "channel": None, "user_id": None},
        {"owner": "", "goal_id": 0, "ts": now - 3, "goal_text": "rotate database credentials safely",
         "failure_class": "agent_error", "failure_msg": "distinct",
         "reflection": "x", "tools_used": [], "channel": None, "user_id": None},
    ]
    path.write_text(
        "\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8",
    )

    hits = reflexion.recall("deploy the service to staging", path=path, k=5)
    msgs = [h[1].failure_msg for h in hits]
    # The two identical "deploy ... staging" goals must collapse to one.
    assert msgs.count("dup-a") + msgs.count("dup-b") == 1


def test_recall_scan_cap_streams_without_reading_all_lines(tmp_path, monkeypatch):
    path = tmp_path / "reflexions.ndjson"
    path.touch()

    class IterOnlyFile:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def __iter__(self):
            import json
            now = time.time()
            for i in range(5):
                yield json.dumps({"owner": "", "goal_id": 0,
                    "ts": now + i,
                    "goal_text": f"target goal {i}",
                    "failure_class": "agent_error",
                    "failure_msg": f"kept-{i}",
                    "reflection": "x",
                    "tools_used": [],
                    "channel": None,
                    "user_id": None,
                }) + "\n"

        def readlines(self):
            raise AssertionError("recall must not materialize the whole log")

    def fake_open(open_path, *args, **kwargs):
        if open_path == path:
            return IterOnlyFile()
        return real_open(open_path, *args, **kwargs)

    real_open = builtins.open
    monkeypatch.setattr(builtins, "open", fake_open)

    hits = reflexion.recall("target goal", path=path, scan_cap=2, k=5)
    assert [hit[1].failure_msg for hit in hits] == ["kept-4", "kept-3"]


def test_recall_scan_cap_limits_considered_lines(tmp_path):
    path = tmp_path / "reflexions.ndjson"
    import json
    now = time.time()
    rows = []
    # Old, highly-relevant lesson buried beyond the scan cap.
    rows.append({"owner": "", "goal_id": 0,
        "ts": now - 1000, "goal_text": "optimize the image resizer pipeline",
        "failure_class": "agent_error", "failure_msg": "buried",
        "reflection": "x", "tools_used": [], "channel": None, "user_id": None,
    })
    # Many irrelevant recent rows pushing the buried one out of the window.
    for i in range(5):
        rows.append({"owner": "", "goal_id": 0,
            "ts": now - i, "goal_text": f"unrelated chore number {i}",
            "failure_class": "agent_error", "failure_msg": "noise",
            "reflection": "x", "tools_used": [], "channel": None,
            "user_id": None,
        })
    path.write_text(
        "\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8",
    )

    hits = reflexion.recall(
        "optimize the image resizer pipeline", path=path, scan_cap=3,
    )
    # With scan_cap=3 the buried first line is never considered.
    assert all(h[1].failure_msg != "buried" for h in hits)


# ---------- reflexion ----------

def test_reflexion_record_and_recall(tmp_path):
    from maverick.reflexion import recall, record
    p = tmp_path / "reflexions.ndjson"
    assert record(
        "Refactor the auth module to use sessions",
        "auth",
        "401 Unauthorized when calling /api/login",
        "I should have read the existing session middleware before refactoring.",
        tools_used=["read_file", "shell"],
        path=p,
    )
    assert p.exists()
    hits = recall("refactor auth module sessions", k=3, path=p)
    assert len(hits) == 1
    score, r = hits[0]
    assert score > 0.3
    assert r.failure_class == "auth"
    assert "session" in r.reflection.lower()


def test_reflexion_recall_ranks_by_similarity(tmp_path):
    from maverick.reflexion import recall, record
    p = tmp_path / "reflexions.ndjson"
    record(
        "Refactor the cart checkout flow",
        "logic_bug",
        "cart total off by one",
        "I miscounted line items.",
        path=p,
    )
    record(
        "Refactor the auth module to use sessions",
        "auth",
        "401",
        "lesson about session middleware",
        path=p,
    )
    record(
        "Plan a 3-day trip to Lisbon",
        "unknown",
        "no failure, just unrelated content",
        "n/a",
        path=p,
    )
    hits = recall("refactor authentication sessions", k=2, path=p)
    assert len(hits) >= 1
    # The auth refactor entry should rank above the cart refactor entry.
    top = hits[0][1]
    assert "auth" in top.goal_text.lower()


def test_reflexion_recall_empty_file(tmp_path):
    from maverick.reflexion import recall
    p = tmp_path / "nonexistent.ndjson"
    assert recall("anything", path=p) == []


def test_reflexion_recall_no_query(tmp_path):
    from maverick.reflexion import recall, record
    p = tmp_path / "x.ndjson"
    record("g", "k", "m", "r", path=p)
    assert recall("", path=p) == []


def test_reflexion_list_recent_newest_first(tmp_path):
    from maverick.reflexion import list_recent, record
    p = tmp_path / "x.ndjson"
    record("first", "k", "m", "r", path=p)
    time.sleep(0.01)
    record("second", "k", "m", "r", path=p)
    time.sleep(0.01)
    record("third", "k", "m", "r", path=p)
    entries = list_recent(limit=10, path=p)
    assert [e.goal_text for e in entries] == ["third", "second", "first"]


def test_reflexion_clear(tmp_path):
    from maverick.reflexion import clear, recall, record
    p = tmp_path / "x.ndjson"
    record("g", "k", "m", "r", path=p)
    assert p.exists()
    assert clear(path=p) is True
    assert not p.exists()
    assert recall("g", path=p) == []


def test_reflexion_file_perms_600(tmp_path):
    """File should be created with mode 0600."""
    import os
    import stat

    from maverick.reflexion import record
    p = tmp_path / "perm.ndjson"
    record("g", "k", "m", "r", path=p)
    assert p.exists()
    mode = stat.S_IMODE(p.stat().st_mode)
    # 0o600 OR 0o644 depending on umask + test env; the helper does
    # chmod 600 but we don't fail if the FS quietly refuses. POSIX-only:
    # NTFS reports 0o666 and os.geteuid() doesn't exist on Windows.
    if os.name != "nt":
        assert (mode & 0o077) == 0 or os.geteuid() == 0


def test_reflexion_format_context_renders_sections():
    from maverick.reflexion import Reflexion, format_context
    r = Reflexion(
        ts=time.time(),
        goal_text="Refactor auth",
        failure_class="auth",
        failure_msg="401",
        reflection="Read middleware first next time.",
    )
    out = format_context([(0.85, r)])
    assert "Prior failures on similar goals" in out
    assert "Refactor auth" in out
    assert "Read middleware first" in out


def test_reflexion_format_context_empty_returns_empty():
    from maverick.reflexion import format_context
    assert format_context([]) == ""


def test_reflexion_record_failsafe_on_bad_path(tmp_path):
    """Writing to a path under a file (cannot create) is a soft failure."""
    from maverick.reflexion import record
    blocking = tmp_path / "blocker"
    blocking.write_text("x")
    bad = blocking / "subdir" / "f.ndjson"
    # Recording must NOT raise; returns False.
    ok = record("g", "k", "m", "r", path=bad)
    assert ok is False
