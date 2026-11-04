"""Tests for the world-model SQLite indexes and the migration that adds them."""
from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]


# ---------- world-model indexes ----------

def test_world_model_v8_indices_present(tmp_path):
    """A fresh world model should have all v8 indices."""
    from maverick.world_model import WorldModel
    wm = WorldModel(tmp_path / "wm.sqlite")
    try:
        names = [
            row["name"] for row in wm.conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index'"
            )
        ]
    finally:
        wm.close()
    for expected in (
        "idx_episodes_goal_started",
        "idx_episodes_started",
        "idx_goals_status_updated",
        "idx_goals_parent",
    ):
        assert expected in names, f"missing index: {expected}"


def test_world_model_indexes_doc_exists():
    p = REPO_ROOT / "docs" / "performance" / "world-model-indexes.md"
    assert p.is_file()
    body = p.read_text(encoding="utf-8")
    for expected in (
        "idx_episodes_goal_started",
        "idx_episodes_started",
        "idx_goals_status_updated",
        "idx_goals_parent",
    ):
        assert expected in body


def _index_exists(conn, name: str) -> bool:
    rows = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='index' AND name=?",
        (name,),
    ).fetchall()
    return bool(rows)


class TestIndexesPresent:
    def test_idx_episodes_ended_at(self, tmp_path):
        from maverick.world_model import WorldModel
        wm = WorldModel(path=tmp_path / "wm.db")
        assert _index_exists(wm.conn, "idx_episodes_ended_at")

    def test_idx_goal_events_ts(self, tmp_path):
        from maverick.world_model import WorldModel
        wm = WorldModel(path=tmp_path / "wm.db")
        assert _index_exists(wm.conn, "idx_goal_events_ts")

    def test_existing_indexes_preserved(self, tmp_path):
        """The earlier indexes must still be present (guard against
        accidental drops)."""
        from maverick.world_model import WorldModel
        wm = WorldModel(path=tmp_path / "wm.db")
        for idx in (
            "idx_goals_status",
            "idx_goals_updated_at",
            "idx_goal_events_goal_id_id",
            "idx_conversations_last_seen",
            "idx_turns_conv_id",
            "idx_attachments_goal_id",
        ):
            assert _index_exists(wm.conn, idx), f"index {idx} missing"


class TestMigrationToV7:
    def test_v6_database_migrates_to_v7(self, tmp_path, monkeypatch):
        """A WorldModel opened against an old SCHEMA_VERSION=6 DB must
        run the v7 migration and end up with the new indexes."""
        from maverick import world_model

        db_path = tmp_path / "legacy.db"

        # Step 1: open with SCHEMA_VERSION temporarily clamped to 6 so
        # the on-disk schema_version row reads as 6 and the index isn't
        # created by SCHEMA (it stays in MIGRATIONS[7] only).
        monkeypatch.setattr(world_model, "SCHEMA_VERSION", 6)
        # Also patch MIGRATIONS to drop v7 so the v6 WorldModel doesn't
        # try to migrate beyond itself.
        v6_migrations = {
            k: v for k, v in world_model.MIGRATIONS.items() if k <= 6
        }
        monkeypatch.setattr(world_model, "MIGRATIONS", v6_migrations)
        # The SCHEMA constant ALSO has the new index inline. To simulate
        # true v6 we have to drop those indexes after init.
        wm_v6 = world_model.WorldModel(path=db_path)
        wm_v6.conn.execute("DROP INDEX IF EXISTS idx_episodes_ended_at")
        wm_v6.conn.execute("DROP INDEX IF EXISTS idx_goal_events_ts")
        wm_v6.conn.commit()
        wm_v6.conn.close()

        # Step 2: undo the patches; reopen with the real v7 SCHEMA_VERSION
        # + MIGRATIONS so the v6→v7 migration path runs.
        monkeypatch.undo()
        wm_v7 = world_model.WorldModel(path=db_path)
        # v6 -> head: the migration chain runs through to the current head.
        assert wm_v7.schema_version >= 7
        assert _index_exists(wm_v7.conn, "idx_episodes_ended_at")
        assert _index_exists(wm_v7.conn, "idx_goal_events_ts")
