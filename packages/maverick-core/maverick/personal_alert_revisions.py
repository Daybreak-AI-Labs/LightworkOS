"""Transactional semantic generations for recipient alert deduplication.

Generations live on the existing tenant-governed goal row. Status changes from
any writer, including receipt transactions, advance the same counter. Heartbeats
and repeated writes of the same state do not. No private content is copied.
"""

SQLITE_MIGRATION = [
    "ALTER TABLE goals ADD COLUMN alert_state_revision INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE goals ADD COLUMN alert_result_revision INTEGER NOT NULL DEFAULT 0",
    """CREATE TRIGGER IF NOT EXISTS goal_personal_alert_revision
    AFTER UPDATE OF status, result ON goals
    WHEN OLD.status IS NOT NEW.status OR OLD.result IS NOT NEW.result
    BEGIN
      UPDATE goals SET
        alert_state_revision = OLD.alert_state_revision + (OLD.status IS NOT NEW.status),
        alert_result_revision = OLD.alert_result_revision +
          (OLD.status = 'done' AND NEW.status = 'done' AND OLD.result IS NOT NEW.result)
      WHERE id = NEW.id;
    END""",
]

POSTGRES_MIGRATION = [
    "ALTER TABLE goals ADD COLUMN IF NOT EXISTS alert_state_revision BIGINT NOT NULL DEFAULT 0",
    "ALTER TABLE goals ADD COLUMN IF NOT EXISTS alert_result_revision BIGINT NOT NULL DEFAULT 0",
    """CREATE OR REPLACE FUNCTION advance_goal_personal_alert_revision()
    RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      NEW.alert_state_revision := OLD.alert_state_revision
        + CASE WHEN OLD.status IS DISTINCT FROM NEW.status THEN 1 ELSE 0 END;
      NEW.alert_result_revision := OLD.alert_result_revision
        + CASE WHEN OLD.status = 'done' AND NEW.status = 'done'
          AND OLD.result IS DISTINCT FROM NEW.result THEN 1 ELSE 0 END;
      RETURN NEW;
    END;
    $$""",
    """CREATE TRIGGER goal_personal_alert_revision
    BEFORE UPDATE OF status, result ON goals
    FOR EACH ROW EXECUTE FUNCTION advance_goal_personal_alert_revision()""",
]
