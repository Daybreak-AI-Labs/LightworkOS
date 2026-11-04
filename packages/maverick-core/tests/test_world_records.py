"""Public record imports and serialized identities survive backend separation."""
import pickle

from maverick import world_model, world_records


def test_record_import_and_pickle_compatibility():
    assert world_model.Goal is world_records.Goal
    assert world_model.Approval is world_records.Approval
    record = world_records.Conversation(1, "chat", "user:alice", 1.0, 2.0)
    assert record.__class__.__module__ == "maverick.world_model"
    assert pickle.loads(pickle.dumps(record)) == record
