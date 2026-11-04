"""Contract shared by the two world-model goal records."""

import pytest
from maverick.world_model import Goal, WorldModel
from maverick.world_model_backends.postgres import PGGoal, PostgresWorldModel
from maverick.world_model_contracts import (
    ApprovalStore,
    ConversationStore,
    FactStore,
    GoalEventReader,
    GoalEventStore,
    GoalRecord,
)


def test_goal_records_share_the_read_contract():
    fields = (1, None, "title", "description", "pending", 1.0, 2.0, None, None)
    assert isinstance(Goal(*fields), GoalRecord)
    assert isinstance(PGGoal(*fields), GoalRecord)


@pytest.mark.parametrize("backend_type", [WorldModel, PostgresWorldModel])
def test_world_backends_expose_narrow_domain_contracts(backend_type):
    # Construct without opening a database: this checks the public surface,
    # while the backend contract suites exercise its behavior and tenant scope.
    world = backend_type.__new__(backend_type)
    assert isinstance(world, ConversationStore)
    assert isinstance(world, ApprovalStore)
    assert isinstance(world, GoalEventReader)
    assert isinstance(world, GoalEventStore)
    assert isinstance(world, FactStore)
