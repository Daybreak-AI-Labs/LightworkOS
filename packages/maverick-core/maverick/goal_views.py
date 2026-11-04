"""Read projections that cannot accidentally hydrate complete goal bodies."""
from dataclasses import dataclass


@dataclass(frozen=True)
class ConversationSummary:
    id: int
    title: str
    status: str
    updated_at: float
    owner: str


@dataclass(frozen=True)
class GoalStreamState:
    id: int
    status: str
    owner: str
    result: str = ""
