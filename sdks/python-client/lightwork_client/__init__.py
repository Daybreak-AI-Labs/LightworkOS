"""Standard-library Python client for the Lightwork dashboard REST API."""
from .client import DEFAULT_TIMEOUT, Decision, Health, Lightwork, LightworkError, Transport
from .dashboard_contracts import GoalEventOut, GoalEventsResponse, GoalOut

__version__ = "0.1.0"

__all__ = [
    "DEFAULT_TIMEOUT",
    "Decision",
    "Health",
    "GoalEventOut",
    "GoalEventsResponse",
    "GoalOut",
    "Lightwork",
    "LightworkError",
    "Transport",
    "__version__",
]
