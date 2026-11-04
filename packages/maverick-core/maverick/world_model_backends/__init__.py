"""Alternative world-model backends.

The default backend is SQLite (``maverick.world_model.WorldModel``).
This subpackage adds optional alternative backends with the same
public surface — agents shouldn't care which is in use.

Currently:
  - ``postgres.PostgresWorldModel`` (extra: ``[postgres]``)

Future: ``redis``, ``duckdb``.
"""
from .postgres import (  # noqa: F401
    PGGoal,
    PostgresWorldModel,
    is_postgres_configured,
    open_postgres_world,
)

__all__ = [
    "PostgresWorldModel",
    "PGGoal",
    "open_postgres_world",
    "is_postgres_configured",
]
