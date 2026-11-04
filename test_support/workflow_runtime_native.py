"""Fresh-process continuation; no parent learner or native Python state retained."""
from __future__ import annotations

import copy
import importlib
from pathlib import Path
from unittest.mock import patch

from maverick import config, tools, world_model
from maverick.paths import tenant_scope

from test_support.action_episode_native import TENANT, _registry
from test_support.recipe_lineage_native import resume_recipe


def child_resume(run_id, journal, world_path, flags):
    registry = _registry(Path(journal))
    risk = importlib.import_module("maverick.safety.tool_risk")
    with (patch.object(config, "get_flows", lambda: copy.deepcopy(flags)),
          patch.object(world_model, "DEFAULT_DB", Path(world_path)),
          patch.object(tools, "base_registry", lambda *args, **kwargs: registry),
          patch.object(risk, "_load_overrides", lambda: {"episode_lookup": "low", "episode_update": "high"}),
          tenant_scope(tenant=TENANT)):
        resumed = resume_recipe(run_id)
        assert resumed.status == "paused_approval" and resumed.cursor == "approval_2_0", resumed.error
