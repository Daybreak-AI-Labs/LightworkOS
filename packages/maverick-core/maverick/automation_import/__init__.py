"""Import clients' existing automations from other platforms into Lightwork.

External automation platforms model a **trigger + ordered actions**. This
package normalizes any of them into one IR (:mod:`.ir`) via a per-platform
translator (:mod:`.base` registry), then maps the IR onto Lightwork's existing
``Template`` + trigger/schedule primitives (:mod:`.materialize`).

Two import modes, by platform capability:

* **Definition import** -- platforms that expose their automation definitions
  over an API (n8n, Make, Workato, Power Automate, UiPath): fetch + translate
  the real workflow graph. ``Importer.can_fetch_definitions`` is True.
* **Connect-and-trigger** -- platforms that do NOT expose their automation
  definitions (Zapier, Notion automations): the source automation can't be
  read, so the client's tool calls into Lightwork (inbound webhook) and/or we
  read its data; ``can_fetch_definitions`` is False and ``fetch`` explains.

Gated by ``[automation_import] enable`` / ``MAVERICK_AUTOMATION_IMPORT``.
"""
from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    # These connectors are imported by get_importer() through the lazy registry.
    # Declare that runtime edge statically without paying startup import cost.
    from . import (  # noqa: F401
        make,
        n8n,
        notion,
        power_automate,
        uipath,
        workato,
        zapier,
    )

from .base import (
    Importer,
    ImporterError,
    available_sources,
    get_importer,
    register,
    register_lazy,
    translate_all,
)
from .ir import ImportedAutomation, ImportedStep, ImportedTrigger
from .materialize import MaterializeResult, materialize

log = logging.getLogger(__name__)

# Keep discovery cheap: importing ``maverick.automation_import`` is part of CLI
# and dashboard startup, but most processes never connect to any of these
# platforms.  Register module names now and import only the selected connector
# in ``get_importer``.  ``from maverick.automation_import import n8n`` remains
# supported by Python's normal package-submodule import behavior.
for _source in (
    "make",
    "n8n",
    "notion",
    "power_automate",
    "uipath",
    "workato",
    "zapier",
):
    register_lazy(_source, f"{__name__}.{_source}")


def enabled() -> bool:
    """True when automation import is switched on (off by default)."""
    from ..config import env_flag
    env_name = "MAVERICK_AUTOMATION_IMPORT"
    v = env_flag(env_name)
    if v is not None:
        return v
    if os.environ.get(env_name, "").strip():
        log.warning(
            "automation import: %s must be one of 1/0, true/false, yes/no, "
            "or on/off; disabling automation import",
            env_name,
        )
        return False
    try:
        from ..config import get_automation_import
        return bool(get_automation_import().get("enable", False))
    except Exception as exc:  # never block on config, but make degradation visible
        log.warning(
            "automation import: could not read feature configuration (%s); "
            "disabling automation import",
            exc,
        )
        return False


__all__ = [
    "Importer",
    "ImporterError",
    "ImportedAutomation",
    "ImportedStep",
    "ImportedTrigger",
    "MaterializeResult",
    "available_sources",
    "enabled",
    "get_importer",
    "materialize",
    "register",
    "register_lazy",
    "translate_all",
]
