"""Product switches through the existing reviewed organization-settings writer."""
from __future__ import annotations

from .plain_labels import feature_help, feature_label
from .settings_feature_metadata import FEATURE_DEFAULTS, FEATURE_INFO


def entries(S, _C, _Column) -> tuple:
    return tuple(
        S("features", name, "Live progress outside the dashboard" if name == "streaming" else feature_label(name), _help(name), "toggle",
          "Server & deployment", default, "maverick.config",
          subgroup="Product features", aliases="feature switch enable disable",
          weaker=True, warning=_help(name),
          env=("MAVERICK_USE_SKILLS",) if name == "skills" else ())
        for name, default in FEATURE_DEFAULTS.items()
    )


def _help(name: str) -> str:
    if name == "streaming":
        return ("Show progress for tasks started outside the dashboard. Chat has its own "
                "live responses. A server setting or an output that cannot show progress "
                "can still suppress these updates.")
    return feature_help(name, FEATURE_INFO[name])
