"""Current hosted image-edit choices, shared by setup and the actual tool."""
from __future__ import annotations

import os
import re

MAX_MODEL_LENGTH = 256
# Only an account/model name, optionally pinned to a version; never a URL/path.
MODEL_PATTERN = (r"((?=.{1,256}$)(?!.*\.\.)[A-Za-z0-9][A-Za-z0-9_.\-]{0,127}/"
                 r"[A-Za-z0-9][A-Za-z0-9_.\-]{0,127}"
                 r"(:[A-Za-z0-9][A-Za-z0-9_.\-]{0,127})?)?")
CHOICES = (
    ("inpaint_model", "MAVERICK_INPAINT_MODEL", "Model for replacing part of an image"),
    ("variation_model", "MAVERICK_VARIATION_MODEL", "Model for making image variations"),
    ("upscale_model", "MAVERICK_UPSCALE_MODEL", "Model for enlarging an image"),
)


def validate_model(value: object) -> str:
    """An empty choice preserves the existing model; malformed input refuses."""
    if not isinstance(value, str) or not re.fullmatch(MODEL_PATTERN, value):
        raise ValueError(
            "Choose a Replicate model name from its model page, with an optional version. "
            "Web addresses, file paths and spaces cannot be used here."
        )
    return value


def current_model(field: str, env: str, default: str) -> str:
    """Read on every operation, with the existing environment precedence."""
    from . import config

    cfg = config.load_config()
    if config.config_source_errors(include_tenant=True):
        raise ValueError("Image model settings are unavailable. Review Images in All settings.")
    value = os.environ.get(env, "").strip()
    if value:
        return validate_model(value)
    table = cfg.get("image_edit", {})
    if not isinstance(table, dict):
        raise ValueError("Image model settings are unavailable. Review Images in All settings.")
    saved = table.get(field)
    if saved is not None:
        value = validate_model(saved)
    return value or default
