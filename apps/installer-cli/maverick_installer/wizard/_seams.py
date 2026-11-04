"""Late-bound access to the wizard facade's patchable names.

Tests patch prompt primitives on the facade module,
``maverick_installer.wizard._q_confirm`` and friends, plus ``console`` and the
``CONFIG_*`` paths.  A step module that imported those names directly would
bind the originals at import time and miss the patch.  Everything here looks
the current binding up on the facade at call time instead, so the step
modules behave exactly like code that still lives in the facade.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any


def _facade() -> Any:
    return sys.modules[__package__]


def _q_confirm(message: str, default: bool = True) -> bool:
    return _facade()._q_confirm(message, default=default)


def _q_text(message: str, default: str = "") -> str:
    return _facade()._q_text(message, default=default)


def _q_select(message: str, choices: list[str], default: str | None = None) -> str:
    return _facade()._q_select(message, choices, default=default)


def _q_checkbox(message: str, choices: list[str], default: list[str] | None = None) -> list[str]:
    return _facade()._q_checkbox(message, choices, default=default)


def _q_secret(message: str) -> str:
    return _facade()._q_secret(message)


def config_file() -> Path:
    """The facade's ``CONFIG_FILE`` as currently bound."""
    return _facade().CONFIG_FILE


class _ConsoleProxy:
    """Forwards every attribute to the facade's current ``console``."""

    def __getattr__(self, name: str) -> Any:
        return getattr(_facade().console, name)


console = _ConsoleProxy()
