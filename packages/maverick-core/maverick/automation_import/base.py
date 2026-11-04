"""Importer protocol + registry.

An :class:`Importer` knows how to talk to ONE external platform: ``fetch()``
pulls raw automation definitions from that platform's API, and ``translate()``
lowers one raw definition into the shared :class:`~.ir.ImportedAutomation`. The
two halves are split on purpose -- ``translate`` is a pure function (unit-tested
against fixture JSON with no network), and ``fetch`` is the thin, credentialed
API layer (single-tenant: creds come from env vars like the rest of the
connector layer).

Platforms that do NOT expose their automation definitions over an API (Zapier,
Notion automations) implement ``fetch`` as a no-op that explains the limitation
and provide ``translate`` for definitions supplied another way (an exported
blueprint the user pastes in), plus a "connect" path documented on the importer.
"""
from __future__ import annotations

import importlib
from collections.abc import Callable
from typing import Any, Protocol, runtime_checkable

from .ir import ImportedAutomation


class ImporterError(RuntimeError):
    """Raised for configuration/fetch problems (missing creds, bad response)."""


@runtime_checkable
class Importer(Protocol):
    source: str
    #: True when this platform exposes automation *definitions* over an API
    #: (so ``fetch`` returns real data). False for trigger-only/connect-only
    #: platforms (Zapier, Notion automations) where ``fetch`` cannot enumerate.
    can_fetch_definitions: bool

    def fetch(self) -> list[dict[str, Any]]:
        """Return raw automation definitions from the platform (or raise)."""
        ...

    def translate(self, raw: dict[str, Any]) -> ImportedAutomation:
        """Lower one raw definition into the shared IR."""
        ...


_REGISTRY: dict[str, Callable[[], Importer]] = {}
_LAZY_MODULES: dict[str, str] = {}


def register(source: str, factory: Callable[[], Importer]) -> None:
    """Register an importer factory under its ``source`` name (idempotent)."""
    _REGISTRY[source] = factory


def register_lazy(source: str, module: str) -> None:
    """Declare the module that registers ``source`` when first requested."""
    _LAZY_MODULES[source] = module


def available_sources() -> list[str]:
    return sorted(_REGISTRY.keys() | _LAZY_MODULES.keys())


def get_importer(source: str) -> Importer:
    factory = _REGISTRY.get(source)
    if factory is None and source in _LAZY_MODULES:
        module = _LAZY_MODULES[source]
        try:
            importlib.import_module(module)
        except Exception as exc:
            raise ImporterError(
                f"automation source {source!r} could not be loaded from "
                f"{module!r}: {type(exc).__name__}: {exc}"
            ) from exc
        factory = _REGISTRY.get(source)
        if factory is None:
            raise ImporterError(
                f"automation source {source!r} did not register an importer "
                f"after loading {module!r}"
            )
    if factory is None:
        raise ImporterError(
            f"unknown automation source {source!r}; "
            f"available: {', '.join(available_sources()) or '(none)'}"
        )
    return factory()


def translate_all(source: str, raws: list[dict[str, Any]]) -> list[ImportedAutomation]:
    """Translate a batch of raw definitions, skipping (and logging) bad ones."""
    import logging

    imp = get_importer(source)
    out: list[ImportedAutomation] = []
    for raw in raws:
        try:
            out.append(imp.translate(raw))
        except Exception as e:  # one malformed definition must not abort the batch
            logging.getLogger(__name__).warning(
                "automation_import: skipped a %s definition: %s", source, e
            )
    return out
