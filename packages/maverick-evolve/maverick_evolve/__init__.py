"""Governed self-evolution for Lightwork: evaluation, archive and search.

Code self-modification is deliberately NOT here -- see the package README.
Everything in this package is opt-in and pure/DI so it is
testable without a live model.
"""
from __future__ import annotations

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _distribution_version

from . import config_space
from .agent_adapter import evolve_live, make_agent_factory
from .archive import Archive, Candidate
from .eval_harness import (
    EvalCase,
    EvalObservation,
    EvalReport,
    evaluate,
    evaluate_case,
    observe_case,
)
from .loop import evolve_continuous
from .metaproductive import (
    CladeNode,
    MetaproductiveArchive,
    MetaproductiveSearchError,
    evolve_metaproductive,
)
from .runner import (
    ConfirmationAuthorize,
    ConfirmationPermit,
    ConfirmationRequest,
    EvolutionFrozen,
    calibration_frozen,
    confirm_candidate,
    evolve_metaproductive_with_eval,
    evolve_with_eval,
    strict_calibration_ready,
)
from .search import evolve

try:
    __version__ = _distribution_version("maverick-evolve")
except PackageNotFoundError:  # source tree without installed metadata
    __version__ = "0.1.7"

__all__ = [
    "EvalCase",
    "EvalReport",
    "EvalObservation",
    "evaluate",
    "evaluate_case",
    "observe_case",
    "Archive",
    "Candidate",
    "evolve",
    "evolve_metaproductive",
    "evolve_metaproductive_with_eval",
    "MetaproductiveArchive",
    "MetaproductiveSearchError",
    "CladeNode",
    "config_space",
    "evolve_with_eval",
    "evolve_continuous",
    "evolve_live",
    "make_agent_factory",
    "calibration_frozen",
    "strict_calibration_ready",
    "confirm_candidate",
    "EvolutionFrozen",
    "ConfirmationAuthorize",
    "ConfirmationPermit",
    "ConfirmationRequest",
]
