"""Agent Shield integration for Lightwork."""
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _distribution_version

from .compartment import ImmunizingShield, ThreatLedger, compartments_enabled
from .guard import Shield, ShieldVerdict

try:
    __version__ = _distribution_version("maverick-shield")
except PackageNotFoundError:  # source tree without installed metadata
    __version__ = "0.1.7"
__all__ = [
    "Shield",
    "ShieldVerdict",
    "ImmunizingShield",
    "ThreatLedger",
    "compartments_enabled",
]
