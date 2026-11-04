"""Read current signed-skill setup and hand off to governed publisher settings."""
from maverick.governed_operations import digest

from . import learning_acquisition_api as native
from .product_operations import Adapter, EmptyInput, Preview, Snapshot


def snapshot(request, _selection):
    value = native.current(request)
    return Snapshot(digest(value), "Current automatic skill preparation", value["notice"])


def prepare(request, _selection, _arguments):
    value = native.current(request)
    return Preview(value["message"], native={"Status": value["status"],
        "Trusted publishers configured": value["trusted_publishers"], "What this establishes": value["notice"],
        "Review setup": value["remedy"]})


def entries():
    return (Adapter("learning.skill_preparation", "Check automatic skill preparation", family="learning",
                    pages=("/learning",), direct_ui="/learning#learning-acquisition", input_model=EmptyInput,
                    snapshot=snapshot, prepare=prepare),)
