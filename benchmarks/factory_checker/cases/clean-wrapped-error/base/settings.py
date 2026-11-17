"""Load settings from a JSON file."""
import json
from pathlib import Path


def load(path):
    """The settings in ``path``."""
    return json.loads(Path(path).read_text())
