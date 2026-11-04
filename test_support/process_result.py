"""Complete-file publication for JSON from disposable acceptance-test children."""
from __future__ import annotations

import json
from os import replace
from pathlib import Path


def publish_json_result(path: Path, result: object) -> None:
    """Publish only after closing the owned sibling; existence means complete."""
    payload = json.dumps(result)
    temporary = path.with_name(f"{path.name}.pending")
    # Every caller owns a unique test directory and a single result writer.
    # Exclusive creation also refuses to overwrite an unexpected staged file.
    with temporary.open("x", encoding="utf-8") as stream:
        stream.write(payload)
    try:
        replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
