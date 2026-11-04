"""Run the environment hunter without importing Lightwork."""
from __future__ import annotations

import os

os.environ["ENV_HUNTER_STANDALONE"] = "1"

import uvicorn  # noqa: E402

if __name__ == "__main__":
    uvicorn.run("app:app", host="127.0.0.1", port=int(os.environ.get("ENV_HUNTER_PORT", "8893")))
