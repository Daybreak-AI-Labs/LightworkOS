"""Run the platform hunter without importing Lightwork."""
from __future__ import annotations

import os

os.environ["PLATFORM_HUNTER_STANDALONE"] = "1"

import uvicorn  # noqa: E402

if __name__ == "__main__":
    uvicorn.run("app:app", host="127.0.0.1", port=int(os.environ.get("PLATFORM_HUNTER_PORT", "8892")))
