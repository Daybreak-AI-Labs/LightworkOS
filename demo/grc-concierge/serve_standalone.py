"""Run GRC Concierge while guaranteeing the standalone backend."""
from __future__ import annotations

import os

os.environ["GRC_STANDALONE"] = "1"

import uvicorn  # noqa: E402

if __name__ == "__main__":
    uvicorn.run("app:app", host="127.0.0.1", port=int(os.environ.get("GRC_PORT", "8891")))
