"""Run the Model Risk & AI Assurance Officer without importing Lightwork."""

from __future__ import annotations

import os

os.environ["MODEL_RISK_OFFICER_STANDALONE"] = "1"

import uvicorn  # noqa: E402

if __name__ == "__main__":
    uvicorn.run(
        "app:app",
        host="127.0.0.1",
        port=int(os.environ.get("MODEL_RISK_OFFICER_PORT", "8896")),
    )
