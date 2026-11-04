"""Launch the DSAR Concierge standalone (no Lightwork platform).

Env: DSAR_STANDALONE=1 is set by the launcher; DSAR_HOST defaults to
loopback (set 0.0.0.0 for containers/proxies), DSAR_PORT to 8891, and
DSAR_DATA_DIR to ./.dsar-data. See README.md.
"""
from __future__ import annotations

import os


def bind() -> tuple[str, int]:
    return (os.environ.get("DSAR_HOST", "127.0.0.1"),
            int(os.environ.get("DSAR_PORT", "8891")))


def main() -> None:  # pragma: no cover - thin launcher
    os.environ.setdefault("DSAR_STANDALONE", "1")
    import uvicorn
    from app import app
    host, port = bind()
    print(f"DSAR Concierge (standalone) → http://{host}:{port}")
    uvicorn.run(app, host=host, port=port, log_level="warning", proxy_headers=False)


if __name__ == "__main__":  # pragma: no cover
    main()
