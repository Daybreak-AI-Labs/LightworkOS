"""Loopback-only starter-team browser fixture; no providers or background work."""
from __future__ import annotations

import argparse
import tempfile
from pathlib import Path

import server


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", required=True, type=int)
    arguments = parser.parse_args()
    server.exit_cleanly_on_sigterm()
    server.CONFIG = server.CONFIG.replace('[features]', '[features]\ncopilot_operations = true').replace(
        'operation_families = ["learning", "commitments"]', 'operation_families = ["tasks"]')
    with tempfile.TemporaryDirectory(prefix="lightwork-starter-browser-", ignore_cleanup_errors=True) as temporary:
        directory = Path(temporary)
        server.environment(directory)
        server.block_outbound()
        app = server.build_app(directory)
        import uvicorn
        uvicorn.run(app, host="127.0.0.1", port=arguments.port, lifespan="off", log_level="warning")


if __name__ == "__main__":
    main()
