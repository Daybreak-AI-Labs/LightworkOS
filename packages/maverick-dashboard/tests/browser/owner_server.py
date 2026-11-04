"""Fresh real owner-form server: no injected identity or request headers."""
import argparse
import os
import secrets
import tempfile
from pathlib import Path

from server import KEEP_ALIVE_SECONDS, block_outbound, exit_cleanly_on_sigterm


def main():
    exit_cleanly_on_sigterm()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="lightwork-owner-browser-") as temporary:
        for key in tuple(os.environ):
            if key.startswith(("MAVERICK_", "LIGHTWORK_")) or key.endswith("_API_KEY"):
                os.environ.pop(key)
        directory = Path(temporary)
        config = directory / "config.toml"
        config.write_text("[client]\nid='owner-browser'\n[voice]\nauto_fetch_model=false\n", encoding="utf-8")
        os.environ.update(MAVERICK_HOME=str(directory), MAVERICK_CONFIG=str(config),
                          MAVERICK_TENANT="owner-browser", MAVERICK_CLIENT_ID="owner-browser",
                          MAVERICK_ENCRYPT_AT_REST="1", MAVERICK_ENCRYPTION_KEY=secrets.token_hex(32))
        block_outbound()
        import uvicorn
        from maverick_dashboard.app import app

        uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="warning", timeout_keep_alive=KEEP_ALIVE_SECONDS)


if __name__ == "__main__":
    main()
