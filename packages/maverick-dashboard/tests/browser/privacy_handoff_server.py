"""Disposable native Privacy/Copilot server; synthetic identities, no remote delivery."""
import argparse
import tempfile
from pathlib import Path

import server


def main():
    server.exit_cleanly_on_sigterm()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    server.CONFIG = server.CONFIG.replace("guided_onboarding = true", "guided_onboarding = true\ncopilot_operations = true")
    server.CONFIG = server.CONFIG.replace('["learning", "commitments"]', '["learning", "commitments", "artifacts"]')
    with tempfile.TemporaryDirectory(prefix="lightwork-privacy-handoff-") as temporary:
        directory = Path(temporary)
        server.environment(directory)
        server.block_outbound()
        app = server.build_app(directory)
        import uvicorn
        uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="warning", timeout_keep_alive=server.KEEP_ALIVE_SECONDS)


if __name__ == "__main__":
    main()
