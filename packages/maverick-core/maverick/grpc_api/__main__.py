"""`python -m maverick.grpc_api` -> start the gRPC server."""
from __future__ import annotations

import sys

from .server import main

if __name__ == "__main__":
    sys.exit(main())
