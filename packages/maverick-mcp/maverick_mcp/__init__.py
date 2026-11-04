"""MCP server for Lightwork."""

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _distribution_version

try:
    __version__ = _distribution_version("maverick-mcp-server")
except PackageNotFoundError:  # source tree without installed metadata
    __version__ = "0.1.7"
