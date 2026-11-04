"""Channel adapters for Lightwork.

A channel normalizes incoming messages from any platform into a shared
``IncomingMessage`` shape, hands it to the orchestrator, and routes the
response back. This is the surface Lightwork uses to power phone-companion
mode — the agent itself runs on Desktop or VPS, and channels give a
phone (or any other client) a way to talk to it.

Server-wired adapters (18; registered in ``maverick.server._WIRES`` and
enableable from the installer, each requiring its provider's credentials and a
per-sender allowlist, default-deny):
  - telegram, discord, slack, signal, email, matrix
  - bluesky, mastodon, irc, threads, rcs, voice
  - whatsapp + sms (Twilio + public webhook), whatsapp_cloud (Meta Graph API)
  - teams (Azure Bot Framework webhook; approvals as Adaptive Cards)
  - mattermost (bot account answering direct messages and @mentions)
  - imessage (macOS only)
rich_render (KaTeX/Mermaid — applied by ``server.add_channel`` when
``[channels] rich_render`` is on) is an opt-in helper layered on the base
channels rather than a separate adapter. signal needs signal-cli on PATH;
matrix needs matrix-nio.
"""
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _distribution_version

from .base import Channel, Handler, IncomingMessage, Reply, as_reply

try:
    __version__ = _distribution_version("maverick-channels")
except PackageNotFoundError:  # source tree without installed metadata
    __version__ = "0.1.7"
__all__ = ["Channel", "IncomingMessage", "Handler", "Reply", "as_reply"]
