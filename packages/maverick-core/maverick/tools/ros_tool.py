"""ROS robotics action tool — publish topics / call services over rosbridge.

Drives a ROS (Robot Operating System) stack from the agent: publish a command
to a topic (e.g. ``/cmd_vel`` to move a base) or call a service. Talks to a
**rosbridge** WebSocket server via ``roslibpy`` (the ``[ros]`` extra) — no
native ROS install in the agent process; the robot side runs rosbridge.

Auth: ``ROS_BRIDGE_URL`` (default ``ws://localhost:9090``). This commands
physical or simulated hardware, so it is high risk and is only registered when
the operator explicitly enables ``[capabilities].ros = true``.

ops:
  - publish(topic, type, message)        — publish one Message to a topic
  - call_service(service, type, request) — call a service, return its response
"""
from __future__ import annotations

import os
from typing import Any
from urllib.parse import urlparse

from . import Tool

_ROS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["publish", "call_service"]},
        "topic": {"type": "string"},
        "service": {"type": "string"},
        "type": {"type": "string", "description": "ROS message/service type, e.g. geometry_msgs/Twist"},
        "message": {"type": "object", "description": "message payload (publish)"},
        "request": {"type": "object", "description": "service request payload"},
    },
    "required": ["op", "type"],
}


def _parse_url(url: str) -> tuple[str, int, bool]:
    u = urlparse(url or "ws://localhost:9090")
    secure = u.scheme == "wss"
    return (u.hostname or "localhost"), (u.port or 9090), secure


def _connect(roslibpy):
    host, port, secure = _parse_url(os.environ.get("ROS_BRIDGE_URL", ""))
    ros = roslibpy.Ros(host=host, port=port, is_secure=secure)
    ros.run()
    return ros


def _op_publish(roslibpy, args: dict) -> str:
    topic = (args.get("topic") or "").strip()
    if not topic:
        return "ERROR: publish requires topic"
    ros = _connect(roslibpy)
    try:
        if not getattr(ros, "is_connected", False):
            return "ERROR: not connected to rosbridge (check ROS_BRIDGE_URL)"
        t = roslibpy.Topic(ros, topic, args["type"])
        t.publish(roslibpy.Message(args.get("message") or {}))
        return f"published to {topic} ({args['type']})"
    finally:
        try:
            ros.terminate()
        except Exception:  # pragma: no cover
            pass


def _op_call_service(roslibpy, args: dict) -> str:
    service = (args.get("service") or "").strip()
    if not service:
        return "ERROR: call_service requires service"
    ros = _connect(roslibpy)
    try:
        if not getattr(ros, "is_connected", False):
            return "ERROR: not connected to rosbridge (check ROS_BRIDGE_URL)"
        svc = roslibpy.Service(ros, service, args["type"])
        result = svc.call(roslibpy.ServiceRequest(args.get("request") or {}))
        return f"{service} -> {result}"
    finally:
        try:
            ros.terminate()
        except Exception:  # pragma: no cover
            pass


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if not op:
        return "ERROR: op is required"
    if not (args.get("type") or "").strip():
        return "ERROR: type is required"
    try:
        import roslibpy
    except ImportError:
        return "ERROR: roslibpy not installed. Run: python -m pip install -e './packages/maverick-core[ros]'"
    try:
        if op == "publish":
            return _op_publish(roslibpy, args)
        if op == "call_service":
            return _op_call_service(roslibpy, args)
    except Exception as e:
        return f"ERROR: ROS request failed: {type(e).__name__}: {e}"
    return f"ERROR: unknown op {op!r}"


def ros_tool() -> Tool:
    return Tool(
        name="ros",
        description=(
            "ROS robotics over rosbridge. ops: publish (topic + type + "
            "message), call_service (service + type + request). Commands a "
            "robot/sim. High-risk; register only after explicit operator opt-in. "
            "Auth: ROS_BRIDGE_URL (default ws://localhost:9090); requires the [ros] extra (roslibpy)."
        ),
        input_schema=_ROS_SCHEMA,
        fn=_run,
    )
