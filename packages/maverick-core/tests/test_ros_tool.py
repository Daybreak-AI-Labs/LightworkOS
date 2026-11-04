"""ROS robotics tool: publish / call_service over a faked roslibpy."""
from __future__ import annotations

import sys
import types

from maverick.tools.ros_tool import _parse_url, ros_tool


def _install_fake_roslibpy(monkeypatch, *, connected=True, service_result=None):
    calls: dict = {"published": [], "services": [], "terminated": 0, "ros_args": None}

    class Ros:
        def __init__(self, host, port, is_secure=False):
            calls["ros_args"] = (host, port, is_secure)
            self.is_connected = False

        def run(self):
            self.is_connected = connected

        def terminate(self):
            calls["terminated"] += 1

    class Topic:
        def __init__(self, ros, name, mtype):
            self._name, self._type = name, mtype

        def publish(self, msg):
            calls["published"].append((self._name, self._type, msg))

    class Service:
        def __init__(self, ros, name, stype):
            self._name = name

        def call(self, req):
            calls["services"].append((self._name, req))
            return service_result if service_result is not None else {"ok": True}

    mod = types.ModuleType("roslibpy")
    mod.Ros = Ros
    mod.Topic = Topic
    mod.Service = Service
    mod.Message = lambda payload: {"_msg": payload}
    mod.ServiceRequest = lambda payload: {"_req": payload}
    monkeypatch.setitem(sys.modules, "roslibpy", mod)
    return calls


def test_parse_url():
    assert _parse_url("ws://localhost:9090") == ("localhost", 9090, False)
    assert _parse_url("wss://robot.local:443") == ("robot.local", 443, True)
    assert _parse_url("") == ("localhost", 9090, False)


def test_missing_roslibpy(monkeypatch):
    monkeypatch.setitem(sys.modules, "roslibpy", None)
    out = ros_tool().fn({"op": "publish", "topic": "/cmd_vel", "type": "geometry_msgs/Twist"})
    assert out.startswith("ERROR") and "roslibpy not installed" in out


def test_requires_type():
    assert ros_tool().fn({"op": "publish", "topic": "/x"}).startswith("ERROR")


def test_publish(monkeypatch):
    calls = _install_fake_roslibpy(monkeypatch)
    out = ros_tool().fn({"op": "publish", "topic": "/cmd_vel",
                         "type": "geometry_msgs/Twist",
                         "message": {"linear": {"x": 1.0}}})
    assert out == "published to /cmd_vel (geometry_msgs/Twist)"
    assert calls["published"][0][0] == "/cmd_vel"
    assert calls["published"][0][2] == {"_msg": {"linear": {"x": 1.0}}}
    assert calls["terminated"] == 1  # connection cleaned up


def test_publish_requires_topic(monkeypatch):
    _install_fake_roslibpy(monkeypatch)
    out = ros_tool().fn({"op": "publish", "type": "std_msgs/String"})
    assert out.startswith("ERROR") and "requires topic" in out


def test_publish_not_connected(monkeypatch):
    calls = _install_fake_roslibpy(monkeypatch, connected=False)
    out = ros_tool().fn({"op": "publish", "topic": "/x", "type": "std_msgs/String"})
    assert out.startswith("ERROR") and "not connected" in out
    assert calls["terminated"] == 1  # still cleaned up


def test_call_service(monkeypatch):
    calls = _install_fake_roslibpy(monkeypatch, service_result={"sum": 3})
    out = ros_tool().fn({"op": "call_service", "service": "/add",
                         "type": "rospy_tutorials/AddTwoInts",
                         "request": {"a": 1, "b": 2}})
    assert "/add ->" in out and "sum" in out
    assert calls["services"][0][1] == {"_req": {"a": 1, "b": 2}}


def test_call_service_requires_service(monkeypatch):
    _install_fake_roslibpy(monkeypatch)
    out = ros_tool().fn({"op": "call_service", "type": "x/Srv"})
    assert out.startswith("ERROR") and "requires service" in out


def test_url_parsed_into_connection(monkeypatch):
    monkeypatch.setenv("ROS_BRIDGE_URL", "wss://robot:9999")
    calls = _install_fake_roslibpy(monkeypatch)
    ros_tool().fn({"op": "publish", "topic": "/x", "type": "std_msgs/String"})
    assert calls["ros_args"] == ("robot", 9999, True)


def test_unknown_op(monkeypatch):
    _install_fake_roslibpy(monkeypatch)
    assert ros_tool().fn({"op": "nope", "type": "x"}).startswith("ERROR: unknown op")


def test_not_registered_by_default():
    from maverick.tools import base_registry

    class _W:
        pass

    class _S:
        workdir = "."

    names = set(getattr(base_registry(world=_W(), sandbox=_S()), "_tools", {}).keys())
    assert "ros" not in names


def test_registered_when_enabled():
    from maverick.tools import base_registry

    class _W:
        pass

    class _S:
        workdir = "."

    names = set(getattr(base_registry(world=_W(), sandbox=_S(), enable_ros=True), "_tools", {}).keys())
    assert "ros" in names
