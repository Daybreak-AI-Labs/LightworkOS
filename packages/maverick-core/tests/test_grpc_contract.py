"""gRPC API v1 stability contract: parser + golden compat gate."""
from __future__ import annotations

from maverick.grpc_api import contract

_PROTO = """
syntax = "proto3";
package maverick.v1;
service Maverick {
  rpc StartGoal(StartGoalRequest) returns (StartGoalResponse);
  rpc StreamEpisode(StreamEpisodeRequest) returns (stream Event);
}
message StartGoalRequest {
  string title = 1;
  double max_dollars = 3;
  repeated string tags = 4;
}
message Event {
  int64 id = 1;
}
"""


def test_parser_inventory_shape():
    inv = contract.parse_inventory(_PROTO)
    assert inv["package"] == "maverick.v1"
    assert inv["services"]["Maverick"]["StreamEpisode"]["response_stream"] is True
    assert inv["services"]["Maverick"]["StartGoal"]["response_stream"] is False
    f = inv["messages"]["StartGoalRequest"]["tags"]
    assert f == {"number": 4, "type": "string", "label": "repeated"}


def test_real_proto_matches_committed_golden():
    """The CI gate: the shipped proto must satisfy its own golden."""
    assert contract.breaking_changes(contract.load_golden(),
                                     contract.load_current()) == []


def test_golden_pins_the_known_v1_surface():
    g = contract.load_golden()
    assert g["package"] == "maverick.v1"
    assert "StartGoal" in g["services"]["Maverick"]
    assert "RunGoal" in g["services"]["Maverick"]
    assert g["messages"]["StartGoalRequest"]["title"]["number"] == 1


def _mutate(**kw):
    golden = contract.parse_inventory(_PROTO)
    current = contract.parse_inventory(kw.get("proto", _PROTO))
    return contract.breaking_changes(golden, current)


def test_additive_changes_allowed():
    added = _PROTO + "\nmessage NewThing { string x = 1; }\n"
    assert _mutate(proto=added) == []
    new_field = _PROTO.replace("repeated string tags = 4;",
                               "repeated string tags = 4;\n  string note = 5;")
    assert _mutate(proto=new_field) == []


def test_field_removal_breaks():
    removed = _PROTO.replace("  double max_dollars = 3;\n", "")
    assert any("field removed: StartGoalRequest.max_dollars" in p
               for p in _mutate(proto=removed))


def test_field_renumber_breaks():
    renum = _PROTO.replace("double max_dollars = 3;", "double max_dollars = 9;")
    assert any("renumbered" in p for p in _mutate(proto=renum))


def test_field_type_change_breaks():
    retyped = _PROTO.replace("double max_dollars = 3;", "int64 max_dollars = 3;")
    assert any("type changed" in p for p in _mutate(proto=retyped))


def test_rpc_shape_change_breaks():
    unstreamed = _PROTO.replace("returns (stream Event)", "returns (Event)")
    assert any("rpc shape changed" in p for p in _mutate(proto=unstreamed))


def test_rpc_and_service_removal_break():
    no_rpc = _PROTO.replace(
        "  rpc StartGoal(StartGoalRequest) returns (StartGoalResponse);\n", "")
    assert any("rpc removed" in p for p in _mutate(proto=no_rpc))
    no_svc = _PROTO.replace("service Maverick", "service Other")
    assert any("service removed" in p for p in _mutate(proto=no_svc))


def test_field_number_reuse_breaks():
    reused = _PROTO.replace("  double max_dollars = 3;\n", "")\
                   .replace("repeated string tags = 4;",
                            "repeated string tags = 4;\n  string sneaky = 3;")
    problems = _mutate(proto=reused)
    assert any("field number reused" in p and "sneaky" in p for p in problems)


def test_package_change_breaks():
    v2 = _PROTO.replace("package maverick.v1;", "package maverick.v2;")
    assert any("package changed" in p for p in _mutate(proto=v2))


def test_parser_keeps_outer_fields_around_nested_message():
    """A nested message must not steal the enclosing message's later fields.

    The old single-depth counter reset the current message to ``Inner`` and
    dropped ``Outer.c``; the stack-based scope tracks both correctly.
    """
    proto = """
message Outer {
  int64 a = 1;
  message Inner { int64 b = 1; }
  int64 c = 2;
}
"""
    msgs = contract.parse_inventory(proto)["messages"]
    assert msgs["Outer"]["a"]["number"] == 1
    assert msgs["Outer"]["c"]["number"] == 2
    assert msgs["Inner"]["b"]["number"] == 1


def test_parser_captures_single_line_message_field():
    inv = contract.parse_inventory("message Req { int64 x = 1; }")
    assert inv["messages"]["Req"]["x"] == {
        "number": 1, "type": "int64", "label": ""}


def test_parser_ignores_braces_in_block_comments():
    """A stray ``}`` inside a /* */ comment must not close the message early."""
    proto = """
message A {
  /* a comment with a } brace */
  int64 x = 1;
}
"""
    assert contract.parse_inventory(proto)["messages"]["A"]["x"]["number"] == 1


def test_parser_keeps_fields_inside_oneof():
    """A `oneof` block is an unkeyed nested scope like an rpc option body, but
    its fields must still attribute to the enclosing message -- not vanish
    into the untracked scope, which would let a later proto3 `oneof` field
    removal/renumber silently bypass the breaking-change CI gate."""
    proto = """
message M {
  oneof kind {
    int64 a = 1;
    string b = 2;
  }
  int64 c = 3;
}
"""
    fields = contract.parse_inventory(proto)["messages"]["M"]
    assert set(fields) == {"a", "b", "c"}
    assert fields["a"]["number"] == 1
    assert fields["b"]["number"] == 2
    assert fields["c"]["number"] == 3


def test_parser_handles_rpc_option_body():
    """An rpc with an option body must not desync the service scope, and a
    following single-line message must still be parsed."""
    proto = """
service S {
  rpc Foo (Req) returns (Resp) { option deadline = 5; }
  rpc Bar (Req) returns (Resp);
}
message Req { int64 x = 1; }
"""
    inv = contract.parse_inventory(proto)
    assert set(inv["services"]["S"]) == {"Foo", "Bar"}
    assert inv["messages"]["Req"]["x"]["number"] == 1
