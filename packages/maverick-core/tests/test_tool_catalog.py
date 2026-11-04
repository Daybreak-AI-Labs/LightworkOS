"""Catalog declarations preserve tool ordering, authority and deferral."""
import pytest
from maverick.tools import Tool, ToolRegistry
from maverick.tools.catalog import ToolDescriptor, declared_names, register_descriptors


def _tool(name):
    return Tool(name=name, description="example", input_schema={}, fn=lambda args: name)


def test_names_can_be_inspected_without_constructing_factories():
    def must_not_run():
        raise AssertionError("catalog introspection must not invoke the factory")

    descriptors = (ToolDescriptor("first", must_not_run), ToolDescriptor("second", must_not_run, True))
    assert declared_names(descriptors) == ("first", "second")


def test_registration_keeps_order_and_deferred_metadata():
    seen = []

    def first():
        seen.append("first")
        return _tool("first")

    def second():
        seen.append("second")
        return _tool("second")

    registry = ToolRegistry()
    register_descriptors(registry, (ToolDescriptor("first", first), ToolDescriptor("second", second, True)))
    assert seen == ["first", "second"]
    assert [tool.name for tool in registry.all()] == ["first", "second"]
    assert registry.catalog_metadata() == [
        {"name": "first", "deferred_eligible": False},
        {"name": "second", "deferred_eligible": True},
    ]


def test_factory_name_mismatch_fails_before_registration():
    registry = ToolRegistry()
    with pytest.raises(ValueError, match="catalog declares"):
        register_descriptors(registry, (ToolDescriptor("expected", lambda: _tool("different"), True),))
    assert registry.all() == []
    assert registry.deferrable_names == set()


def test_catalog_metadata_does_not_reveal_hidden_or_denied_tools():
    registry = ToolRegistry()
    for name in ("visible", "hidden", "denied"):
        registry.register(_tool(name))
    registry._hidden.add("hidden")
    registry.set_acl(denied={"denied"})
    assert registry.catalog_metadata() == [{"name": "visible", "deferred_eligible": False}]
