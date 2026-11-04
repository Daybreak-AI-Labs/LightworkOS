"""Zero-config BYO tool decorator."""
from __future__ import annotations

import pytest
from maverick.tools import Tool
from maverick.tools.decorator import clear_registered, registered_tools, tool


@pytest.fixture(autouse=True)
def _clean():
    clear_registered()
    yield
    clear_registered()


def test_decorated_fn_stays_callable_and_builds_tool():
    @tool
    def add(a: int, b: int) -> int:
        """Add two integers."""
        return a + b

    assert add(2, 3) == 5  # still a normal function
    assert isinstance(add.tool, Tool)
    assert add.tool.name == "add"
    assert add.tool.description == "Add two integers."


def test_schema_from_type_hints():
    @tool
    def greet(name: str, times: int = 1, loud: bool = False) -> str:
        return name

    schema = greet.tool.input_schema
    assert schema["properties"]["name"] == {"type": "string"}
    assert schema["properties"]["times"] == {"type": "integer"}
    assert schema["properties"]["loud"] == {"type": "boolean"}
    assert schema["required"] == ["name"]  # only the param without a default


def test_runs_through_tool_fn():
    @tool
    def mul(a: int, b: int) -> int:
        return a * b

    assert mul.tool.fn({"a": 4, "b": 5}) == "20"


def test_missing_required_arg_is_clean_error():
    @tool
    def needs(a: int) -> int:
        return a

    out = needs.tool.fn({})
    assert out.startswith("ERROR") and "bad arguments" in out


def test_untyped_param_accepts_anything():
    @tool
    def echo(x):
        return x

    assert echo.tool.input_schema["properties"]["x"] == {}  # no type constraint
    assert echo.tool.fn({"x": "hi"}) == "hi"


def test_options_form():
    @tool(name="custom", description="d", parallel_safe=True)
    def f(a: int) -> int:
        return a

    assert f.tool.name == "custom" and f.tool.parallel_safe is True


def test_registered_collection():
    @tool
    def one(a: int) -> int:
        return a

    @tool
    def two(a: int) -> int:
        return a

    names = {t.name for t in registered_tools()}
    assert {"one", "two"} <= names
