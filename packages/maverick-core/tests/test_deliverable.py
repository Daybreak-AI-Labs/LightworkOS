"""Rendering a goal result as the deliverable its pack declares: parse the grid
agents emit (pipe tables) when the shape is structured, else fall back to prose."""
from __future__ import annotations

from maverick.deliverable import (
    RenderedDeliverable,
    parse_pipe_table,
    render_deliverable,
)

_FORECAST = """\
Here is the rolling forecast, every figure tied to its system of record.

| Week | Inflows | Outflows | Net |
| --- | ---: | ---: | ---: |
| W1 | 1,200 | 900 | 300 |
| W2 | 1,100 | 1,000 | 100 |

Assumptions: collections hold at trend.
"""


class TestParsePipeTable:
    def test_parses_header_and_rows(self):
        t = parse_pipe_table(_FORECAST)
        assert t is not None
        assert t.headers == ["Week", "Inflows", "Outflows", "Net"]
        assert t.rows[0] == ["W1", "1,200", "900", "300"]
        assert len(t.rows) == 2

    def test_parses_without_outer_pipes(self):
        t = parse_pipe_table("a | b\n--- | ---\n1 | 2\n")
        assert t.headers == ["a", "b"]
        assert t.rows == [["1", "2"]]

    def test_alignment_colons_are_a_valid_separator(self):
        t = parse_pipe_table("| x | y |\n| :--- | ---: |\n| 1 | 2 |\n")
        assert t is not None and t.headers == ["x", "y"]

    def test_ragged_rows_padded_to_header_width(self):
        t = parse_pipe_table("| a | b | c |\n| - | - | - |\n| 1 | 2 |\n")
        assert t.rows == [["1", "2", ""]]

    def test_stops_body_at_first_non_table_line(self):
        t = parse_pipe_table("| a |\n| - |\n| 1 |\nnarrative after\n| 2 |\n")
        assert t.rows == [["1"]]

    def test_plain_text_has_no_table(self):
        assert parse_pipe_table("just a sentence, no grid here.") is None

    def test_header_without_separator_is_not_a_table(self):
        # A lone pipe line (no --- separator) must not be mistaken for a table.
        assert parse_pipe_table("Net | total cash\nis 300 this week\n") is None


class TestRenderDeliverable:
    def test_forecast_with_table_is_structured_grid(self):
        d = render_deliverable("forecast", _FORECAST)
        assert d.structured is True
        assert d.table is not None
        assert d.table.headers[0] == "Week"

    def test_prose_shape_is_never_structured(self):
        d = render_deliverable("prose", _FORECAST)
        assert d.structured is False
        assert d.table is None
        assert "rolling forecast" in d.prose

    def test_structured_shape_without_table_falls_back_to_prose(self):
        d = render_deliverable("report", "A narrative memo with no grid.")
        assert d.structured is True          # still earns a titled card
        assert d.table is None               # but there's nothing to tabulate
        assert d.prose == "A narrative memo with no grid."

    def test_none_and_empty_inputs_are_safe(self):
        assert render_deliverable(None, None) == RenderedDeliverable(shape="prose", prose="")
        assert render_deliverable("forecast", None).prose == ""

    def test_unknown_shape_is_treated_as_prose(self):
        d = render_deliverable("hologram", _FORECAST)
        assert d.structured is False
