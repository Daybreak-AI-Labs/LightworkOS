"""Transform functions inside {{ }} templating and bounded-loop controls
(foreach max-iterations + early _break)."""
from __future__ import annotations

import pytest
from maverick.flow import Flow, FlowNode
from maverick.flow.runner import FlowCredentialRefused, eval_condition, render, run_flow


def test_text_functions_refuse_results_larger_than_a_run_can_hold():
    from maverick.flow.expressions import FlowTextLimitRefused

    x = {"x": "a" * 100}
    assert len(render("{{replace(replace(x,'',x),'',x)}}", x)) == 1_030_300
    with pytest.raises(FlowTextLimitRefused):
        render("{{replace(replace(replace(x,'',x),'',x),'',x)}}", x)
    with pytest.raises(FlowTextLimitRefused):
        render("{{concat(x, x)}}", {"x": "a" * (9 * 1024 * 1024)})


class TestArithmeticAndLists:
    def test_arithmetic(self):
        assert render("{{add(a, b)}}", {"a": 2, "b": 3}) == "5"      # int, not 5.0
        assert render("{{sub(10, 3)}}", {}) == "7"
        assert render("{{mul(qty, price)}}", {"qty": 3, "price": 4}) == "12"
        assert render("{{div(10, 4)}}", {}) == "2.5"
        assert render("{{div(1, 0)}}", {}) == "0"                    # divide-by-zero -> 0

    def test_nested_arithmetic_and_round(self):
        assert render("{{round(div(10, 3), 2)}}", {}) == "3.33"

    def test_list_first_last(self):
        assert render("{{first(items)}}", {"items": ["a", "b"]}) == "a"
        assert render("{{last(items)}}", {"items": ["a", "b"]}) == "b"


class TestStringAndCollectionTransforms:
    def test_split_and_join(self):
        assert render("{{join(split(csv, \",\"), \" | \")}}", {"csv": "a,b,c"}) == "a | b | c"
        assert render("{{split(name)}}", {"name": "a b"}) == "['a', 'b']"   # default whitespace split

    def test_slice_string_and_list(self):
        assert render("{{slice(s, 0, 3)}}", {"s": "hello"}) == "hel"
        assert render("{{slice(s, 2)}}", {"s": "hello"}) == "llo"           # to end
        assert render("{{index(items, 1)}}", {"items": ["x", "y", "z"]}) == "y"
        assert render("{{index(items, -1)}}", {"items": ["x", "y"]}) == "y"
        assert render("{{index(items, 9)}}", {"items": ["x"]}) == ""        # out of range

    def test_regex_extracts_group_or_whole_match(self):
        assert render("{{regex(email, \"@(.+)$\")}}", {"email": "a@example.com"}) == "example.com"
        assert render("{{regex(s, \"[0-9]+\")}}", {"s": "order 42 ok"}) == "42"    # whole match
        assert render("{{regex(s, \"zzz\")}}", {"s": "abc"}) == ""                 # no match
        from maverick.flow.runner import FlowRegexRefused
        with pytest.raises(FlowRegexRefused):
            render("{{regex(s, \"(\")}}", {"s": "abc"})

    def test_regex_rejects_redos_patterns(self):
        from maverick.flow.runner import FlowRegexRefused, _regex_is_safe
        for pattern in ("(a+)+$", "(.*)*", "(a?)+$", "(a|aa)+$", r"(a+)\1", "a*a*a*a*b"):
            with pytest.raises(FlowRegexRefused):
                render('{{regex(s, "' + pattern + '")}}', {"s": "a" * 2000})
        assert not _regex_is_safe("a{100000000}")
        # a normal capture with a single '+' inside a group still works
        assert render("{{regex(email, \"([a-z]+)@\")}}", {"email": "bob@x.com"}) == "bob"

    def test_abs_int_keys(self):
        assert render("{{abs(sub(3, 10))}}", {}) == "7"
        assert render("{{int(x)}}", {"x": "5.9"}) == "5"
        assert render("{{keys(m)}}", {"m": {"a": 1, "b": 2}}) == "['a', 'b']"

    def test_datefmt_from_epoch_and_iso(self):
        assert render("{{datefmt(ts, \"%Y-%m-%d\")}}", {"ts": 0}) == "1970-01-01"
        assert render("{{datefmt(when, \"%Y\")}}", {"when": "2027-03-04T12:00:00Z"}) == "2027"
        assert render("{{datefmt(bad, \"%Y\")}}", {"bad": "not-a-date"}) == ""

    def test_now_is_an_iso_utc_datetime(self):
        # ISO (not epoch) so it composes with add_days/today and lexical compares
        out = render("{{now()}}", {})
        import datetime as dt
        parsed = dt.datetime.fromisoformat(out)
        assert parsed.tzinfo is not None and parsed.year >= 2026


class TestConditionComposition:
    def test_single_predicate_still_works(self):
        assert eval_condition("x > 5", {"x": 10}) is True
        assert eval_condition("x > 5", {"x": 1}) is False

    def test_and_requires_both(self):
        c = "amount > 100 and region == 'EU'"
        assert eval_condition(c, {"amount": 150, "region": "EU"}) is True
        assert eval_condition(c, {"amount": 150, "region": "US"}) is False
        assert eval_condition(c, {"amount": 50, "region": "EU"}) is False

    def test_or_requires_either(self):
        c = "a == 1 or b == 2"
        assert eval_condition(c, {"a": 9, "b": 2}) is True
        assert eval_condition(c, {"a": 1, "b": 9}) is True
        assert eval_condition(c, {"a": 9, "b": 9}) is False

    def test_or_of_ands_precedence(self):
        # (tier == gold) OR (amount > 1000 AND region == 'EU')
        c = "tier == 'gold' or amount > 1000 and region == 'EU'"
        assert eval_condition(c, {"tier": "gold", "amount": 0, "region": "US"}) is True
        assert eval_condition(c, {"tier": "silver", "amount": 2000, "region": "EU"}) is True
        assert eval_condition(c, {"tier": "silver", "amount": 2000, "region": "US"}) is False

    def test_quoted_literals_can_contain_boolean_operator_words(self):
        assert eval_condition("role == 'contractor or vendor'", {"role": "contractor or vendor"}) is True
        assert eval_condition(
            "department == 'Research and Development'",
            {"department": "Research and Development"},
        ) is True

    def test_boolean_operators_still_compose_around_quoted_literals(self):
        c = "role == 'contractor or vendor' and region == 'EU' or tier == 'gold'"
        assert eval_condition(c, {"role": "contractor or vendor", "region": "EU", "tier": "silver"}) is True
        assert eval_condition(c, {"role": "employee", "region": "EU", "tier": "silver"}) is False
        assert eval_condition(c, {"role": "employee", "region": "US", "tier": "gold"}) is True


class TestDateFunctions:
    def test_today_is_an_iso_date(self):
        import datetime as dt
        assert render("{{today()}}", {}) == dt.datetime.now(dt.timezone.utc).date().isoformat()

    def test_add_days_from_a_given_date(self):
        assert render("{{add_days('2026-07-05', 3)}}", {}) == "2026-07-08"
        assert render("{{add_days('2026-07-05', -5)}}", {}) == "2026-06-30"

    def test_add_days_from_today_when_blank(self):
        import datetime as dt
        want = (dt.datetime.now(dt.timezone.utc).date() + dt.timedelta(days=2)).isoformat()
        assert render("{{add_days('', 2)}}", {}) == want

    def test_date_helpers_compose_with_ordering(self):
        # "is this due date within the next 3 days?" -- add_days + lexical compare
        d = {"due": "2026-07-05"}
        assert eval_condition("due <= '2026-07-08'", d) is True
        assert eval_condition("due <= '2026-07-04'", d) is False

    def test_bad_date_is_empty(self):
        assert render("{{add_days('not-a-date', 3)}}", {}) == ""


class TestOrderingComparisons:
    def test_iso_date_strings_order_lexically(self):
        # the footgun: a date compare used to force float() and silently be False
        assert eval_condition("created >= '2026-01-01'", {"created": "2026-07-05"}) is True
        assert eval_condition("created >= '2026-01-01'", {"created": "2025-12-31"}) is False
        assert eval_condition("created < '2026-01-01'", {"created": "2025-06-30"}) is True

    def test_plain_string_ordering(self):
        assert eval_condition("tier > 'a'", {"tier": "b"}) is True
        assert eval_condition("tier < 'a'", {"tier": "b"}) is False

    def test_numeric_ordering_stays_numeric_not_lexical(self):
        # 10 vs 9 must be numeric (10 > 9), not the string-wise '10' > '9' == False
        assert eval_condition("n > 9", {"n": 10}) is True
        assert eval_condition("n >= 100", {"n": 100}) is True

    def test_missing_key_is_never_ordered_true(self):
        assert eval_condition("ghost >= '2026-01-01'", {}) is False
        assert eval_condition("ghost > 5", {}) is False


class TestSecretFunction:
    def test_unsafe_regex_fails_flow_before_action(self):
        seen = []
        flow = Flow(id="f", name="f", start="a", nodes={
            "a": FlowNode(id="a", kind="action", tool="t",
                          params={"value": '{{regex(input, "a*a*b")}}'})
        })
        result = run_flow(flow, agent_fn=lambda *a: ("", None),
                          action_fn=lambda *a: seen.append(a), data={"input": "aaa"})
        assert result.status == "failed"
        assert "safe subset" in result.error
        assert not seen

    def test_legacy_allow_flag_never_grants_deployment_secret_access(self, monkeypatch):
        monkeypatch.setenv("STRIPE_KEY", "sk_test_123")
        assert render("{{secret('STRIPE_KEY')}}", {}) == "{{secret('STRIPE_KEY')}}"
        with pytest.raises(FlowCredentialRefused, match="Connections"):
            render("{{secret('STRIPE_KEY')}}", {}, allow_secrets=True)

    def test_missing_secret_also_requires_explicit_migration(self, monkeypatch):
        monkeypatch.delenv("NO_SUCH_SECRET", raising=False)
        with pytest.raises(FlowCredentialRefused, match="no credential or grant was migrated"):
            render("{{secret('NO_SUCH_SECRET')}}", {}, allow_secrets=True)

    def test_secret_in_action_params_refuses_before_any_executor(self, monkeypatch):
        monkeypatch.setenv("API_KEY", "s3kret-value")
        seen = {}

        def action(node, params, data):
            seen["params"] = params
            return ("ok", 1.0)
        f = Flow(id="f", name="f", start="a",
                 nodes={"a": FlowNode(id="a", kind="action", tool="t",
                                      params={"key": "{{secret('API_KEY')}}"}, output="r")})
        res = run_flow(f, agent_fn=lambda *a: ("", None), action_fn=action)
        assert res.status == "failed" and "Connections" in res.error
        assert seen == {}
        assert "s3kret-value" not in str(res)

    def test_secret_in_setvar_is_not_resolved_or_persisted(self, monkeypatch):
        monkeypatch.setenv("API_KEY", "s3kret-value")
        f = Flow(id="f", name="f", start="s",
                 nodes={"s": FlowNode(id="s", kind="setvar",
                                      assignments={"public": "{{secret('API_KEY')}}"})})
        res = run_flow(f, agent_fn=lambda *a: ("", None), action_fn=lambda *a: ("", None))
        assert res.data["public"] == "{{secret('API_KEY')}}"
        assert "s3kret-value" not in str(res.data)

    def test_secret_in_agent_brief_is_not_resolved(self, monkeypatch):
        monkeypatch.setenv("API_KEY", "s3kret-value")
        seen = {}

        def agent(node, brief, data):
            seen["brief"] = brief
            return ("ok", 1.0)
        f = Flow(id="f", name="f", start="a",
                 nodes={"a": FlowNode(id="a", kind="agent",
                                      brief="use {{secret('API_KEY')}}")})
        run_flow(f, agent_fn=agent, action_fn=lambda *a: ("", None))
        assert seen["brief"] == "use {{secret('API_KEY')}}"
        assert "s3kret-value" not in seen["brief"]


class TestExpressions:
    def test_case_and_trim_transforms(self):
        d = {"name": "  aDa  "}
        assert render("{{upper(name)}}", d) == "  ADA  "
        assert render("{{trim(name)}}", d) == "aDa"
        assert render("{{title('hello world')}}", {}) == "Hello World"

    def test_default_falls_back_on_missing_or_empty(self):
        assert render("{{default(missing, 'n/a')}}", {}) == "n/a"
        assert render("{{default(x, 'n/a')}}", {"x": "here"}) == "here"

    def test_concat_and_length_and_replace(self):
        assert render("{{concat(first, ' ', last)}}", {"first": "Ada", "last": "L"}) == "Ada L"
        assert render("{{length(items)}}", {"items": [1, 2, 3]}) == "3"
        assert render("{{replace(s, 'a', 'b')}}", {"s": "banana"}) == "bbnbnb"

    def test_missing_bare_key_stays_literal_but_present_renders(self):
        assert render("hi {{ghost}}", {}) == "hi {{ghost}}"
        assert render("hi {{name}}", {"name": "Ada"}) == "hi Ada"

    def test_bool_renders_lowercase(self):
        assert render("{{flag}}", {"flag": True}) == "true"

    def test_unknown_function_is_treated_as_a_key(self):
        assert render("{{bogus(x)}}", {}) == "{{bogus(x)}}"   # not a known fn, no such key

    def test_nested_function_calls_evaluate(self):
        # a nested call's inner comma must not split the outer args, and the
        # inner call must actually evaluate (not silently render "")
        assert render("{{upper(default(x, 'fallback'))}}", {}) == "FALLBACK"
        assert render("{{upper(default(x, 'fallback'))}}", {"x": "here"}) == "HERE"
        assert render("{{concat(upper(first), ' ', lower(last))}}",
                      {"first": "ada", "last": "LOVELACE"}) == "ADA lovelace"

    def test_literal_comma_inside_nested_call_survives(self):
        assert render("{{default(missing, concat('a', 'b'))}}", {}) == "ab"

    def test_unclosed_placeholders_render_linearly(self):
        text = "{{" * 20000
        assert render(text, {"name": "Ada"}) == text

    def test_unclosed_placeholder_preserves_remainder(self):
        assert render("hi {{name}} then {{", {"name": "Ada"}) == "hi Ada then {{"


class TestLoopControls:
    def _counting_agent(self):
        calls = []

        def ag(node, brief, data):
            calls.append(brief)
            return ("x", 1.0)
        return ag, calls

    def test_foreach_limit_caps_iterations(self):
        body = Flow(id="b", name="b", start="s",
                    nodes={"s": FlowNode(id="s", kind="agent", brief="do {{item}}")})
        f = Flow(id="f", name="f", start="a", nodes={
            "a": FlowNode(id="a", kind="foreach", items="rows", var="item", limit=2, body=body)})
        ag, calls = self._counting_agent()
        run_flow(f, agent_fn=ag, action_fn=lambda *a: ("", None), data={"rows": [1, 2, 3, 4]})
        assert calls == ["do 1", "do 2"]

    def test_foreach_break_stops_early(self):
        body = Flow(id="b", name="b", start="s",
                    nodes={"s": FlowNode(id="s", kind="action", tool="t")})
        f = Flow(id="f", name="f", start="a", nodes={
            "a": FlowNode(id="a", kind="foreach", items="rows", var="item", body=body)})
        seen = []

        def action(node, params, data):
            seen.append(data.get("item"))
            if data.get("item") == 2:
                data["_break"] = True          # ask the loop to stop after this item
            return ("ok", 1.0)
        run_flow(f, agent_fn=lambda *a: ("", None), action_fn=action, data={"rows": [1, 2, 3, 4]})
        assert seen == [1, 2]                   # stopped after the break, not all 4
