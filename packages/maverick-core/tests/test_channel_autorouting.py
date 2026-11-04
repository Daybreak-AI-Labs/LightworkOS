"""Channel auto-routing: rule matching, passthrough default, classifier, explain."""
from __future__ import annotations

from maverick.channel_autorouting import (
    MessageSignals,
    RouteRule,
    explain,
    parse_rules,
    route,
)


def test_passthrough_when_no_rules():
    d = route(MessageSignals(text="hi"), rules=[], inbound_channel="sms")
    assert d.passthrough is True
    assert d.channel == "sms"
    assert d.rule == "passthrough"


def test_passthrough_marker_when_no_inbound():
    d = route(MessageSignals(text="hi"), rules=[])
    assert d.channel == "passthrough" and d.passthrough is True


def test_first_matching_rule_wins():
    rules = [
        RouteRule(channel="email", min_length=100, name="long"),
        RouteRule(channel="sms", name="catchall"),
    ]
    long_msg = MessageSignals(text="x" * 150)
    assert route(long_msg, rules=rules).channel == "email"
    short_msg = MessageSignals(text="hi")
    d = route(short_msg, rules=rules)
    assert d.channel == "sms" and d.rule == "catchall"


def test_length_bounds_inclusive():
    rules = [RouteRule(channel="mid", min_length=10, max_length=20, name="mid")]
    assert route(MessageSignals(text="x" * 10), rules=rules).channel == "mid"
    assert route(MessageSignals(text="x" * 20), rules=rules).channel == "mid"
    # length 9 and 21 fall through to passthrough
    assert route(MessageSignals(text="x" * 9), rules=rules).passthrough
    assert route(MessageSignals(text="x" * 21), rules=rules).passthrough


def test_urgency_inferred_from_keywords():
    sig = MessageSignals(text="the prod database is DOWN right now")
    assert sig.effective_urgency() == "critical"
    rules = [RouteRule(channel="pager", urgency="high", name="urgent")]
    assert route(sig, rules=rules).channel == "pager"  # critical >= high


def test_explicit_urgency_overrides_text():
    sig = MessageSignals(text="no scary words", urgency="critical")
    assert sig.effective_urgency() == "critical"


def test_language_match():
    rules = [RouteRule(channel="es-desk", languages=("es",), name="spanish")]
    assert route(MessageSignals(text="hola", language="es"), rules=rules).channel == "es-desk"
    assert route(MessageSignals(text="hi", language="en"), rules=rules).passthrough


def test_attachment_and_keyword():
    rules = [
        RouteRule(channel="ticket", attachments=("log",), name="haslog"),
        RouteRule(channel="legal", any_keyword=("subpoena",), name="legal"),
    ]
    assert route(MessageSignals(text="see trace", attachments=("log",)),
                 rules=rules).channel == "ticket"
    assert route(MessageSignals(text="a SUBPOENA arrived"), rules=rules).channel == "legal"


def test_injected_classifier_sets_label():
    rules = [RouteRule(channel="sales", label="lead", name="lead")]
    sig = MessageSignals(text="interested in pricing")
    # no label -> passthrough
    assert route(sig, rules=rules).passthrough
    # classifier supplies the label -> routes
    d = route(sig, rules=rules, classifier=lambda s: "lead")
    assert d.channel == "sales" and d.rule == "lead"


def test_classifier_failure_is_ignored():
    def boom(_):
        raise RuntimeError("model down")

    rules = [RouteRule(channel="x", name="c")]
    # a broken classifier must not crash routing; rule still matches (catch-all)
    assert route(MessageSignals(text="hi"), rules=rules, classifier=boom).channel == "x"


def test_parse_rules_skips_channelless_and_bad_urgency():
    rules = parse_rules([
        {"channel": "a", "urgency": "bogus", "min_length": "nope"},
        {"no_channel": "skip"},
        {"channel": "b", "languages": "EN", "attachments": ["LOG", "pdf"]},
    ])
    assert [r.channel for r in rules] == ["a", "b"]
    assert rules[0].urgency == ""          # bogus dropped
    assert rules[0].min_length is None     # non-int dropped
    assert rules[1].languages == ("en",)   # normalised + coerced to tuple
    assert rules[1].attachments == ("log", "pdf")


def test_explain_mentions_rule_and_signals():
    rules = [RouteRule(channel="email", min_length=5, name="long")]
    text = explain(MessageSignals(text="hello world"), rules=rules)
    assert "email" in text and "long" in text and "length=11" in text


def test_explain_passthrough():
    text = explain(MessageSignals(text="hi"), rules=[], inbound_channel="sms")
    assert "passthrough" in text and "sms" in text
