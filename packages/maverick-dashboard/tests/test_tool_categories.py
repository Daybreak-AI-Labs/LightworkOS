"""The flow designer's coarse tool classifier: keyword buckets, first-match-wins,
honest OTHER catch-all."""
from __future__ import annotations

from maverick_dashboard.tool_categories import OTHER, categories, categorize


def test_known_connectors_land_in_expected_buckets():
    assert categorize("slack_bot", "post to a Slack channel") == "Communication"
    assert categorize("gmail", "read Gmail messages") == "Communication"
    assert categorize("github_issues", "list GitHub issues") == "Dev & Code"
    assert categorize("stripe", "Stripe payments REST") == "Finance & Payments"
    assert categorize("salesforce", "Salesforce CRM REST") == "CRM & Sales"
    assert categorize("zendesk", "Zendesk support tickets") == "Support & Ticketing"
    assert categorize("notion", "Notion pages") == "Productivity"


def test_unmatched_tool_is_other_not_a_wrong_label():
    assert categorize("zzz_unknownvendor", "a bespoke internal REST api") == OTHER


def test_first_match_wins_by_rule_order():
    # A description that could touch two buckets resolves to the earlier rule.
    # "communication" is checked before "support", so a chat-support tool is comms.
    assert categorize("chatdesk", "team chat + support") == "Communication"


def test_categorize_is_case_insensitive_and_null_safe():
    assert categorize("SLACK", "POST TO SLACK") == "Communication"
    assert categorize("", "") == OTHER
    assert categorize(None, None) == OTHER  # type: ignore[arg-type]


def test_categories_are_ordered_with_other_last():
    cats = categories()
    assert cats[0] == "Communication"
    assert cats[-1] == OTHER
    assert len(cats) == len(set(cats))  # no duplicates
