"""People, agents and specialists, waiting approvals and help for Ctrl+K.

Each kind comes from its own page's permission check, on every request, for
this person only: people only for those who may open the Users page, agents
and specialists within their departments, approvals they may read and decide,
and the help topics the Help page shows everyone. Nothing is cached or shared
between people, and a source someone may not use adds nothing.
"""
from __future__ import annotations

from urllib.parse import quote, urlencode

PER_KIND = 5


def _rank(labels: list[str], haystack: str, terms: list[str]) -> int | None:
    """0 = a name is exactly the words, 1 = a name starts with them, 2 = the
    words start words of a name, 3 = the words appear anywhere; None = no match."""
    if not all(term in haystack for term in terms):
        return None
    phrase = " ".join(terms)
    best = 3
    for label in labels:
        name = label.casefold()
        words = name.split()
        if name == phrase:
            return 0
        if name.startswith(phrase):
            best = min(best, 1)
        elif all(any(word.startswith(term) for word in words) for term in terms):
            best = min(best, 2)
    return best


def _best(rows: list[tuple[int, dict]]) -> list[dict]:
    return [row for _rank_value, row in sorted(rows, key=lambda pair: (pair[0], pair[1]["title"].casefold()))][:PER_KIND]


def people(request, terms, can_open_page) -> list[dict]:
    from .navigation_api import people_available
    if not people_available(request):
        return []
    from .admin_pages import _users_context
    from .identity_format import role_label

    found = []
    for person in _users_context(request)["people"]:
        label = str(person["label"])
        rank = _rank([label], label.casefold(), terms)
        if rank is not None:
            found.append((rank, {"kind": "person", "title": label, "labels": [label],
                                 "context": role_label(person["role"]) if person.get("role") else "",
                                 "href": "/users?" + urlencode({"q": label}) + "#people"}))
    return _best(found)


def agents(request, terms, can_open_page) -> list[dict]:
    if not can_open_page("/agents"):
        return []
    from maverick.domain import available_domains, suites_for_domain

    from .agent_changelog import agent_kind
    from .auth import caller_suites
    from .identity_format import humanize

    allowed = caller_suites(request)
    found = []
    # The parsed pack catalogue is cached for the process (domain.builtin_domains);
    # workspace packs are read live. Readiness, which the /agents roster
    # recomputes per pack, is not needed to find a name.
    for pack, profile in available_domains().items():
        description = str(profile.description or "")
        # Two thousand packs: words the pack cannot hold skip the naming work.
        if not all(term in f"{pack} {humanize(pack)} {description} agent specialist".casefold() for term in terms):
            continue
        if allowed is not None and not set(suites_for_domain(pack, profile)) <= allowed:
            continue
        kind = agent_kind(pack)
        # "Trade Finance: Prepare letter-of-credit..." is known as "Trade Finance".
        known, _, _rest = description.partition(":")
        title = known.strip() if _rest and 0 < len(known.strip()) <= 60 else humanize(pack)
        names = list(dict.fromkeys([title, humanize(pack)]))
        labels = [*names, *(f"{name} {kind}" for name in names)]
        rank = _rank(labels, f"{' '.join(labels)} {description} {pack}".casefold(), terms)
        # Two thousand packs: a word met only in a description is noise here.
        if rank is not None and rank <= 2:
            found.append((rank, {"kind": kind, "title": title, "labels": labels,
                                 "context": description, "href": "/agents?name=" + quote(pack, safe="")}))
    return _best(found)


def approvals(request, terms, can_open_page) -> list[dict]:
    from . import auth
    if not auth.has_permission(request, "operate") or not can_open_page("/approvals"):
        return []
    from ._shared import _world
    from .approval_labels import action_label
    from .content_access import can_read_approval
    from .identity_format import humanize

    world = _world()
    found = []
    for approval in world.pending_approvals():
        if not can_read_approval(request, approval, world):
            continue
        title = action_label(approval.action)
        risk = humanize(getattr(approval, "risk", "") or "")
        rank = _rank([title], f"{title} {approval.action} {risk} approval".casefold(), terms)
        if rank is not None:
            found.append((rank, {"kind": "approval", "title": title, "labels": [title],
                                 "context": (risk + " risk" if risk else "Waiting for a decision"),
                                 "href": "/approvals#approval-" + quote(str(approval.id), safe="")}))
    return _best(found)


def help_topics(request, terms, can_open_page) -> list[dict]:
    if not can_open_page("/help"):
        return []
    from .help_topics import TOPICS

    found = []
    for topic in TOPICS:
        rank = _rank([topic.title], " ".join((topic.title, *topic.steps)).casefold(), terms)
        if rank is not None:
            found.append((rank, {"kind": "help", "title": topic.title, "labels": [topic.title],
                                 "context": topic.persona, "href": "/help#how-" + topic.slug}))
    return _best(found)


SOURCES = (people, agents, approvals, help_topics)


# Question words carry no meaning for matching: "how do I invite" is "invite".
_FILLER = frozenset({"how", "do", "does", "i", "can", "to", "a", "an", "the", "my", "where", "is", "what", "who"})


def find(request, query: str, can_open_page) -> list[dict]:
    terms = query.casefold().replace("?", " ").split()[:8]
    terms = [term for term in terms if term not in _FILLER] or terms
    if len("".join(terms)) < 2:
        return []
    results = []
    for source in SOURCES:
        try:
            results.extend(source(request, terms, can_open_page))
        except Exception:  # a closed or unreadable source adds nothing  # noqa: BLE001
            continue
    return results
