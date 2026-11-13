"""Explicit product copy for reviewed journey wiring; never translate user data.

The four non-English catalogs are draft translations pending native-language
and consequence-copy review. Arabic remains the community seed, unchanged.
"""
from __future__ import annotations

import functools
import hashlib
import json
import re
from string import Formatter

from markupsafe import Markup, escape

from .i18n_flow_credentials import ROWS as FLOW_CREDENTIAL_ROWS
from .i18n_journey_ai_trust import ROWS as AI_TRUST_ROWS
from .i18n_journey_budget import ROWS as BUDGET_ROWS
from .i18n_journey_chat_review import ROWS as CHAT_REVIEW_ROWS
from .i18n_journey_common import ROWS as COMMON_ROWS
from .i18n_journey_composer_files import ROWS as COMPOSER_FILE_ROWS
from .i18n_journey_connections import ROWS as CONNECTION_ROWS
from .i18n_journey_conversation import ROWS as CONVERSATION_ROWS
from .i18n_journey_coverage_gaps import ROWS as COVERAGE_GAP_ROWS
from .i18n_journey_employee import ROWS as EMPLOYEE_ROWS
from .i18n_journey_finder import ROWS as FINDER_ROWS
from .i18n_journey_live_chat import ROWS as LIVE_CHAT_ROWS
from .i18n_journey_next_steps import ROWS as NEXT_STEP_ROWS
from .i18n_journey_preferences import ROWS as PREFERENCE_ROWS
from .i18n_journey_receipts import ROWS as RECEIPT_ROWS
from .i18n_journey_recovery_controls import ROWS as RECOVERY_CONTROL_ROWS
from .i18n_journey_recovery_states import ROWS as RECOVERY_STATE_ROWS
from .i18n_journey_resume import ROWS as RESUME_ROWS
from .i18n_journey_review import ROWS as REVIEW_ROWS
from .i18n_journey_shell import ROWS as SHELL_ROWS
from .i18n_journey_task_controls import ROWS as TASK_CONTROL_ROWS
from .i18n_journey_voice_controls import ROWS as VOICE_CONTROL_ROWS
from .i18n_journey_workflow import ROWS as WORKFLOW_ROWS

ROWS = [*FLOW_CREDENTIAL_ROWS, *BUDGET_ROWS, *COMMON_ROWS, *EMPLOYEE_ROWS, *REVIEW_ROWS, *WORKFLOW_ROWS, *CONVERSATION_ROWS,
        *RECEIPT_ROWS, *RECOVERY_CONTROL_ROWS, *RESUME_ROWS, *SHELL_ROWS, *TASK_CONTROL_ROWS,
        *LIVE_CHAT_ROWS, *PREFERENCE_ROWS, *VOICE_CONTROL_ROWS, *COMPOSER_FILE_ROWS, *CONNECTION_ROWS,
        *FINDER_ROWS, *AI_TRUST_ROWS, *NEXT_STEP_ROWS, *COVERAGE_GAP_ROWS, *CHAT_REVIEW_ROWS, *RECOVERY_STATE_ROWS]

TRANSLATION_LANGS = ("fr", "de", "ja", "zh")
# Rows are source, French, German, Japanese, Chinese. No Arabic machine completion.


@functools.lru_cache(maxsize=8192)
def key(source):
    return "journey." + hashlib.sha256(source.encode("utf-8")).hexdigest()[:20]


def messages():
    """One row per source: the first table in ``ROWS`` order wins.

    A source repeated in a later table must carry the same translations (a
    test pins that), so the order decides nothing a reader can see.
    """
    result = {}
    for row in ROWS:
        source, *translations = row
        if len(translations) != len(TRANSLATION_LANGS):
            raise ValueError("Journey translations require all four draft languages")
        expected = {name for _, name, _, _ in Formatter().parse(source) if name}
        for text in translations:
            if (not text.strip() or {name for _, name, _, _ in Formatter().parse(text) if name} != expected
                    or set(re.findall(r"\{\{[a-z_]+\}\}", text)) != set(re.findall(r"\{\{[a-z_]+\}\}", source))):
                raise ValueError("Journey catalog placeholders differ")
        result.setdefault(key(source), {"en": source, **dict(zip(TRANSLATION_LANGS, translations, strict=True))})
    return result


def entry(source, lang):
    from .i18n import MESSAGES
    row = MESSAGES.get(key(source), {"en": source})
    actual = lang if row.get(lang) else "en"
    return row[actual], actual


def text(source, lang="en", /, **values):
    value, _ = entry(source, lang)
    return value.format_map(values) if values else value


def region(source, lang="en", /, **values):
    """A product-copy region, with caller-supplied content escaped and isolated."""
    if not values and type(source) is str:  # a Markup equals its text: never share one's escaping
        return _plain_region(source, lang)
    value, actual = entry(source, lang)
    safe = escape(value).format_map({name: Markup('<bdi lang="und" dir="auto">{}</bdi>').format(escape(str(value))) for name, value in values.items()})
    return Markup('<span lang="{}" dir="{}" data-product-copy>{}</span>').format(actual, "rtl" if actual == "ar" else "ltr", safe)


@functools.lru_cache(maxsize=8192)
def _plain_region(source, lang):
    # A page renders about 200 of these; without values one depends only on
    # the fixed catalog, the text and the language.
    value, actual = entry(source, lang)
    return Markup('<span lang="{}" dir="{}" data-product-copy>{}</span>').format(actual, "rtl" if actual == "ar" else "ltr", escape(value))


def accepted_locales(request):
    """Honor browser quality values; malformed and explicitly rejected tags lose."""
    choices = []
    for position, part in enumerate(request.headers.get("Accept-Language", "").split(",")):
        tag, *options = part.strip().split(";")
        if not re.fullmatch(r"[A-Za-z]{2}(?:-[A-Za-z]{4})?(?:-(?:[A-Za-z]{2}|[0-9]{3}))?", tag):
            continue
        try:
            quality = float(next((option.strip()[2:] for option in options if option.strip().startswith("q=")), "1"))
        except ValueError:
            continue
        if 0 < quality <= 1:
            choices.append((-quality, position, tag))
    return [tag for _, _, tag in sorted(choices)]


def locale_for(request, lang):
    """Retain a valid regional formatting preference without inventing translation."""
    from .auth import caller_principal
    candidates = ([] if caller_principal(request) else [request.query_params.get("lang", "")]) + accepted_locales(request)
    for candidate in candidates:
        if re.fullmatch(r"[A-Za-z]{2}(?:-[A-Za-z]{4})?(?:-(?:[A-Za-z]{2}|[0-9]{3}))?", candidate or "") and candidate.lower().split("-")[0] == lang:
            return candidate
    return lang


def browser_catalog(lang):
    """Public product strings only; no request, account, or regional state."""
    from .i18n import MESSAGES
    catalog = {}
    for source, *_ in ROWS:
        value, actual = entry(source, lang)
        catalog[source] = {"text": value, "lang": actual}
    # Existing community-reviewed chrome remains available to explicitly wired
    # controls, but missing Arabic journey copy always retains English regions.
    for row in MESSAGES.values():
        if row.get("en") not in catalog:
            actual = lang if row.get(lang) else "en"
            catalog[row["en"]] = {"text": row.get(actual, row["en"]), "lang": actual}
    return catalog


def browser_catalog_asset(lang):
    """Content-address the complete catalog so HTML need not repeat it."""
    payload = {"language": lang, "catalog": browser_catalog(lang)}
    encoded = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    content = ("window.LightworkJourneyCatalog=" + encoded + ";\n").encode("utf-8")
    return hashlib.sha256(content).hexdigest(), content


def context(request, lang):
    metadata = {"language": lang, "locale": locale_for(request, lang),
                "review_status": "source" if lang == "en" else "community_seed" if lang == "ar" else "draft_partial"}
    # English is the source language and its catalog is identity (the
    # runtime's fallback), so English pages skip the blocking download.
    asset = "" if lang == "en" else f"/static/lightwork-i18n-catalog/{lang}/{browser_catalog_asset(lang)[0]}.js"
    return {"ui": lambda source, /, **values: region(source, lang, **values),
            "ut": lambda source, /, **values: text(source, lang, **values),
            "ul": lambda source: entry(source, lang)[1],
            "journey_i18n": metadata,
            "journey_i18n_bootstrap": metadata,
            "journey_i18n_asset": asset}
