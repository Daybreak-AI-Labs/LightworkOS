"""Explicit dashboard product-copy catalogs, with honest partial-language regions.

The original chrome catalog and draft journey catalogs share the community
translation validation tooling. User content is never submitted for translation.
Interface language is independent of response language; regional browser tags
control date and number formatting. No draft catalog qualifies a full page body.
"""
from __future__ import annotations

from .i18n_journeys import messages as _journey_messages

LANGS = ("en", "fr", "de", "ja", "zh", "ar")
DEFAULT_LANG = "en"

# Community-seed catalogs: genuinely translated but intentionally partial.
# ``t()`` falls back to English for unseeded keys, and the catalog
# completeness test requires full coverage only for non-seed languages.
# Do NOT machine-translate these to completion — they grow by contribution.
SEED_LANGS = ("ar",)

# Right-to-left scripts. ``ar`` is the only one with a (seed) catalog today;
# the rest are listed so the ``dir`` attribute flips correctly the moment a
# catalog for them lands.
RTL_LANGS = frozenset({"ar", "he", "fa", "ur"})

#: Languages the page BODY is actually rendered in. The templates' copy is
#: English; only explicitly bound chrome and journey product regions follow
#: the selected language. ``<html lang>`` must describe the body (WCAG 3.1.1),
#: so it uses :func:`content_lang`, and the translated chrome elements carry
#: their own ``lang`` attribute. Add a language here once its templates exist.
CONTENT_LANGS = frozenset({"en"})


def content_lang(lang: str) -> str:
    """The language to declare on ``<html>``: the selected language only when
    the page body is translated into it, else English (the body's language).
    Assistive tech picks voice and pronunciation rules from this attribute;
    declaring ``de`` over an English page reads it with the wrong engine."""
    return lang if lang in CONTENT_LANGS else DEFAULT_LANG


def dir_for(lang: str) -> str:
    """Text direction for a language code: ``rtl`` or ``ltr``."""
    return "rtl" if (lang or "").split("-")[0].strip().lower() in RTL_LANGS else "ltr"

# key -> {lang: text}. English is the reference set; the catalog test asserts
# every non-seed language covers every key (seed langs fall back to English).
# The "ar" entries below are the community-seed example: a handful of
# genuinely translated keys, not a machine-translated catalog.
MESSAGES: dict[str, dict[str, str]] = {
    "nav.goals":      {"en": "Goals", "fr": "Objectifs", "de": "Ziele", "ja": "ゴール", "zh": "目标", "ar": "الأهداف"},
    "nav.chat":       {"en": "Chat", "fr": "Discussion", "de": "Chat", "ja": "チャット", "zh": "聊天", "ar": "الدردشة"},
    "nav.approvals":  {"en": "Approvals", "fr": "Approbations", "de": "Freigaben", "ja": "承認", "zh": "审批", "ar": "الموافقات"},
    "nav.oversight":  {"en": "Oversight", "fr": "Supervision", "de": "Aufsicht", "ja": "監督", "zh": "监管"},
    "nav.cost":       {"en": "Cost", "fr": "Coûts", "de": "Kosten", "ja": "コスト", "zh": "成本"},
    "nav.audit":      {"en": "Audit", "fr": "Audit", "de": "Audit", "ja": "監査", "zh": "审计"},
    "nav.channels":   {"en": "Channels", "fr": "Canaux", "de": "Kanäle", "ja": "チャネル", "zh": "渠道"},
    "label.status":   {"en": "Status", "fr": "Statut", "de": "Status", "ja": "状態", "zh": "状态", "ar": "الحالة"},
    "label.created":  {"en": "Created", "fr": "Créé", "de": "Erstellt", "ja": "作成日時", "zh": "创建时间"},
    "label.owner":    {"en": "Owner", "fr": "Propriétaire", "de": "Eigentümer", "ja": "所有者", "zh": "所有者"},
    "label.theme":    {"en": "Theme", "fr": "Thème", "de": "Design", "ja": "テーマ", "zh": "主题"},
    "label.font":     {"en": "Font", "fr": "Police", "de": "Schrift", "ja": "フォント", "zh": "字体"},
    "label.language": {"en": "Language", "fr": "Langue", "de": "Sprache", "ja": "言語", "zh": "语言", "ar": "اللغة"},
    "action.start":   {"en": "Start", "fr": "Démarrer", "de": "Starten", "ja": "開始", "zh": "开始"},
    "action.cancel":  {"en": "Cancel", "fr": "Annuler", "de": "Abbrechen", "ja": "キャンセル", "zh": "取消", "ar": "إلغاء"},
    "action.approve": {"en": "Approve", "fr": "Approuver", "de": "Genehmigen", "ja": "承認する", "zh": "批准", "ar": "موافقة"},
    "action.deny":    {"en": "Deny", "fr": "Refuser", "de": "Ablehnen", "ja": "却下する", "zh": "拒绝", "ar": "رفض"},
    "action.search":  {"en": "Search", "fr": "Rechercher", "de": "Suchen", "ja": "検索", "zh": "搜索", "ar": "بحث"},
    "footer.local":   {"en": "self-hosted", "fr": "auto-hébergé", "de": "selbst gehostet", "ja": "セルフホスト", "zh": "自托管"},
    "chrome.skip_to_content": {"en": "Skip to content", "fr": "Aller au contenu", "de": "Zum Inhalt springen", "ja": "コンテンツへスキップ", "zh": "跳到内容", "ar": "تخطي إلى المحتوى"},
    "chrome.account": {"en": "Your account", "fr": "Votre compte", "de": "Ihr Konto", "ja": "アカウント", "zh": "您的账户", "ar": "حسابك"},
    "chrome.sign_out": {"en": "Sign out", "fr": "Se déconnecter", "de": "Abmelden", "ja": "サインアウト", "zh": "退出登录", "ar": "تسجيل الخروج"},
    "font.default":   {"en": "Default", "fr": "Par défaut", "de": "Standard", "ja": "標準", "zh": "默认"},
    "font.dyslexic":  {"en": "Dyslexia-friendly", "fr": "Adaptée à la dyslexie", "de": "Legasthenie-freundlich", "ja": "ディスレクシア対応", "zh": "阅读障碍友好"},
}



MESSAGES.update(_journey_messages())

# Browser language detection is an implicit choice. It may select only a
# catalog with a translation for every registered product string. Community
# seeds remain available through explicit selection and saved preferences.
AUTO_LANGS = frozenset(
    lang for lang in LANGS
    if lang not in SEED_LANGS and all(entry.get(lang) for entry in MESSAGES.values())
)


def resolve_lang(request) -> str:
    """Explicit language → saved preference → complete browser catalog → en."""
    q = (request.query_params.get("lang") or "").strip().lower().split("-")[0]
    from .auth import caller_principal

    if q in LANGS and not caller_principal(request):
        return q
    from .preferences_api import resolved_display

    preferred = resolved_display(request, "interface_language") or resolved_display(request, "language")
    if preferred in LANGS:
        return preferred
    from .i18n_journeys import accepted_locales
    for locale in accepted_locales(request):
        code = locale.lower().split("-")[0]
        if code in AUTO_LANGS:
            return code
    return DEFAULT_LANG


def t(key: str, lang: str = DEFAULT_LANG) -> str:
    """Translate a chrome string; fall back en → key (never blank)."""
    entry = MESSAGES.get(key)
    if not entry:
        return key
    return entry.get(lang) or entry.get(DEFAULT_LANG) or key


__all__ = [
    "LANGS", "DEFAULT_LANG", "SEED_LANGS", "RTL_LANGS", "CONTENT_LANGS", "AUTO_LANGS", "MESSAGES",
    "content_lang", "dir_for", "resolve_lang", "t",
]
