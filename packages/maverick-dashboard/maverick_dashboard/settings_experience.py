"""Reviewed configuration portability and history over the existing catalog writer."""
from __future__ import annotations

from collections import deque
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import quote

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from . import auth, settings_store, ui_visibility
from . import settings_all_page as page
from . import settings_catalog as catalog

router = APIRouter()
HEADERS = {"Cache-Control": "private, no-store"}
# Explicit portability boundary: no arbitrary URLs, paths, policy documents,
# credentials, access grants, identifiers, or deployment data leave the server.
PORTABLE = frozenset({
    "persona.style", "persona.name", "persona.addendum",
    "dashboard.theme", "dashboard.density", "dashboard.glass",
    "budget.max_wall_seconds", "budget.max_tool_calls", "budget.max_output_tokens",
    "models.vision", "speculative.draft_model", "verification.cross_family_model",
})
PRESETS = {
    "bounded-research": {
        "label": "Bounded research", "tradeoff": "Limit each task to 10 minutes and 30 actions. Long research may stop earlier; this does not estimate provider prices.",
        "changes": [{"id": "budget.max_wall_seconds", "value": 600}, {"id": "budget.max_tool_calls", "value": 30}],
    },
    "assurance-review": {
        "label": "High-assurance review", "tradeoff": "Apply the existing regulated governance profile. Additional review and evidence collection can increase latency and cost. Every expanded change is shown before confirmation.",
        "changes": [{"id": "governance.profile", "value": "regulated"}],
    },
}


def _allowed(request: Request, *, feature: bool = False):
    auth.require_global_permission(request, "admin")
    if feature:
        from maverick.config import get_features, load_global_config
        if load_global_config().get("features", {}).get("configuration_profiles", True) is not True or not get_features().get("configuration_profiles"):
            raise HTTPException(403, "Configuration profiles are turned off in Settings.")


def _can_export(setting) -> bool:
    return (setting.id in PORTABLE and not setting.secret and not page._secret_columns(setting)
            and setting.control in {"text", "number", "toggle", "select", "list", "multiselect"})


def _impact(setting):
    from .settings_runtime_status import impact
    return impact(setting)


def _present_value(setting, value):
    # Keep immutable identities in accepted audit evidence; name them only in
    # the customer projection, without contacting Docker during history reads.
    if setting.section == "features" or setting.id == "plugins.workbench_image" or (
        setting.control == "number" and not catalog.valid_number(setting, value)
    ):
        return catalog.display_value(setting, value)
    return page._audit_value(setting, value)


@router.post('/api/v1/settings/catalog/review')
def review(request: Request, body: page.CatalogUpdate):
    page._app()._require_same_origin(request)
    _allowed(request)
    from . import settings_access_guard, settings_governance_level

    with settings_store._locked(strict=True):
        current = page._revision()
        if body.expected_revision != current:
            # A review never calls a mutation handler, even if an external file
            # source changes again while the conflict projection is assembled.
            state = page.catalog_state()
            asked = {item.id for item in body.changes}
            conflicts = [{"id": row["id"], "label": row["label"],
                          "current": row["value_text"], "source": row["source_text"]}
                         for group in state["groups"] for row in group["settings"]
                         if row["id"] in asked]
            return JSONResponse({"message": "Settings changed. Your draft is kept.",
                                 "conflicts": conflicts, "revision": state['revision']},
                                status_code=409, headers=HEADERS)
        try:
            expanded, learning = settings_governance_level.expand(body, page.SettingChange)
            writes, changes, warnings, layers = page._plan(expanded)
            warnings += page._guard(request, writes, changes, layers) if changes else []
            warnings += settings_governance_level.confirm_items(learning)
        except (page._Refused, settings_access_guard.Refused, settings_governance_level.Unavailable) as exc:
            raise HTTPException(getattr(exc, "status", 409), str(exc)) from exc
        items = []
        for change in changes:
            setting = change['setting']
            requested = next((item for item in body.changes if item.id == setting.id), None)
            inherited = {**layers, 'here': {}}
            resulting_source = (page._resolve(setting, inherited)['source']
                                if requested and requested.inherit else 'dashboard setting')
            items.append({
                'id': setting.id, 'label': setting.label,
                'before': _present_value(setting, change['old']),
                'after': _present_value(setting, change['new']),
                'source': page._resolve(setting, layers)['source'], 'resulting_source': resulting_source,
                'scope': 'Organization / installation', 'restart': setting.restart,
                'affected': 'Authorized workspaces inheriting this organization setting',
                'module': setting.group, 'area': setting.group,
                'automatic': requested is None,
                **_impact(setting),
            })
        return JSONResponse({'items': items, 'warnings': warnings, 'revision': current,
                             'learning': [spec['label'] for spec in learning]}, headers=HEADERS)


class ExportSelection(BaseModel):
    ids: list[str] = Field(default_factory=list, max_length=100)


@router.post('/api/v1/settings/profiles/export')
def export_profile(request: Request, body: ExportSelection):
    page._app()._require_same_origin(request)
    _allowed(request, feature=True)
    with settings_store._locked(strict=True):
        layers = page._sources()
        picked = body.ids or sorted(PORTABLE & catalog.BY_ID.keys())
        settings, excluded = {}, []
        for key in picked:
            setting = catalog.BY_ID.get(key)
            if setting is None or not _can_export(setting):
                excluded.append(key)
                continue
            resolved = page._resolve(setting, layers)
            if not resolved['known']:
                excluded.append(key)
                continue
            from .draft_store import validate_payload
            value = page._form_value(setting, resolved['value'])
            try:
                validate_payload({key: value})
            except ValueError:
                excluded.append(key)
            else:
                settings[key] = value
        return JSONResponse({'format': 'lightwork-preferences-profile', 'version': 1,
                             'scope': 'organization', 'settings': settings,
                             'excluded': excluded, 'credentials': 'Not exported. Configure provider credentials separately.'}, headers=HEADERS)


class ImportedProfile(BaseModel):
    profile: dict[str, Any]


@router.post('/api/v1/settings/profiles/import')
def import_profile(request: Request, body: ImportedProfile):
    page._app()._require_same_origin(request)
    _allowed(request, feature=True)
    data = body.profile
    if data.get('format') != 'lightwork-preferences-profile' or data.get('version') != 1:
        raise HTTPException(422, 'Use a Lightwork preferences profile, version 1. Re-export older profiles from their original installation; no settings were applied.')
    if data.get('scope') != 'organization' or not isinstance(data.get('settings'), dict) or len(data['settings']) > 100:
        raise HTTPException(422, 'This profile must contain up to 100 organization preferences.')
    unsupported = [key for key in data['settings'] if key not in catalog.BY_ID or not _can_export(catalog.BY_ID[key])]
    if unsupported:
        raise HTTPException(422, 'Unsupported or non-portable fields: ' + ', '.join(unsupported[:12]) + '. Remove these fields and configure them through their current Settings controls; no fields were imported.')
    changes = [{'id': key, 'value': value} for key, value in data['settings'].items()]
    from .draft_store import validate_payload
    try:
        validate_payload(data['settings'])
    except ValueError as exc:
        raise HTTPException(422, 'This profile contains credential-like data. Remove it and configure credentials separately.') from exc
    with settings_store._locked(strict=True):
        revision = page._revision()
        # Use the ordinary coercion, dependency and authority review before an
        # import is even offered as a proposed change. Nothing is written here.
        preview = review(request, page.CatalogUpdate(changes=changes, expected_revision=revision))
        if preview.status_code != 200:
            return preview
        return JSONResponse({'changes': changes, 'revision': revision, 'scope': 'organization',
                             'message': 'Loaded for review. Nothing has been saved.'}, headers=HEADERS)


@router.get('/api/v1/settings/presets')
def presets(request: Request):
    _allowed(request, feature=True)
    from . import settings_governance_level
    with settings_store._locked(strict=True):
        layers = page._sources()
        results = []
        for key, preset in PRESETS.items():
            body = page.CatalogUpdate(changes=preset['changes'], expected_revision=page._revision(layers))
            try:
                expanded, _ = settings_governance_level.expand(body, page.SettingChange)
                drift = [item.id for item in expanded.changes if page._effective(catalog.BY_ID[item.id], layers) != catalog.coerce(page._resolved(catalog.BY_ID[item.id], page._effective(catalog.BY_ID[item.id], layers)), item.value)]
                results.append({'id': key, **preset, 'drift': drift, 'available': True})
            except (settings_governance_level.Unavailable, catalog.SettingError):
                results.append({'id': key, **preset, 'drift': [], 'available': False})
        return JSONResponse({'presets': results, 'revision': page._revision(layers)}, headers=HEADERS)


@router.get('/api/v1/settings/history')
def history(request: Request):
    _allowed(request)
    from maverick.audit.reader import iter_events
    from maverick.paths import data_dir

    events = deque(maxlen=100)
    since = (datetime.now(timezone.utc) - timedelta(days=30)).date().isoformat()
    try:
        for event in iter_events(since=since, audit_dir=data_dir('audit', tenant=None), strict=True):
            if event.get('kind') != 'setting_changed':
                continue
            payload = event
            key = str(payload.get('section', '')) + '.' + str(payload.get('key', ''))
            setting = catalog.BY_ID.get(key)
            if setting is None:
                continue
            old, new = payload.get('old'), payload.get('new')
            restorable = _can_export(setting) and old is not None
            events.append({'id': key, 'label': setting.label, 'actor': payload.get('actor', 'Unknown'),
                           'at': datetime.fromtimestamp(event['ts'], timezone.utc).isoformat(),
                           'before': _present_value(setting, old), 'after': _present_value(setting, new),
                           'before_revision': payload.get('before_revision'), 'after_revision': payload.get('after_revision'),
                           'restorable': restorable,
                           'restore_value': page._form_value(setting, old) if restorable else None})
    except (OSError, ValueError) as exc:
        raise HTTPException(503, 'Settings history could not be read completely. No rollback is available until the record store is readable.') from exc
    return JSONResponse({'items': list(reversed(events)), 'revision': page._revision(),
                         'coverage': 'Last 100 setting changes in the past 30 days. Secret values are never restorable from history.'}, headers=HEADERS)


def _title_rank(title: str, terms: list[str], aliases: str = '') -> int:
    """0 exact title, 1 title starts with the words, 2 every word starts a title
    word, 3 words in the title, 4 in the curated search words, 5 elsewhere."""
    title, phrase = title.lower(), ' '.join(terms)
    words = title.split()
    if title == phrase:
        return 0
    if title.startswith(phrase):
        return 1
    if all(any(word.startswith(term) for word in words) for term in terms):
        return 2
    if all(term in title for term in terms):
        return 3
    return 4 if all(term in title + ' ' + aliases.lower() for term in terms) else 5


@router.get('/api/v1/settings/search')
def search(request: Request, q: str = Query('', max_length=200)):
    auth.require_permission(request, 'view')
    terms = q.lower().split()[:15]
    results, catalogue = [], []
    allowed = {link['href'].split('?')[0] for group in page._app()._nav_context(request)['finder_pages'] for link in group['links']}
    def opens(href):
        # The registry page that governs the destination, e.g. /settings for /settings/all.
        governing = ui_visibility.page_for(href.split('?')[0].split('#')[0])
        return governing is not None and governing['path'] in allowed
    def matches(text):
        return all(word in text.lower() for word in terms)
    def add(title, href, aliases, *, scope='Organization', value='Open this control to review current state', source='Dedicated control', role='Global administrator'):
        if opens(href) and matches(title + ' ' + aliases):
            results.append((_title_rank(title, terms, aliases), {'title': title, 'href': href, 'group': scope, 'id': href,
                            'scope': scope, 'required_role': role, 'effective': value, 'source': source}))
    if auth.has_global_permission(request, 'admin'):
        layers = page._sources()
        # A single letter matches most of All settings: wait for a second one.
        for setting in (catalog.SETTINGS if opens("/settings/all") and len(q.strip()) >= 2 else ()):
            if matches(page._search_text(setting)):
                state = page._resolve(setting, layers)
                if setting.secret:
                    value = 'Set' if state['value'] else 'Not set'
                elif setting.control in {'table', 'rules', 'document', 'keys', 'picks'}:
                    value = 'Configured' if state['value'] else 'Not configured'
                else:
                    value = catalog.display_value(setting, state['value'])
                anchor = 'sa-' + setting.id.replace('.', '-').replace('*', 'all') + '-label'
                catalogue.append((_title_rank(setting.label, terms, setting.aliases), {'title': setting.label, 'href': '/settings/all?group=' + page._slug(setting.group) + '&id=' + quote(setting.id) + '#' + anchor,
                                'group': setting.group, 'id': setting.id, 'scope': 'Organization', 'required_role': 'Global administrator',
                                'effective': value if state['known'] else 'Controlled by deployment', 'source': state['source'], 'locked': state['locked']}))
        add('AI provider keys', '/settings#settings-integrations', 'ai service ai provider api key model key credentials')
        for provider in settings_store.state()['providers']:
            add(provider['label'] + ' provider key', '/settings?focus=provider-key-' + quote(provider['name']), 'api credentials provider key password ai service model key ' + provider['name'],
                value='Set' if provider['configured'] else 'Not set', source=provider['api_key_source'])
        add('Default AI model', '/settings?focus=settings-model-default', 'models route provider model choices')
        add('Your colour theme', '/settings?focus=settings-theme', 'appearance theme color display', scope='Personal / device')
        add('Your page spacing', '/settings?focus=settings-density', 'appearance density compact display', scope='Personal / device')
        add('Your font', '/settings?focus=settings-font', 'appearance accessibility dyslexic font display', scope='Personal / device')
        add('Task spending cap', '/settings?focus=settings-task-budget', 'budget spending per task cost')
        add('Page visibility', '/settings?focus=ui-visibility', 'roles navigation visibility')
        for href, title, aliases in [('/channels','Chat channels','slack teams telegram whatsapp'),
                                     ('/connections','Connected accounts','oauth connectors integrations'),
                                     ('/plugins','Plugins','tools extensions plugins'),
                                     ('/learning','Learning controls','learning consent improvement')]:
            add(title, href, aliases)
    add('Choose a workspace', '/workspace/tenant#tsel-title', 'workspace tenant switch current', scope='Current workspace', role='Signed-in member')
    principal = auth.caller_principal(request)
    if principal:
        from maverick import experience_preferences
        personal = experience_preferences.state(principal) if experience_preferences.enabled() else None
        for key, title, aliases in [('tone','Your writing tone','writing tone voice personality'),
                                    ('preferred_name','Your preferred name','name personalization'),
                                    ('output_style','Your response style','style format response output'),
                                    ('language','Your response language','language locale'),
                                    ('verbosity','Your response detail','verbosity detail concise'),
                                    ('start_page','Your starting page','home start today landing'),
                                    ('theme','Your theme','theme colors appearance system'),
                                    ('font','Your font','font dyslexia accessibility'),
                                    ('density','Your page spacing','density display compact'),
                                    ('text_size','Your text size','text size reading accessibility'),
                                    ('glass','Your glass effects','glass blur translucent transparency appearance')]:
            if personal:
                add(title, '/preferences#preference-' + key, aliases, scope='Personal', role='Signed-in member',
                    value=str(personal['values'][key]) or 'Inherited', source=personal['sources'][key])
        add('Your notifications', '/notifications#notification-preferences', 'notification alerts digest quiet hours mute', scope='Personal', role='Signed-in member')
    # Personal first, then the dedicated controls above, then All settings rows;
    # within each the closest match first (see _title_rank). The 50 shown are
    # the best ones.
    def order(pair):
        return pair[1]['scope'] != 'Personal', pair[0], pair[1]['title'].casefold()
    results = [item for _rank, item in sorted(results, key=order) + sorted(catalogue, key=order)]
    return JSONResponse({'items': results[:50], 'total': len(results)}, headers=HEADERS)
