"""Explicitly enrolled mobile work, through existing task and approval services."""
from __future__ import annotations

import json
import math
import re
import secrets
import time
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from maverick import crypto_at_rest
from maverick.authority_effects import authority_effect_fence
from maverick.budget import Budget
from maverick.governed_operations import digest
from maverick.paths import current_tenant_id_strict
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from . import auth, device_pairing
from .draft_api import context_for
from .product_operations import Outcome

router = APIRouter()
BASE, PURPOSE, TTL = '/api/v1/devices/work', 'lightwork.device-work-review.v1', 180
ACTIONS = {'start': 'tasks.start', 'approve': 'reviews.approval_approve', 'reject': 'reviews.approval_reject'}


class Input(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)


class Prepare(Input):
    action: Literal['start', 'approve', 'reject']
    approval_id: int = Field(default=0, ge=0)
    context: str = Field(pattern=r'^[a-f0-9]{64}$')
    revision: str = Field(pattern=r'^[a-f0-9]{64}$')
    arguments: dict[str, Any] = Field(default_factory=dict, max_length=5)


class Token(Input):
    token: str = Field(min_length=1, max_length=160000)


class Execute(Token):
    confirmed: bool


def _response(value, background=None):
    return JSONResponse(value, background=background, headers={'Cache-Control': 'private, no-store'})


def _device(request, action=None):
    ident = getattr(request.state, 'paired_device_id', None)
    if not ident:
        raise HTTPException(403, 'Pair this device and explicitly approve the requested work choice first.')
    principal = device_pairing.authenticate(auth._bearer_token(request), request.method, auth.route_path(request))
    if principal.principal != auth.caller_principal(request) or principal.claims['device_id'] != ident:
        raise HTTPException(401, 'This device connection changed. Pair it again before reviewing work.')
    if action and principal.claims['new_tasks' if action == 'start' else 'approvals'] is not True:
        raise HTTPException(403, 'This device was not approved for this choice. Pair it again and review that separate permission on the dashboard.')
    auth.require_permission(request, 'operate')
    binding = digest([context_for(request), ident, device_pairing._policy(),
                      principal.claims['new_tasks'], principal.claims['approvals']])
    return ident, principal.principal, binding, principal.claims


def _adapter(action):
    from .product_operations_approvals import entries as approval_entries
    from .product_operations_task_launch import entries as task_entries
    return next(entry for entry in (task_entries() if action == 'start' else approval_entries()) if entry.id == ACTIONS[action])


def _owned_approval(request, identifier, *, supported=False):
    from ._shared import _world
    world = _world()
    row = world.get_approval(identifier)
    goal = world.get_goal(row.goal_id) if row and row.goal_id else None
    if goal is None or goal.owner != auth.caller_principal(request):
        raise HTTPException(404, 'This request does not belong to one of your current tasks.')
    auth.assert_goal_access(request, goal)
    if supported:
        from maverick.chat_message_actions import require_copy_sources
        if require_copy_sources(world, goal.id) is not None:
            raise HTTPException(409, 'This request uses copied conversation sources. Open its complete protected dashboard review so every original source permission can be checked.')
    from .content_access import require_approval_content
    require_approval_content(request, identifier, world)
    return world, row, goal


def _state(request, action, approval_id):
    _device(request, action)
    selection = {} if action == 'start' else {'kind': 'approval', 'id': approval_id}
    if action != 'start':
        _owned_approval(request, approval_id, supported=True)
    return selection, _adapter(action).snapshot(request, selection)


@router.get(BASE + '/context')
def context(request: Request, action: Literal['start', 'approve', 'reject'] = 'start', approval_id: int = 0):
    with authority_effect_fence():
        _ident, _actor, binding, _claims = _device(request, action)
        _selection, state = _state(request, action, approval_id)
        if _device(request, action)[2] != binding:
            raise HTTPException(409, 'Your connection changed. Refresh before reviewing work.')
        labels = ('Most steps for each agent', 'AI connection', 'Task spending limit', 'Task time limit', 'Levels of helpers')
        current_details = [{'label': label, 'value': str(state.details[label])} for label in labels] if action == 'start' else []
        return _response({'context': binding, 'revision': state.revision, 'blocked': state.blocked,
                          'summary': state.summary, 'fields': state.fields, 'current_details': current_details, 'checked_at': time.time()})


@router.get(BASE + '/approvals')
def approvals(request: Request, before_id: int = 0):
    from ._shared import _world
    from .approval_queue_operations import safe
    with authority_effect_fence():
        _ident, actor, binding, _claims = _device(request, 'approve')
        world = _world()
        from maverick.attachment_submissions import SubmissionStore
        scope, values = SubmissionStore(world).scope('g.tenant_id')
        scope_sql = '' if SubmissionStore(world).sqlite else ' AND ' + scope
        rows = world.query('SELECT a.id FROM approvals a JOIN goals g ON g.id=a.goal_id '
            "WHERE a.status='pending' AND g.owner=? AND (?=0 OR a.id<?)" + scope_sql + ' ORDER BY a.id DESC LIMIT 51',
            (actor, before_id, before_id, *(() if not scope_sql else values)))
        result = []
        for (identifier,) in rows[:50]:
            try:
                _world, row, goal = _owned_approval(request, identifier)
            except HTTPException as exc:
                if exc.status_code in {403, 404}:
                    continue
                raise
            result.append({'id': row.id, 'task_title': goal.title, 'action': safe(row.action)})
        if _device(request, 'approve')[2] != binding:
            raise HTTPException(409, 'Access changed. Refresh the current request list.')
        return _response({'items': result, 'before_id': rows[49][0] if len(rows) > 50 else 0,
                          'complete': len(rows) <= 50, 'checked_at': time.time(),
                          'notice': 'Only your current task requests are shown. Other approval types need their protected dashboard review. Approval is permission, not proof of execution.'})


def _arguments(adapter, arguments):
    try:
        return adapter.input_model.model_validate(arguments).model_dump(mode='json')
    except ValidationError as exc:
        raise HTTPException(422, 'Check the entered work and limits. Nothing was shortened or changed.') from exc


@router.post(BASE + '/prepare')
def prepare(request: Request, body: Prepare):
    from .app import _require_same_origin
    _require_same_origin(request)
    with authority_effect_fence():
        ident, actor, binding, _claims = _device(request, body.action)
        selection, state = _state(request, body.action, body.approval_id)
        if state.blocked or body.context != binding or state.revision != body.revision:
            raise HTTPException(409, state.blocked or 'Work or access changed. Keep your draft, refresh, and review again.')
        adapter = _adapter(body.action)
        arguments = _arguments(adapter, body.arguments)
        preview = adapter.prepare(request, selection, arguments)
        if _state(request, body.action, body.approval_id)[1].revision != state.revision or _device(request, body.action)[2] != binding:
            raise HTTPException(409, 'Work changed while this review was prepared. Refresh before confirming.')
        material = {'purpose': PURPOSE, 'action': body.action, 'selection': selection, 'context': binding,
            'actor': actor, 'device': ident, 'tenant': current_tenant_id_strict(), 'revision': state.revision,
            'arguments': arguments, 'source': None if body.action == 'start' else _source(_owned_approval(request, body.approval_id, supported=True)[2]), 'native': preview.native, 'operation': secrets.token_hex(16), 'expires_at': time.time() + TTL}
        encoded = json.dumps(material, allow_nan=False, sort_keys=True, separators=(',', ':'))
        if len(encoded.encode()) > 100000:
            raise HTTPException(422, 'The complete review exceeds this device limit. Nothing was shortened; open its full dashboard review.')
        token = crypto_at_rest.seal_to_str(encoded)
        if not crypto_at_rest.is_sealed_str(token):
            raise HTTPException(503, 'This full review could not be protected. Nothing was submitted.')
        return _response({'token': token, 'expires_at': material['expires_at'], 'action': body.action,
                          'summary': preview.summary, 'changes': preview.changes, 'operation_id': material['operation']})


def _open(token):
    try:
        if not crypto_at_rest.is_sealed_str(token):
            raise ValueError('Protected review required')
        value = json.loads(crypto_at_rest.unseal_from_str(token))
        expected = {'purpose', 'action', 'selection', 'context', 'actor', 'device', 'tenant', 'revision', 'arguments', 'source', 'native', 'operation', 'expires_at'}
        if (not isinstance(value, dict) or set(value) != expected or value['purpose'] != PURPOSE
                or value['action'] not in ACTIONS or not re.fullmatch(r'[a-f0-9]{32}', value['operation'])
                or type(value['expires_at']) not in {int, float} or not math.isfinite(value['expires_at'])):
            raise ValueError('Invalid protected review')
        return value
    except Exception as exc:
        raise HTTPException(409, 'This original review could not be verified. Nothing was repeated.') from exc


def _source(goal):
    return {'id': goal.id, 'owner': goal.owner, 'domain': goal.domain}


def _current(request, value, *, effect=False, budget=None, verify_source=True):
    ident, actor, binding, _claims = _device(request, value['action'] if effect else None)
    if (ident, actor, current_tenant_id_strict()) != (value['device'], value['actor'], value['tenant']):
        raise HTTPException(403, 'This original review belongs to another device, account or workspace.')
    if effect:
        if binding != value['context'] or time.time() >= value['expires_at']:
            raise HTTPException(409, 'This full review expired or access changed. No new work was admitted.')
        if value['action'] == 'start':
            from .product_operations_task_launch import _policy
            if _policy() != value['native']['policy']:
                raise HTTPException(409, 'Current task limits changed. Review them again.')
        elif verify_source:
            from .approval_queue_operations import identity
            _world, row, goal = _owned_approval(request, value['selection']['id'], supported=True)
            if _source(goal) != value['source'] or identity(row) != value['native']['identity']:
                raise HTTPException(409, 'The complete request changed. Review its current contents again.')
        if time.time() >= value['expires_at']:
            raise HTTPException(409, 'This full review expired while current work was being checked.')
    if budget:
        budget.check()


def _original(request, value):
    _current(request, value)
    if value['action'] == 'start':
        return _task_original(request, value['actor'], value['operation'])
    _owned_approval(request, value['selection']['id'])
    adapter = _adapter(value['action'])
    return adapter.read_recovery(request, value['selection'], value['arguments'], value['native'], value['operation']) or Outcome(
        'unconfirmed', 'The original vote is unconfirmed. A previous effect may exist; nothing was repeated.')


def _read_identity(request, device_id=''):
    if getattr(request.state, 'paired_device_id', None):
        ident, actor, binding, _claims = _device(request)
        if device_id and device_id != ident:
            raise HTTPException(404, 'That original device record is unavailable.')
        return ident, actor, binding
    auth.require_permission(request, 'operate')
    actor = auth.caller_principal(request)
    if not actor or not re.fullmatch(r'[a-f0-9]{32}', device_id):
        raise HTTPException(403, 'Sign in to the original named account and choose its paired device history.')
    device_pairing.work_history(device_id, actor)
    return device_id, actor, digest([context_for(request), device_id, actor])


def _task_original(request, actor, operation):
    from ._shared import _world
    from .goal_submission import lookup_receipt
    try:
        receipt, goal = lookup_receipt(_world(), key=operation, owner=actor, kind='api')
    except HTTPException as exc:
        if exc.status_code == 404:
            return Outcome('unconfirmed', 'The original task admission is unconfirmed. A previous effect may exist; nothing was repeated.')
        raise
    auth.assert_goal_access(request, goal)
    confirmed = receipt['state'] in {'dispatching', 'dispatched'} and goal.status != 'draft'
    return Outcome('queued' if confirmed else 'unconfirmed',
        'Your original task admission is recorded. No second task was started; open progress for its current state.' if confirmed else
        'The task was retained but its execution admission is unconfirmed. Nothing was repeated.',
        {'goal_id': goal.id, 'task': {'label': 'Open task progress', 'href': f'/chat/goal/{goal.id}'}})


@router.get(BASE + '/history')
def history(request: Request, device_id: str = ''):
    with authority_effect_fence():
        ident, actor, binding = _read_identity(request, device_id)
        attempts = device_pairing.work_history(ident, actor)
        names = {'start': 'Start a task', 'approve': 'Approve an owned task request', 'reject': 'Reject an owned task request'}
        result = [{'operation': operation, 'action': row['action'], 'label': names[row['action']], 'at': row['at']}
                  for operation, row in attempts.items()]
        if _read_identity(request, device_id)[2] != binding:
            raise HTTPException(409, 'Your connection changed. Reload your original decisions.')
        return _response({'items': sorted(result, key=lambda row: (row['at'], row['operation']), reverse=True),
                          'complete': True, 'notice': 'These are earlier submitted requests, including unknown outcomes. Reading them never repeats work.'})


@router.get(BASE + '/original')
def original_reference(request: Request, operation: str, device_id: str = ''):
    with authority_effect_fence():
        ident, actor, binding = _read_identity(request, device_id)
        row = device_pairing.work_history(ident, actor).get(operation)
        if row is None:
            raise HTTPException(404, 'This original request is unavailable to this device.')
        receipt = row['receipt']
        if row['action'] == 'start':
            result = _task_original(request, actor, operation)
        else:
            from .approval_queue_operations import receipt as vote_receipt
            from .product_operations_approvals import outcome
            world, _approval, _goal = _owned_approval(request, receipt['approval_id'])
            event = world.get_approval_audit_event(receipt['event_id'])
            if event is None:
                result = Outcome('unconfirmed', 'The original vote is unconfirmed. A previous effect may exist; nothing was repeated.')
            elif not event.matches(receipt['approval_id'], receipt['status'], actor):
                raise HTTPException(503, 'The original vote could not be verified. Nothing was repeated.')
            else:
                result = outcome(vote_receipt(world, event), replayed=True)
        if _read_identity(request, device_id)[2] != binding:
            raise HTTPException(409, 'Your connection changed. Reload the original result.')
        return _result(result, operation)


def _result(value, operation):
    return _response({'status': value.status, 'message': value.message, 'details': value.details,
                      'operation_id': operation}, value.background)


@router.post(BASE + '/original')
def original(request: Request, body: Token):
    from .app import _require_same_origin
    _require_same_origin(request)
    with authority_effect_fence():
        value = _open(body.token)
        result = _original(request, value)
        _current(request, value)
        return _result(result, value['operation'])


@router.post(BASE + '/execute')
def execute(request: Request, body: Execute):
    from .app import _require_same_origin
    _require_same_origin(request)
    if body.confirmed is not True:
        raise HTTPException(400, 'Confirm the complete reviewed work before applying it.')
    value = _open(body.token)
    with authority_effect_fence():
        budget = Budget(max_wall_seconds=15, max_dollars=0, max_tool_calls=0)
        def guard():
            # Native vote callbacks run inside the held DB transaction. Do not
            # open another World reader there (it can commit or block that tx).
            _current(request, value, effect=True, budget=budget, verify_source=False)
        def source_guard(goal_id, owner, domain):
            guard()
            if {'id': goal_id, 'owner': owner, 'domain': domain} != value['source']:
                raise HTTPException(409, 'The current task owner or department changed. Review its protected request again.')
            if owner != auth.caller_principal(request) or not auth.domain_suites_allowed(request, domain):
                raise HTTPException(404, 'This task request is unavailable to your current account.')
        if value['action'] != 'start':
            guard.approval_source = source_guard
        _current(request, value)
        claimed = device_pairing.claim_work(value['device'], value['actor'], value['operation'],
            digest(value), value['action'], receipt={} if value['action'] == 'start' else {
                'approval_id': value['selection']['id'], 'event_id': value['native']['event_id'], 'status': value['native']['status']}, effect_guard=lambda: _current(request, value, effect=True, budget=budget))
        if not claimed:
            return _result(_original(request, value), value['operation'])
        try:
            _current(request, value, effect=True, budget=budget)
            result = _adapter(value['action']).execute(request, value['selection'], value['arguments'],
                value['native'], value['operation'], effect_guard=guard)
        except Exception:
            result = _original(request, value)
        _current(request, value)
        return _result(result, value['operation'])
