"""Current scoped dashboard authority for explicit human web conversations."""
from __future__ import annotations

import copy
import json
import math
import secrets
import time
from types import SimpleNamespace

from fastapi import HTTPException
from maverick import config, contact_centre, conversation_inbox, crypto_at_rest
from maverick.authority_effects import authority_effect_fence
from maverick.budget import Budget
from maverick.governed_operations import digest
from maverick.human_conversation_handoffs import HELD, MAX_ROWS, HumanConversations

from . import auth, tools_ops_api
from .draft_api import context_for

API, PAGE = '/api/v1/human-conversations', '/human-conversations'
_EXCLUDED = 'Earlier conversation messages, files, connections and learned information are excluded.'
_OUTSIDE_EXCLUDED = ('Inside Lightwork, earlier conversation messages, files, connections and learned information are excluded. '
                     'The outside contact centre listed below also receives the recent messages shown there, a link back and your name and email when known.')
NOTICE = ('This transfers this web conversation to one named person inside Lightwork. Only the reviewed task brief, saved reply and this human exchange are shared. '
          + _EXCLUDED + ' AI work must settle before a person can claim the conversation. '
          'Stop does not reverse external actions. Hand-back releases only this AI hold. Future intentional messages still need their usual current permissions; it never restarts old attempts or sends human replies to AI automatically.')


def _notice(outside=None):
    """The limits text. With an outside contact centre, it says what that destination receives too."""
    return NOTICE.replace(_EXCLUDED, _OUTSIDE_EXCLUDED) if outside else NOTICE
LABELS = {'request':'Ask a person to take over', 'claim':'Take this conversation', 'reply':'Send a human reply', 'message':'Send your reply to the person',
          'handback':'Hand back future work to AI', 'finish_pause':'Finish pausing current AI work'}


def authority(request, context=None, *, write=False, enabled=False):
    auth.require_permission(request, 'operate' if write else 'view')
    actor = auth.caller_principal(request)
    if not actor:
        raise HTTPException(403, 'Sign in with a named account to use human conversations.')
    current = context_for(request)
    if context is not None and current != context:
        raise HTTPException(409, 'Your account or workspace changed. Reopen this conversation.')
    if write:
        tools_ops_api.same_origin(request)
    if enabled and (config.config_source_errors(include_tenant=True) or config.get_features().get('human_conversation_handoffs') is not True):
        raise HTTPException(403, 'Human conversations are off or their current policy is unavailable. Turn on Human help in Chat in Settings first.')
    return actor, current


def _person_current(principal, domain=None):
    try:
        conversation_inbox.current_authority(SimpleNamespace(owner=principal, domain=domain))
        return True
    except (PermissionError, ValueError, RuntimeError):
        return False


def _sharing_access(world,goal,recipient):
    from maverick.chat_message_actions import require_copy_sources
    from maverick.knowledge_task_context import require_read
    def checked(source):
        if not _person_current(source.owner,source.domain) or not _person_current(recipient,source.domain):
            raise PermissionError('Current source or department permission does not permit this sharing.')
        require_read(source,source.owner)
        require_read(source,recipient)
    checked(goal)
    require_copy_sources(world,goal.id,authorize=checked)


def service(request, *, write=False, metadata_only=False):
    from ._shared import _world
    actor, context = authority(request, write=write)
    world = _world()
    def authorize(goal, session, effect):
        authority(request, context, write=effect)
        if actor == goal.owner:
            if metadata_only:
                auth.require_permission(request, 'operate')
                return
            auth.assert_goal_access(request, goal)
            return
        if not session or session['recipient'] != actor or session['state'] not in HELD or session['expires_at'] <= time.time():
            raise HTTPException(404, 'This shared human conversation is unavailable.')
        if conversation_inbox.task_snapshot(goal)['version'] != session['source']:
            raise HTTPException(409, 'The reviewed task source changed. The customer must review a new sharing decision.')
        if not _person_current(goal.owner, goal.domain) or not _person_current(actor, goal.domain):
            raise HTTPException(403, 'Current source or department permission no longer permits this human exchange.')
        _sharing_access(world,goal,actor)
        if not auth.domain_suites_allowed(request, goal.domain):
            raise HTTPException(403, 'Your current department access does not permit this human exchange.')
    return HumanConversations(world, actor=actor, authorize=authorize, metadata_only=metadata_only)


def roster(request, goal_id=None):
    actor, context = authority(request)
    source = service(request)
    domain = None
    if goal_id is not None:
        goal, _root, _binding = source._source(goal_id)
        auth.assert_goal_access(request, goal)
        domain = goal.domain
    values = [row for row in source.roster() if row['owner'] != actor and _person_current(row['owner'], domain)]
    authority(request, context)
    return values


def _history(request):
    actor, context = authority(request)
    source = service(request)
    rows = source.store.list(limit=MAX_ROWS + 1)
    if len(rows) > MAX_ROWS:
        raise HTTPException(409, 'The complete original history exceeds its supported limit. No subset was called complete.')
    result = []
    for row in rows:
        if row.get('schema') != 'lightwork.conversation-inbox.v1':
            continue
        human = conversation_inbox._unpack(row).get('human', {})
        for operation in human.get('operations', {}).values():
            if operation['actor'] == actor:
                result.append({'record':row['id'], 'operation':operation['operation'], 'action':LABELS[operation['action']],
                               'at':operation['recorded_at'], 'confirmed':operation['state']=='confirmed' and not row.get('_audit_pending')})
    _row,duty=source.duty()
    result += [{'record':'duty','operation':operation,'action':'On-duty declaration','at':entry['at'],'confirmed':not (_row or {}).get('_audit_pending',False)} for operation,entry in duty['operations'].items()]
    if len(result)>MAX_ROWS:
        raise HTTPException(409,'The complete original decision list exceeds the supported limit. No subset was called complete.')
    authority(request, context)
    return sorted(result, key=lambda row:(row['at'],row['operation']), reverse=True)


def inventory(request, goal_id=None):
    actor, context = authority(request)
    source = service(request)
    duty_record, duty_value = source.duty()
    value = {'context':context, 'enabled':config.get_features().get('human_conversation_handoffs') is True,
             'duty':{'revision':(duty_record or {}).get('revision',0), 'label':duty_value['label'], 'until':duty_value['until'],
                     'audit_pending':bool(duty_record and duty_record.get('_audit_pending'))}, 'history':_history(request), 'notice':_notice(contact_centre.enabled())}
    if goal_id is not None:
        try:
            value.update(conversation=source.state(goal_id))
        except HTTPException as exc:
            if exc.status_code not in {403,404}:
                raise
            value.update(conversation=service(request,metadata_only=True).state(goal_id))
        if value['conversation']['owner'] == actor and not value['conversation']['source_unavailable']:
            value['people'] = roster(request, goal_id)
        else:
            value['people'] = []
    else:
        rows = source.store.list(limit=MAX_ROWS + 1)
        if len(rows)>MAX_ROWS:
            raise HTTPException(409,'The complete incoming conversation list exceeds its supported limit. No conversations were silently omitted.')
        incoming=[]
        for row in rows:
            if row.get('schema') != 'lightwork.conversation-inbox.v1':
                continue
            human=conversation_inbox._unpack(row).get('human',{})
            session=human.get('sessions',{}).get(human.get('current'))
            if not session or session['recipient']!=actor or session['state'] not in HELD:
                continue
            try:
                current=source.state(session['goal_id'])
                incoming.append({'goal_id':session['goal_id'],'title':current['session']['shared']['title'],'state':session['state']})
            except (HTTPException,PermissionError,ValueError):
                incoming.append({'goal_id':session['goal_id'],'title':'Shared conversation unavailable under current permission','state':'unavailable'})
        value['incoming']=incoming
    authority(request,context)
    return value


def _guard(request, prepared, budget=None, operation=None):
    actor,_context=authority(request,prepared['context'],write=True,enabled=prepared['action']!='handback')
    now=time.time()
    if actor!=prepared['actor'] or not math.isfinite(prepared['review_expires']) or now>=prepared['review_expires']:
        raise HTTPException(409,'This full review expired. Earlier submitted decisions are retained; review a new intent.')
    if prepared['action']=='request' and prepared.get('outside')!=contact_centre.disclosure():
        raise HTTPException(409,'The outside contact centre settings changed after this review. Nothing was sent; review the handoff again.')
    source=service(request,write=True,metadata_only=prepared.get('metadata_only',False))
    goal,root,_binding,record,_value,human=source._load(prepared['goal_id'])
    source._authorized(goal,root,human,write=True)
    if conversation_inbox.task_snapshot(goal)['version'] != prepared['source'] or root.id!=prepared['root_id'] or root.owner!=prepared['owner']:
        raise HTTPException(409,'The reviewed conversation source changed. Nothing new was admitted.')
    if prepared['action']=='request':
        person=next((row for row in source.roster() if row['owner']==prepared['recipient']),None)
        _sharing_access(source.world,goal,prepared['recipient'])
        if person!=prepared['duty'] or not _person_current(prepared['recipient'],goal.domain) or now>=prepared['expires_at']:
            raise HTTPException(409,'The selected person, source permission or sharing deadline changed. Review the handoff again.')
    current=human['sessions'].get(human['current']) if human['current'] else None
    if prepared['action']=='request' and current and current['state'] in HELD and current['id']!=operation:
        raise HTTPException(409,'Another handoff now holds this conversation. Read its original decision.')
    if prepared['action']!='request' and (not current or current['id']!=prepared['session']):
        raise HTTPException(409,'The selected human exchange changed. Review it again.')
    if prepared['action']=='claim':
        duty_row,duty=source.duty()
        if not duty_row or duty_row.get('_audit_pending') or duty['until']<=now:
            raise HTTPException(409,'You are no longer on duty. Review your availability before claiming this conversation.')
    if prepared['action'] in {'claim','reply','message'} and (not current or now>=current['expires_at']):
        raise HTTPException(403,'Current sharing permission ended. The earlier original remains available.')
    authority(request,prepared['context'],write=True,enabled=prepared['action']!='handback')
    if time.time()>=prepared['review_expires']:
        raise HTTPException(409,'This review expired while current source permission was being checked.')
    if budget:
        budget.check()


def prepare(request, goal_id, action, *, recipient='', purpose='', hours=1, message=''):
    source=service(request,write=True,metadata_only=action=='handback')
    actor,context=authority(request,write=True,enabled=action!='handback')
    if type(hours) is not int or hours not in {1,2,4,8}:
        raise HTTPException(422,'Choose one, two, four or eight hours.')
    duty=next((row for row in roster(request,goal_id) if row['owner']==recipient),None) if action=='request' else None
    prepared=source.review(goal_id,action,recipient=recipient,purpose=purpose,expires_at=time.time()+hours*3600 if action=='request' else 0,message=message,duty=duty)
    prepared.update(actor=actor,context=context)
    prepared['outside']=contact_centre.disclosure() if prepared['action']=='request' else None
    prepared['binding']=digest({key:value for key,value in prepared.items() if key!='binding'})
    _guard(request,prepared)
    return prepared


def _outside_change(outside):
    return {'label':'Outside contact centre','after':{'Destination':outside['where'],
            'Sent':f"Ticket subject or message title, the reason, your name and email when known, the latest {outside['messages']} messages of this web conversation (each shortened to 2,000 characters, personal data removed where it can be detected, and Lightwork's replies can be among them), and a link back to this conversation.",
            'If settings change':'Nothing is sent to a different destination or provider. If Settings change before the send, the handoff is refused or recorded as not sent.'}}


def changes(prepared):
    return [{'label':'Decision','after':LABELS[prepared['action']]},
            {'label':'Complete information shared','after':prepared['shared']},
            {'label':'Selected person and access','after':{'Person':prepared['person_name'],
                 'Reason':prepared['purpose'] or 'Existing reviewed sharing purpose','Access ends':'With this decision' if prepared['action']=='handback' else time.strftime('%b %d, %Y %H:%M',time.localtime(prepared['expires_at'])) if prepared['expires_at'] else 'Existing sharing deadline remains'}},
            {'label':'Exact reply','after':prepared['message'] or 'No reply is sent by this decision.'},
            {'label':'Related AI work','after':[{'Task':name,'Reviewed state':row[3]} for name,row in zip(prepared['task_names'],prepared['tasks'],strict=True)]},
            *([_outside_change(prepared['outside'])] if prepared.get('outside') else []),
            {'label':'Limits and consequences','after':_notice(prepared.get('outside'))},
            {'label':'If the response is lost','after':'Read the exact original decision. Unknown means unknown; no request, stop or reply is automatically repeated. Separately review Finish pausing or Hand back for a new intentional decision.'}]


def apply(request, prepared, operation):
    with authority_effect_fence():
        source=service(request,write=True,metadata_only=prepared.get('metadata_only',False))
        # Existing exact original lookup is pure and precedes expired review checks.
        try:
            return original(request,prepared['record'],operation)
        except PermissionError:
            pass
        budget=Budget(max_wall_seconds=15,max_dollars=0,max_tool_calls=0)
        def guard():
            _guard(request,prepared,budget,operation)
        try:
            return source.apply(prepared,operation,guard=guard)
        except Exception as failure:
            try:
                value=source.original_record(prepared['record'],operation)
                if value['confirmed']:
                    return value
                value['message']='This original is unconfirmed. Earlier stop or sharing effects may exist. Nothing was repeated. Read the current conversation and separately review any remaining pause or hand-back decision.'
                return value
            except PermissionError:
                raise failure from None


def original(request,record,operation):
    authority(request)
    source=service(request)
    # Audit delivery recovery is allowed only for the actual original actor.
    value=source.original_record(record,operation)
    row=source.store.get(record)
    if row.get('_audit_pending'):
        with authority_effect_fence():
            authority(request)
            source.original_record(record,operation)
            source.store._flush(row)
        value=source.original_record(record,operation)
    return value


def duty_review(request,label,hours):
    source=service(request,write=True)
    actor,context=authority(request,write=True,enabled=True)
    if type(hours) is not int or hours not in {0,1,2,4,8}:
        raise HTTPException(422,'Choose Off duty or one, two, four or eight hours.')
    if hours and (not isinstance(label,str) or not label.strip() or len(label)>120):
        raise HTTPException(422,'Enter the name customers will see, up to 120 characters.')
    row,_value=source.duty()
    return {'actor':actor,'context':context,'label':label,'until':time.time()+hours*3600 if hours else 0,
            'revision':(row or {}).get('revision',0),'review_expires':time.time()+300}


def duty_apply(request,prepared,operation):
    with authority_effect_fence():
        actor,_context=authority(request,prepared['context'],write=True,enabled=prepared['until']>0)
        source=service(request,write=True)
        try:
            return duty_original(request,operation)
        except PermissionError:
            pass
        def guard():
            authority(request,prepared['context'],write=True,enabled=prepared['until']>0)
            if actor!=prepared['actor'] or time.time()>=prepared['review_expires']:
                raise HTTPException(409,'This duty review expired. Read its original declaration before reviewing another.')
        row=source.set_duty(label=prepared['label'],until=prepared['until'],operation=operation,expected_revision=prepared['revision'],guard=guard)
        return {'confirmed':not row.get('_audit_pending'),'message':'Your reviewed duty declaration is saved.' if not row.get('_audit_pending') else 'Your duty declaration is unconfirmed. Read it; nothing was automatically repeated.'}


def duty_original(request,operation):
    authority(request)
    source=service(request)
    value=source.duty_original(operation)
    row,_payload=source.duty()
    if row.get('_audit_pending'):
        with authority_effect_fence():
            authority(request)
            source.duty_original(operation)
            source.store._flush(row)
        value=source.duty_original(operation)
    return value


def seal(prepared,operation):
    token=crypto_at_rest.seal_to_str(json.dumps({'purpose':'lightwork.human-conversation-review.v1','prepared':prepared,'operation':operation},allow_nan=False,separators=(',',':')))
    if not crypto_at_rest.is_sealed_str(token):
        raise HTTPException(503,'This complete review could not be retained securely. Nothing was submitted.')
    return token


def open_review(token):
    try:
        if not crypto_at_rest.is_sealed_str(token):
            raise ValueError
        value=json.loads(crypto_at_rest.unseal_from_str(token))
        if set(value)!={'purpose','prepared','operation'} or value['purpose']!='lightwork.human-conversation-review.v1':
            raise ValueError
        return copy.deepcopy(value)
    except Exception as exc:
        raise HTTPException(409,'This complete review could not be verified. Read its original outcome or review current permission again.') from exc


def review_response(prepared):
    operation=secrets.token_hex(16)
    rows=changes(prepared) if 'action' in prepared else duty_changes(prepared)
    return {'context':prepared['context'],'record':prepared.get('record','duty'),'operation':operation,'token':seal(prepared,operation),'changes':rows,'notice':_notice(prepared.get('outside'))}


def duty_changes(prepared):
    return [{'label':'On-duty name','after':prepared['label'] if prepared['until'] else 'Off duty'},
            {'label':'Availability ends','after':time.strftime('%b %d, %Y %H:%M',time.localtime(prepared['until'])) if prepared['until'] else 'Available conversations are no longer offered to new customers'},
            {'label':'Current conversation permission','after':'Availability is only a declaration. Each customer separately reviews the exact task brief, person and sharing deadline. Going off duty does not silently erase an already reviewed exchange.'},
            {'label':'If the response is lost','after':'Read the exact original declaration. Nothing is automatically repeated.'}]
