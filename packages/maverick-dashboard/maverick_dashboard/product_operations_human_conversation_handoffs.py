"""Typed Copilot operations reuse the same web conversation service."""
from __future__ import annotations

from typing import Literal

from fastapi import HTTPException
from maverick.chat_threads import ChatThreads
from maverick.governed_operations import digest
from pydantic import Field

from . import human_conversation_handoffs as native
from .product_operations import Adapter, Outcome, Preview, Snapshot, StrictInput


class Empty(StrictInput):
    pass
class GoalInput(StrictInput):
    goal_id:int=Field(gt=0)
class RequestInput(GoalInput):
    recipient:str=Field(min_length=1,max_length=256)
    purpose:str=Field(min_length=1,max_length=1000)
    hours:Literal[1,2,4,8]=1
class ReplyInput(GoalInput):
    message:str=Field(min_length=1,max_length=4000)
class DutyInput(StrictInput):
    label:str=Field(default='',max_length=120)
    hours:Literal[0,1,2,4,8]=1
class OriginalInput(StrictInput):
    selected:str=Field(min_length=18,max_length=150)

def _choices(request, *, metadata_only=False):
    actor,context=native.authority(request)
    source=native.service(request)
    rows=source.world.query('SELECT id FROM goals WHERE owner=? ORDER BY id DESC LIMIT 10001',(actor,))
    if len(rows)>10000:
        raise HTTPException(409,'The complete owned conversation choices exceed the supported limit. No subset was called complete.')
    result=[]
    for row in rows:
        if not ChatThreads(source.world).binding(row[0]):
            continue
        goal=source.world.get_goal(row[0])
        label=goal.title
        try:
            native.auth.assert_goal_access(request,goal)
        except HTTPException:
            if not metadata_only:
                continue
            try:
                held=native.service(request,metadata_only=True).state(goal.id)
            except (HTTPException,PermissionError,ValueError):
                continue
            if not held['held']:
                continue
            label='Owned human conversation with unavailable source'
        result.append({'value':goal.id,'label':label})
    for row in native.inventory(request).get('incoming',[]):
        if row['state']!='unavailable' and row['goal_id'] not in {item['value'] for item in result}:
            result.append({'value':row['goal_id'],'label':row['title']})
    native.authority(request,context)
    return result

def snapshot_for(action):
    def snapshot(request,selection):
        actor,context=native.authority(request)
        choices=_choices(request,metadata_only=action=='handback')
        chosen=selection.get('goal_id') or selection.get('goal')
        chosen=int(chosen) if str(chosen).isdigit() else 0
        fields=[{'name':'goal_id','label':'Web conversation','kind':'select','required':True,'choices':choices,'value':chosen if chosen in {row['value'] for row in choices} else None}]
        if action=='request':
            groups={str(row['value']):[{'value':person['owner'],'label':person['label']} for person in native.roster(request,row['value'])] for row in choices if source_owner(request,row['value'])==actor}
            fields += [{'name':'recipient','label':'On-duty person','kind':'select','required':True,'depends_on':'goal_id','choices_by':groups,'choices':groups.get(str(chosen),[])},
                       {'name':'purpose','label':'Why do you need a person?','kind':'textarea','required':True,'max_length':1000},hours_field(False)]
        if action in {'reply','message'}:
            fields += [{'name':'message','label':'Exact human reply','kind':'textarea','required':True,'max_length':4000}]
        return Snapshot(digest([actor,context,choices,fields]),'Current web conversations in this account and workspace',native.NOTICE,fields=fields,blocked='' if choices else 'No current authorized web conversation is available.')
    return snapshot

def source_owner(request,goal_id):
    return native.service(request)._source(goal_id)[0].owner

def hours_field(off):
    return {'name':'hours','label':'Availability' if off else 'Sharing permission lasts','kind':'select','required':True,'value':1,
            'choices':[{'value':hours,'label':'Off duty' if hours==0 else f'{hours} hour'+('s' if hours!=1 else '')} for hours in ([0,1,2,4,8] if off else [1,2,4,8])]}

def duty_snapshot(request,_selection):
    value=native.inventory(request)
    return Snapshot(digest(value['duty']),'Your current on-duty declaration',native.NOTICE,fields=[{'name':'label','label':'Name customers see','kind':'text','max_length':120,'value':value['duty']['label']},hours_field(True)])

def empty_snapshot(request,_selection):
    value=native.inventory(request)
    return Snapshot(digest([value['context'],value['duty'],value['history']]),'Current human conversation metadata',native.NOTICE)

def status_prepare(request,_selection,_arguments):
    value=native.inventory(request)
    return Preview('Read your duty declaration, current assigned conversations and original decisions. Open the complete page to continue.',native={'Availability':'On duty' if value['duty']['until']>native.time.time() else 'Off duty','Assigned conversations':[row['title'] for row in value.get('incoming',[])],
        'Original decisions':len(value['history']),'Open human conversations':{'href':native.PAGE,'label':'Open human conversations'},'Limits':native.NOTICE})

def prepare_for(action):
    def prepare(request,_selection,arguments):
        prepared=native.prepare(request,action=action,**arguments)
        return Preview('Review the complete sharing, pause and reply decision before confirming.',native.changes(prepared),prepared)
    return prepare

def duty_prepare(request,_selection,arguments):
    prepared=native.duty_review(request,**arguments)
    return Preview('Review your exact name and availability before confirming.',native.duty_changes(prepared),prepared)

def outcome(value):
    return Outcome('confirmed' if value['confirmed'] else 'unconfirmed',value['message'],{'Limits':native.NOTICE})

def execute(request,_selection,_arguments,prepared,operation):
    return outcome(native.apply(request,prepared,operation) if 'action' in prepared else native.duty_apply(request,prepared,operation))

def recover(request,_selection,_arguments,prepared,operation,*,read_only=False):
    native.authority(request,prepared['context'])
    try:
        result=native.original(request,prepared['record'],operation) if 'action' in prepared else native.duty_original(request,operation)
        return outcome(result)
    except PermissionError:
        return Outcome('unconfirmed','No exact original receipt is available. Nothing was repeated.') if read_only else None

def original_snapshot(request,_selection):
    value=native.inventory(request)
    rows=value['history']
    choices=[{'value':row['record']+':'+row['operation'],'label':row['action']+' / '+native.time.strftime('%b %d, %Y %H:%M',native.time.localtime(row['at']))} for row in rows]
    return Snapshot(digest([value['context'],choices]),'Your exact retained human conversation decisions',native.NOTICE,fields=[{'name':'selected','label':'Original decision','kind':'select','required':True,'choices':choices}],blocked='' if choices else 'No original decision is retained for your account.')

def original_prepare(request,_selection,arguments):
    record,operation=arguments['selected'].split(':',1)
    result=native.duty_original(request,operation) if record=='duty' else native.original(request,record,operation)
    return Preview(result['message'],native={'Result':'Confirmed' if result['confirmed'] else 'Unconfirmed','Nothing repeated':'This is the exact original read only.'})

def entries():
    common={'family':'tasks','pages':(native.PAGE,'/chat/goal/*'),'direct_ui':native.PAGE,'review_max_bytes':200000}
    writes={'execute':execute,'recover':recover,'read_recovery':recover}
    result=[Adapter('conversations.human.status','Read human conversation availability',input_model=Empty,snapshot=empty_snapshot,prepare=status_prepare,**common),
            Adapter('conversations.human.duty','Set your on-duty availability',input_model=DutyInput,snapshot=duty_snapshot,prepare=duty_prepare,**writes,**common)]
    for action in native.LABELS:
        result.append(Adapter('conversations.human.'+action,native.LABELS[action],input_model=RequestInput if action=='request' else ReplyInput if action in {'reply','message'} else GoalInput,snapshot=snapshot_for(action),prepare=prepare_for(action),**writes,**common))
    result.append(Adapter('conversations.human.original','Read an original human conversation decision',input_model=OriginalInput,snapshot=original_snapshot,prepare=original_prepare,**common))
    return tuple(result)
