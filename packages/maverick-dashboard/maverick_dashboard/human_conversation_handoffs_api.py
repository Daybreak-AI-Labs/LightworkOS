"""Protected web-only human conversation controls."""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from . import human_conversation_handoffs as native

router=APIRouter(prefix=native.API,tags=['human-conversations'])

class ReviewIn(BaseModel):
    model_config=ConfigDict(extra='forbid',strict=True)
    context:str=Field(pattern=r'^[a-f0-9]{64}$')
    goal_id:int=Field(gt=0)
    action:Literal['request','claim','reply','message','handback','finish_pause']
    recipient:str=Field(default='',max_length=256)
    purpose:str=Field(default='',max_length=1000)
    hours:Literal[1,2,4,8]=1
    message:str=Field(default='',max_length=4000)

class DutyIn(BaseModel):
    model_config=ConfigDict(extra='forbid',strict=True)
    context:str=Field(pattern=r'^[a-f0-9]{64}$')
    label:str=Field(default='',max_length=120)
    hours:Literal[0,1,2,4,8]=1

class ApplyIn(BaseModel):
    model_config=ConfigDict(extra='forbid',strict=True)
    token:str=Field(min_length=1,max_length=2000000)
    confirmed:Literal[True]

def response(request,value):
    actor,context=native.authority(request)
    return JSONResponse({**value,'context':context},headers={'Cache-Control':'private, no-store'})

def run(function,*args,**kwargs):
    try:
        return function(*args,**kwargs)
    except PermissionError as exc:
        raise HTTPException(404,str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(409,str(exc)) from exc
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(503,'This outcome could not be confirmed. Read the exact original; nothing is automatically repeated.') from exc

@router.get('')
def inventory(request:Request,goal_id:int|None=None):
    return response(request,run(native.inventory,request,goal_id))

@router.post('/review')
def review(request:Request,body:ReviewIn):
    native.authority(request,body.context,write=True)
    prepared=run(native.prepare,request,**body.model_dump(exclude={'context'}))
    return response(request,native.review_response(prepared))

@router.post('/duty/review')
def duty_review(request:Request,body:DutyIn):
    native.authority(request,body.context,write=True)
    return response(request,native.review_response(run(native.duty_review,request,body.label,body.hours)))

@router.post('/apply')
def apply(request:Request,body:ApplyIn):
    value=native.open_review(body.token)
    function=native.apply if 'action' in value['prepared'] else native.duty_apply
    return response(request,run(function,request,value['prepared'],value['operation']))

@router.get('/originals/{record}/{operation}')
def original(request:Request,record:str,operation:str):
    function=native.duty_original if record=='duty' else native.original
    args=(request,operation) if record=='duty' else (request,record,operation)
    return response(request,run(function,*args))
