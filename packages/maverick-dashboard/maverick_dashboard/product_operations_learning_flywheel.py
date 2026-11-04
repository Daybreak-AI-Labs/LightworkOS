"""Copilot reviews the native flywheel and reads its exact retained admission."""
from __future__ import annotations

import time

from fastapi import HTTPException
from maverick.governed_operations import digest
from pydantic import Field

from . import learning_flywheel as native
from .product_operations import Adapter, EmptyInput, Outcome, Preview, Snapshot, StrictInput


class OriginalInput(StrictInput):
    operation: str = Field(pattern=r'^[a-f0-9]{32}$')

def snapshot(request, _selection):
    current = native.catalog(request)
    return Snapshot(current['revision'] or digest(current), 'Current improvement cycle', native.NOTICE,
                    details={'Permitted recorded runs': current['tasks'], 'Permitted retained work records': current['steps']},
                    blocked='' if current['ready'] else current['problem'])

def prepare(request, _selection, _arguments):
    prepared = native.prepare(request)
    return Preview(native.NOTICE, changes=native.review_rows(prepared), native={'prepared': prepared, 'expires': time.time() + native.TTL})

def outcome(current, replay=False):
    status = 'replayed' if replay and current['confirmed'] else 'queued' if current.get('job', {}).get('worker_available') else 'confirmed' if current['confirmed'] else 'unconfirmed'
    details = {'Original request': current['message'], 'Meaning': native.NOTICE}
    if current.get('result'):
        result = current['result']
        details['Cycle outcome'] = result['message']
        details['Recorded changes'] = result['stores']
        if result.get('counts'):
            details['Safeguards saved'] = result['counts']['avoid']
            details['Habits saved'] = result['counts']['habits']
            details['Ideas suggested for testing'] = result['counts']['ideas']
        details['Review recovery'] = result['recovery']
    if current.get('task_href'):
        details['Original task'] = {'href': current['task_href'], 'label': 'Read original progress and observations'}
    if current.get('job', {}).get('problem'):
        details['Task problem'] = current['job']['problem']
    summary = current['result']['message'] if isinstance(current.get('result'), dict) and current['result'].get('complete') is False else current['message']
    return Outcome(status, summary, details)

def execute(request, _selection, _arguments, prepared, operation):
    return outcome(native.start(request, prepared['prepared'], operation, expires=prepared['expires']))

def recover(request, _selection, _arguments, prepared, operation, *, read_only=False):
    if native.owned(request, operation, prepared['prepared']) is None and not read_only:
        return None
    return outcome(native.original(request, operation, prepared['prepared']), replay=True)

def original_snapshot(request, _selection):
    state = native.catalog(request)
    return Snapshot(digest([state['context'], state['requests']]), 'Your recorded improvement cycles',
                    'Read the original task without repeating learning.',
                    fields=[{'name': 'operation', 'label': 'Original improvement cycle', 'kind': 'select', 'required': True, 'choices': state['requests']}],
                    blocked='No original improvement cycle is currently retained for your account.' if not state['requests'] else '')

def original_prepare(request, _selection, arguments):
    result = native.original(request, arguments['operation'])
    if not result['recorded']:
        raise HTTPException(404, 'This original cycle is not currently available. Nothing was repeated.')
    view = outcome(result, replay=True)
    return Preview(view.message, native=view.details)

def entries():
    common = {'family': 'learning', 'pages': ('/learning',), 'direct_ui': native.PAGE}
    return (Adapter('learning.run_improvement_cycle', 'Run a reviewed improvement cycle', input_model=EmptyInput,
                    snapshot=snapshot, prepare=prepare, execute=execute, recover=recover,
                    read_recovery=lambda r,s,a,p,o: recover(r,s,a,p,o,read_only=True), **common),
            Adapter('learning.read_original_improvement_cycle', 'Read an original improvement cycle', input_model=OriginalInput,
                    snapshot=original_snapshot, prepare=original_prepare, **common))
