"""Exact reviewed flywheel admission; native jobs retain the actual outcome."""
from __future__ import annotations

import hashlib
import json
import math
import time
from contextlib import contextmanager, nullcontext
from pathlib import Path

from fastapi import HTTPException
from maverick import config, data_engine, dreaming, flywheel, learning_store, trajectory_store
from maverick.authority_effects import authority_effect_fence
from maverick.file_lock import cross_process_lock, open_private_read
from maverick.governed_operations import digest
from maverick.governed_records import GovernedRecordStore, RecordConflict

from . import auth
from . import learning_jobs as jobs
from . import learning_ops_api as native
from .draft_api import context_for

PAGE = '/learning#lo-flywheel'
TTL = 600
NOTICE = ('Review the latest 10,000 retained work records that are currently permitted for learning. '
          'This cycle replaces shared safeguards and refreshes shared habits from those records, and suggests changes to test. '
          'It uses no AI and makes no outside changes. A learning safety copy is required. '
          'Recorded patterns are not proof of better customer results.')


def _requests():
    return GovernedRecordStore('learning-flywheel-requests', 'LFW', 'learning_flywheel_request', authority_scope='deployment_global')


def _authority(request, context=None, *, write=False):
    auth.require_global_permission(request, 'admin')
    current = context_for(request)
    if context is not None and context != current:
        raise HTTPException(409, 'Your account or workspace changed. Refresh before continuing.')
    if write:
        from .app import _require_same_origin
        _require_same_origin(request)
        native._halt_preflight('flywheel')
    return current


def _read(path, limit=64 * 1024 * 1024):
    import os
    try:
        with os.fdopen(open_private_read(path), 'rb') as handle:
            raw = handle.read(limit + 1)
    except FileNotFoundError:
        return b''
    if len(raw) > limit:
        raise ValueError('source bound')
    return raw


def _artifact(*, details=False):
    from maverick.paths import data_dir
    values, guidance = [], {}
    for name in ('guardrails.json', 'procedural_memory.json'):
        raw = _read(data_dir(name), 16 * 1024 * 1024)
        value = json.loads(raw) if raw else []
        if not isinstance(value, list):
            raise ValueError('guidance shape')
        json.dumps(value, allow_nan=False)
        required = {'action': str, 'severity': float, 'ci_high': float, 'rule': str} if name == 'guardrails.json' else {'action': str, 'benefit': float, 'strength': float}
        for row in value:
            if not isinstance(row, dict) or set(row) != set(required):
                raise ValueError('unsupported guidance record')
            for key, kind in required.items():
                if kind is str and not isinstance(row[key], str):
                    raise ValueError('guidance text')
                if kind is float and (type(row[key]) not in (int, float) or not math.isfinite(row[key])):
                    raise ValueError('guidance number')
        if len({row['action'] for row in value}) != len(value):
            raise ValueError('duplicate guidance record')
        guidance[name] = value
        values.append([str(data_dir(name).resolve()), hashlib.sha256(raw).hexdigest()])
    return (digest(values), guidance) if details else digest(values)


def _source(*, locked=False):
    from maverick.pilot_learning import restriction_state
    store = trajectory_store.shared()
    with (nullcontext() if locked else store._lock), (nullcontext() if locked else cross_process_lock(store.path, strict=True)):
        raw = _read(store.path)
        lines = raw.splitlines()
        if len(lines) > 56250:
            raise ValueError('retained work exceeds supported source')
        steps = []
        policies = {}
        fields = trajectory_store.TrajectoryStep.__dataclass_fields__
        for line in lines[-10000:]:
            if not line.strip():
                continue
            row = json.loads(line)
            if not isinstance(row, dict):
                raise ValueError('work row shape')
            json.dumps(row, allow_nan=False)
            if any(type(row.get(key)) is not int or row[key] < 0 for key in ('goal_id', 'episode_id', 'step')):
                raise ValueError('work identity')
            goal = row['goal_id']
            if goal not in policies:
                policies[goal] = restriction_state(goal) if goal else 'permitted'
            if policies[goal] == 'unavailable':
                raise ValueError('source permission unavailable')
            if policies[goal] == 'excluded':
                continue
            steps.append(trajectory_store.TrajectoryStep(**{key: row.get(key) for key in fields}))
        outcomes = flywheel.grounded_outcome_fn()
        episodes = {}
        for step in steps:
            episodes.setdefault((step.goal_id, step.episode_id), []).append(step)
        grounded = [[key, outcomes(sorted(rows, key=lambda s: s.step))] for key, rows in episodes.items()]
        return steps, digest([str(Path(store.path).resolve()), hashlib.sha256(raw).hexdigest(), policies, grounded]), len(episodes)


def _state(request, *, context=None, write=False, locked=False):
    with auth.fresh_configuration():
        current = _authority(request, context, write=write)
        if config.config_source_errors(include_tenant=True):
            raise HTTPException(503, 'The current learning settings cannot be read. No cycle was started.')
        if not data_engine.enabled():
            raise HTTPException(409, 'Turn on the improvement flywheel under Learning systems before starting a cycle.')
        native._halt_preflight('flywheel')
        cfg = config.get_data_engine()
        threshold, support, top = cfg.get('failure_threshold', .5), cfg.get('min_support', 8), cfg.get('top_k', 10)
        if (type(threshold) not in (int, float) or not math.isfinite(threshold) or not 0 <= threshold <= 1
                or type(support) is not int or not 1 <= support <= 1000 or type(top) is not int or not 1 <= top <= 100):
            raise HTTPException(409, 'The improvement flywheel limits need attention in All settings.')
        try:
            steps, source, episodes = _source(locked=locked)
            artifact = _artifact()
        except (OSError, ValueError, TypeError) as exc:
            raise HTTPException(409, 'The retained work or current learned guidance cannot be completely checked. Refresh when its records are available; nothing was started.') from exc
        revision = digest([current, config.load_config(), source, artifact])
        _authority(request, current)
        return {'context': current, 'revision': revision, 'source_revision': digest([current, config.load_config(), source]),
                'artifact': artifact, 'steps': steps, 'tasks': episodes,
                'settings': {'failure_threshold': threshold, 'min_support': support, 'top_k': top}}


def catalog(request):
    current = _authority(request)
    rows = _requests().list(limit=1001)
    if len(rows) > 1000:
        raise HTTPException(409, 'The retained cycle list cannot be completely displayed. Original outcomes remain available from their saved links.')
    own = [row for row in rows if (row['actor'], row['workspace']) == (native._actor(request), native._workspace())]
    _authority(request, current)
    result = {'context': current, 'notice': NOTICE, 'requests': [{'value': row['id'][4:], 'label': 'Improvement cycle / ' + time.strftime('%b %d, %H:%M:%S', time.localtime(row['created_at']))}
                                                             for row in sorted(own, key=lambda r: r['created_at'], reverse=True)]}
    try:
        state = _state(request, context=current)
        result.update(revision=state['revision'], tasks=state['tasks'], steps=len(state['steps']), ready=True)
    except HTTPException as exc:
        if exc.status_code in (401, 403):
            raise
        result.update(revision='', tasks=0, steps=0, ready=False, problem=exc.detail)
    _authority(request, current)
    return result


def prepare(request, *, context=None, revision=None):
    state = _state(request, context=context, write=True)
    if revision is not None and revision != state['revision']:
        raise HTTPException(409, 'The work, learning permission, settings or saved guidance changed. Refresh and review again.')
    prepared = {key: value for key, value in state.items() if key != 'steps'}
    planned = _guidance_review(state)
    prepared.update(guidance_review=planned['rows'], guidance_plan=planned['plan'], prior_habits=planned['prior_habits'])
    if _state(request, context=state['context'], write=True)['revision'] != state['revision']:
        raise HTTPException(409, 'The current guidance or reviewed work changed. Refresh and review again.')
    return prepared


def _guidance_review(state):
    from maverick.tenant import registry

    artifact, before = _artifact(details=True)
    if artifact != state['artifact']:
        raise HTTPException(409, 'The current guidance changed. Refresh and review again.')
    plan = _guidance_plan(state, before['procedural_memory.json'])
    after = {'guardrails.json': plan['guardrails'], 'procedural_memory.json': plan['habits']} if plan is not None else before
    workspace = native._workspace()
    record = registry.get_tenant(workspace) if workspace else None
    if workspace and record is None:
        raise HTTPException(409, 'The current workspace is unavailable. Refresh before reviewing its learning information.')
    rows = [{'label': 'Scope of these changes', 'before': record.display_name if record else 'This installation',
             'after': 'Shared learning guidance in this workspace. This does not change completed customer work or another workspace.'}]
    for name, label in (('guardrails.json', 'Safeguard'), ('procedural_memory.json', 'Habit')):
        previous = {row['action']: row for row in before[name]}
        proposed = {row['action']: row for row in after[name]}
        for action in sorted(set(previous) | set(proposed)):
            def describe(value, name=name):
                if value is None:
                    return 'Not present'
                if name == 'guardrails.json':
                    return f"Action: {value['action']}\nGuidance: {value['rule']}\nRecorded harm estimate: {value['severity']}\nUpper effect estimate: {value['ci_high']}"
                return f"Action: {value['action']}\nRecorded benefit estimate: {value['benefit']}\nStrength: {value['strength']}"
            rows.append({'label': label + ': ' + action, 'before': describe(previous.get(action)), 'after': describe(proposed.get(action))})
        if not previous and not proposed:
            rows.append({'label': label + 's', 'before': 'None saved', 'after': 'None will be saved'})
    if len(rows) > 1000 or len(json.dumps(rows, ensure_ascii=False, separators=(',', ':')).encode('utf-8')) > 128000:
        raise HTTPException(409, 'The complete guidance changes are too large to review in one cycle. No cycle was admitted; review the saved learning information before trying again.')
    return {'rows': rows, 'plan': plan, 'prior_habits': before['procedural_memory.json']}


def _guidance_plan(state, prior_habits):
    from dataclasses import asdict

    from maverick import negative_knowledge, procedural_memory

    if not state['steps']:
        return None
    settings, steps = state['settings'], state['steps']
    outcome = flywheel.grounded_outcome_fn()
    classes = data_engine.triage(steps, outcome_fn=outcome, **settings)
    prior = sorted((procedural_memory.Memory(**row) for row in prior_habits), key=lambda m: m.strength, reverse=True)[:128]
    return {'guardrails': [asdict(row) for row in negative_knowledge.mine(classes)],
            'habits': [asdict(row) for row in procedural_memory.consolidate(steps, prior=prior, min_support=settings['min_support'], outcome_fn=outcome)]}


def review_rows(prepared):
    return [{'label': 'What this cycle can change', 'after': NOTICE},
            {'label': 'Currently permitted recorded work', 'after': str(prepared['tasks']) + ' recorded runs'},
            {'label': 'Cost', 'after': 'No AI provider calls or charges. At most 60 seconds of local work, or a tighter current organization allowance.'},
            {'label': 'Recovery', 'after': 'Read the original task and saved observations after an interrupted reply. Do not repeat an unconfirmed cycle. A safety copy can restore covered learning information; it does not undo completed work.'}] + prepared['guidance_review']


def owned(request, operation, prepared=None):
    if len(operation) != 32 or any(c not in '0123456789abcdef' for c in operation):
        raise HTTPException(422, 'Choose a retained original cycle.')
    current = _authority(request)
    row = _requests().get('LFW-' + operation)
    if row and (row['actor'], row['workspace']) != (native._actor(request), native._workspace()):
        raise HTTPException(404, 'This original cycle is unavailable to your account and workspace.')
    if row and prepared is not None and row['binding'] != digest([operation, native._actor(request), prepared]):
        raise HTTPException(409, 'This request belongs to another reviewed cycle.')
    _authority(request, current)
    return row


def original(request, operation, prepared=None):
    row = owned(request, operation, prepared)
    result = {'context': _authority(request), 'operation': operation, 'recorded': bool(row), 'confirmed': False,
              'message': 'The original start is unconfirmed. No cycle was repeated; absence is not proof it failed.', 'notice': NOTICE}
    if row and row.get('job_id'):
        job = jobs.get(row['job_id'])
        if job and (job.kind, job.started_by, job.workspace) == ('flywheel', row['actor'], row['workspace']):
            view = jobs.current_view(job)
            result.update(confirmed=not row.get('_audit_pending') and bool(view['observation_saved']),
                          job={key: view[key] for key in ('state', 'worker_available', 'observation_saved', 'problem', 'result_retained')},
                          task_href='/learning?learning_task=' + job.id + '#learning-job-history')
            result['message'] = 'The original cycle task is recorded. Read its current progress; nothing was repeated.' if result['confirmed'] else 'The original task is known, but its latest observation is not confirmed as saved. Nothing was repeated.'
            if view['result_retained'] and isinstance(view['result'], dict):
                result['result'] = view['result']
        else:
            result['message'] = 'The original admission is retained, but its detailed outcome is unavailable. Nothing was repeated or declared finished.'
    _authority(request, result['context'])
    return result


def _deadline(expires):
    if type(expires) not in (int, float) or not math.isfinite(expires) or not time.time() < expires <= time.time() + TTL:
        raise HTTPException(409, 'This review expired. Review current work again; no new cycle was admitted.')


def start(request, prepared, operation, *, expires):
    with authority_effect_fence():
        _authority(request, prepared['context'], write=True)
        if owned(request, operation, prepared):
            return original(request, operation, prepared)
        _deadline(expires)
        state = _state(request, context=prepared['context'], write=True)
        if state['revision'] != prepared['revision'] or _guidance_review(state) != {'rows': prepared['guidance_review'], 'plan': prepared['guidance_plan'], 'prior_habits': prepared['prior_habits']}:
            raise HTTPException(409, 'The reviewed work, settings, learning permission or guidance changed. No cycle was started.')
        native._record(request, 'flywheel_turn', phase='prepared', operation=operation, reviewed_revision=prepared['revision'])
        store, actor = _requests(), native._actor(request)
        try:
            claim = store.create({'id': 'LFW-' + operation, 'actor': actor, 'context': prepared['context'], 'workspace': native._workspace(),
                                  'binding': digest([operation, actor, prepared]), 'state': 'admitting'},
                                 action='learning.flywheel.prepare', actor=actor, max_records=1000)
        except RecordConflict:
            return original(request, operation, prepared)
        if claim.get('_audit_pending'):
            return original(request, operation, prepared)

    budget_box = []

    def run(job):
        expected = [prepared['artifact']]
        progress = {}
        locked = [False]
        budget = native._budget('learning')
        budget.max_wall_seconds = min(budget.max_wall_seconds, 60) if budget.max_wall_seconds is not None else 60
        budget_box.append(budget)
        def guard():
            if job.cancelled:
                from maverick.learning_guard import Halted
                raise Halted('operator requested stop', 'learning-task')
            budget.check()
            _deadline(expires)
            current = _state(request, context=prepared['context'], write=True, locked=locked[0])
            if (current['source_revision'] != prepared['source_revision'] or current['artifact'] != expected[0]
                    or _guidance_plan(current, prepared['prior_habits']) != prepared['guidance_plan']):
                raise HTTPException(409, 'The reviewed work or learning guidance changed. This cycle stopped; earlier changes may remain.')
        @contextmanager
        def effects():
            source = trajectory_store.shared()
            with authority_effect_fence(), learning_store.derived_guidance_fence(), source._lock, cross_process_lock(source.path, strict=True):
                locked[0] = True
                try:
                    guard()
                    yield
                finally:
                    locked[0] = False
        def observe(family, phase, count):
            progress[family] = {'phase': phase, 'count': count}
            if phase == 'saved':
                expected[0] = _artifact()
        with authority_effect_fence():
            guard()
            def admit(row):
                guard()
                row.update(job_id=job.id, state='admitted')
            admitted = store.update(claim['id'], admit, expected_revision=claim['revision'], action='learning.flywheel.admitted', actor=actor)
            if admitted.get('_audit_pending'):
                raise HTTPException(503, 'The original task admission is not confirmed; no learning write was dispatched.')
            scope = dreaming.learning_mutation_scope()
            scope.__enter__()
        result = {'tasks': prepared['tasks'], 'stores': [], 'complete': False}
        try:
            report = flywheel.run_once(state['steps'], strict=True, guard=guard, effect_scope=effects, observe=observe, expected_guidance=prepared['guidance_plan'], **state['settings'])
            result.update(complete=True, state='completed' if state['steps'] else 'no_eligible_work',
                          message='The cycle finished. Read its recorded guidance changes and suggestions.' if state['steps'] else 'No permitted retained work was available. No guidance was replaced.',
                          counts={'avoid': len(report.guardrails), 'habits': len(report.memories), 'ideas': len(report.hypotheses)})
        except Exception:
            written = any(v['phase'] in ('saved', 'recorded') for v in progress.values())
            uncertain = any(v['phase'] == 'writing' for v in progress.values())
            result.update(state='partial' if written else 'uncertain' if uncertain else 'failed_before_changes',
                          message='This cycle did not finish. Earlier learning changes were saved; some activity records may be unavailable. Nothing was undone or repeated.' if written else
                                  'The guidance write outcome is unconfirmed. Check current guidance and a saved learning point before deciding what to do next; do not repeat automatically.' if uncertain else
                                  'This cycle stopped before any learning-store write was dispatched. No guidance was replaced.')
        finally:
            scope.__exit__(None, None, None)
        labels = {'guardrails': 'Safeguards', 'habits': 'Habits'}
        result['stores'] = [{'Information': labels[k], 'Recorded state': {'writing': 'Write outcome unconfirmed', 'saved': 'Saved; activity record unconfirmed', 'recorded': 'Saved and activity recorded'}[v['phase']], 'Items': v['count']} for k, v in progress.items()]
        result['recovery'] = {'href': '/learning#learning-review', 'label': 'Review saved learning points and restoration'}
        return result
    def cancel():
        if budget_box:
            jobs.stop_budget(budget_box[0])()
    try:
        native.start_job(request, 'flywheel', 'Reviewed improvement cycle', run, cancellable=True, on_cancel=cancel)
    except Exception:
        return original(request, operation, prepared)
    return original(request, operation, prepared)
