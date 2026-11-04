"""My Data routes navigation data through existing export and reviewed erasure."""
import copy
import json
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi import HTTPException
from maverick import ux_store
from maverick_dashboard import personal_data_exports as exports
from maverick_dashboard import personal_data_requests as deletion
from maverick_dashboard import product_operations_personal_data as operations


@pytest.fixture
def owned(tmp_path, monkeypatch):
    store = ux_store.UxStore(tmp_path / "ux.json")
    monkeypatch.setattr(ux_store, "shared", lambda: store)
    store.save_view("user:alice", "Private", {"q": "private search"})
    store.pin("user:alice", 1)
    store.pin("user:bob", 2)
    monkeypatch.setattr(deletion.personal_memory, "require_scope", lambda *args: None)
    monkeypatch.setattr(deletion, "preservation_snapshot", lambda: {"blocked": False})
    return store


class Requests:
    def __init__(self, row):
        self.row = copy.deepcopy(row)
        self.fail_final_audit = False

    def get(self, identifier):
        return copy.deepcopy(self.row)

    def update(self, identifier, mutate, *, expected_revision, **kwargs):
        assert self.row['revision'] == expected_revision
        mutate(self.row)
        self.row['revision'] += 1
        if self.fail_final_audit and self.row['targets'][0]['state'] == 'purged':
            self.row['_audit_pending'] = True
        return copy.deepcopy(self.row)


def reviewed(monkeypatch):
    plan = deletion.preview('user:alice', 'dashboard', 'alice', ['saved_views_and_pins'], None)
    assert 'private search' not in json.dumps(plan)
    records = Requests({'id': 'PDR-review', 'revision': 1, 'status': 'requested', **plan})
    monkeypatch.setattr(deletion, 'STORE', records)
    return records


def test_independent_native_review_erases_only_exact_owned_views_and_pins(owned, monkeypatch):
    records = reviewed(monkeypatch)
    with pytest.raises(HTTPException) as own_review:
        deletion.apply('PDR-review', 1, 'user:alice', lambda: None, None, external_holds_clear=True)
    assert own_review.value.status_code == 403
    result = deletion.apply('PDR-review', 1, 'user:reviewer', lambda: None, None, external_holds_clear=True)
    assert result['status'] == 'purged-with-retained-exceptions'
    assert records.row['targets'][0]['removed'] == 2 and owned.pins('user:bob') == [2]
    assert {'workspace_gallery_curation', 'task_feedback_and_trace_annotations'} <= {row['store'] for row in result['exceptions']}


def test_new_saved_view_invalidates_native_review_without_erasure(owned, monkeypatch):
    reviewed(monkeypatch)
    owned.save_view('user:alice', 'Later', {'q': 'new'})
    with pytest.raises(HTTPException) as stale:
        deletion.apply('PDR-review', 1, 'user:reviewer', lambda: None, None, external_holds_clear=True)
    assert stale.value.status_code == 409 and len(owned.views('user:alice')) == 2


def test_partial_write_and_pending_audit_never_return_confirmed_erasure(owned, monkeypatch):
    records = reviewed(monkeypatch)
    real_save = owned._save
    def interrupted(data):
        assert records.row['targets'][0]['state'] == 'dispatching'
        real_save(data)
        raise OSError('acknowledgement lost')
    monkeypatch.setattr(owned, '_save', interrupted)
    result = deletion.apply('PDR-review', 1, 'user:reviewer', lambda: None, None, external_holds_clear=True)
    assert result['status'] == 'partial' and result['targets'][0]['state'] == 'unconfirmed'
    assert owned.views('user:alice') == {} and owned.pins('user:bob') == [2]
    with pytest.raises(HTTPException):
        deletion.apply('PDR-review', result['revision'], 'user:reviewer', lambda: None, None, external_holds_clear=True)


def test_pending_audit_after_delete_raises_instead_of_claiming_complete(owned, monkeypatch):
    records = reviewed(monkeypatch)
    records.fail_final_audit = True
    with pytest.raises(RuntimeError, match='audit receipt'):
        deletion.apply('PDR-review', 1, 'user:reviewer', lambda: None, None, external_holds_clear=True)
    assert records.row['_audit_pending'] is True
    assert records.row['status'] == 'processing'


def test_export_uses_current_exact_owner_and_private_link_context(owned, monkeypatch):
    identity = {'owner': 'user:alice', 'context': 'a' * 64}
    monkeypatch.setattr(exports.native, '_actor', lambda request: identity['owner'])
    monkeypatch.setattr(exports, 'context_for', lambda request: identity['context'])
    monkeypatch.setattr(exports.crypto_at_rest, 'seal_to_str', lambda value: 'sealed:' + value)
    monkeypatch.setattr(exports.crypto_at_rest, 'unseal_from_str', lambda value: value.removeprefix('sealed:'))
    monkeypatch.setattr(exports.crypto_at_rest, 'is_sealed_str', lambda value: value.startswith('sealed:'))
    monkeypatch.setattr(exports, 'audit_event', lambda *args, **kwargs: True)
    link = exports.link(None, store='saved_views_and_pins')
    token = parse_qs(urlsplit(link['href']).query)['token'][0]
    owned.save_view('user:alice', 'Later', {'q': 'new'})
    result = exports.download(None, token)
    data = json.loads(result.body)
    assert set(data['views']) == {'Private', 'Later'} and data['pins'] == [1]
    assert result.headers['cache-control'] == 'private, no-store'
    identity['context'] = 'b' * 64
    with pytest.raises(HTTPException):
        exports.download(None, token)


def test_native_and_copilot_account_export_select_same_registered_store():
    from maverick_dashboard.personal_data_api import AccountExportIn
    assert AccountExportIn(context='a' * 64, store='saved_views_and_pins').store == 'saved_views_and_pins'
    assert operations.AccountExport(store='saved_views_and_pins').store == 'saved_views_and_pins'
    assert 'saved_views_and_pins' in {row['value'] for row in operations._fields({}, 'export_account', [])[0]['choices']}
    assert 'saved_views_and_pins' in deletion.KINDS
