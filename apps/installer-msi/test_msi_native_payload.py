"""Read real synthetic MSI databases/cabinets; never install or execute payloads."""
from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location("msi_native_payload", Path(__file__).with_name("msi_native_payload.py"))
payload = importlib.util.module_from_spec(spec)
spec.loader.exec_module(payload)


def tables():
    return ([('Path', 'Path', 'short.exe|maverick-desktop.exe', '12', '2')],
            [('Path', 'INSTALLDIR')], [('1', '#other.cab'), ('2', '#payload.cab')])


def test_selects_exact_native_component_and_sequence_cabinet():
    assert payload.select_payload(*tables()) == ('Path', 12, 'payload.cab')


@pytest.mark.parametrize("damage", ['missing', 'duplicate', 'path', 'component', 'directory',
    'external', 'cabinet_path', 'wildcard', 'size', 'oversize', 'sequence', 'no_media'])
def test_payload_selection_refuses_ambiguous_or_unsafe_tables(damage):
    files, components, media = tables()
    if damage == 'missing':
        files.clear()
    elif damage == 'duplicate':
        files.append(files[0])
    elif damage in ('path', 'component', 'wildcard', 'size', 'oversize', 'sequence'):
        values = list(files[0])
        index, value = {'path': (0, '../Path'), 'component': (1, "quote'"), 'wildcard': (0, '*'),
                        'size': (3, '0'), 'oversize': (3, str(payload.MAX_NATIVE_BYTES + 1)),
                        'sequence': (4, '0')}[damage]
        values[index] = value
        files[0] = tuple(values)
    elif damage == 'directory':
        components[0] = ('Path', 'OTHERDIR')
    elif damage == 'no_media':
        media.clear()
    else:
        media[1] = ('2', 'payload.cab' if damage == 'external' else '#../payload.cab')
    with pytest.raises(RuntimeError):
        payload.select_payload(files, components, media)


@pytest.mark.skipif(os.name != 'nt' or sys.version_info >= (3, 13), reason='Windows Python 3.12 build-host MSI fixture')
@pytest.mark.parametrize('damage', [None, 'size', 'missing_stream'])
def test_real_embedded_msi_native_bytes_are_read_without_installation(tmp_path, damage):
    # msilib only authors this inert database fixture. Production extraction
    # uses the read-only API directly and does not depend on deprecated msilib.
    import msilib
    from msilib import schema

    native = tmp_path / 'Path'
    native.write_bytes(b'nonexecutable synthetic native payload with package marker MSI')
    restored = tmp_path / 'restored.exe'
    restored.write_bytes(native.read_bytes().replace(b'MSI', b'UNK'))
    cabinet = tmp_path / 'payload.cab'
    makecab = Path(os.environ['SystemRoot']) / 'System32/makecab.exe'
    subprocess.run([str(makecab), str(native), str(cabinet)], cwd=tmp_path,
                   check=True, capture_output=True, timeout=30)
    msi = tmp_path / 'fixture.msi'
    db = msilib.OpenDatabase(str(msi), msilib.MSIDBOPEN_CREATE)
    for table in (schema.File, schema.Component, schema.Media):
        table.create(db)
    msilib.add_data(db, 'File', [('Path', 'Path', 'native.exe|maverick-desktop.exe',
                                native.stat().st_size + int(damage == 'size'), None, None, 512, 1)])
    msilib.add_data(db, 'Component', [('Path', None, 'INSTALLDIR', 0, None, 'Path')])
    msilib.add_data(db, 'Media', [(1, 1, None, '#payload.cab', None, None)])
    if damage != 'missing_stream':
        msilib.add_data(db, '_Streams', [('payload.cab', msilib.Binary(str(cabinet)))])
    db.Commit()
    del db
    original = payload.file_hash(msi)

    if damage:
        with pytest.raises(RuntimeError, match='file table' if damage == 'size' else 'embedded cabinet stream'):
            payload.inspect_payload(msi)
    else:
        result = payload.inspect_payload(msi)
        assert result['native_sha256'] == payload.file_hash(native)
        assert result['native_sha256'] != payload.file_hash(restored)
        assert result['msi_sha256'] == original
        assert result['native_bytes'] == native.stat().st_size
        assert result['file_id'] == 'Path'
    assert payload.file_hash(msi) == original
    # Inspection closes all MSI handles, including refusal paths.
    msi.rename(tmp_path / 'closed.msi')


def test_workflow_does_not_copy_tauri_restored_native_as_packaged_identity():
    workflow = Path(__file__).parents[2] / '.github/workflows/windows-customer.yml'
    assert 'transition-base-native.exe' not in workflow.read_text(encoding='utf-8')
    assert 'transition-next-native.exe' not in workflow.read_text(encoding='utf-8')
