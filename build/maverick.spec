# -*- mode: python ; coding: utf-8 -*-

from PyInstaller.utils.hooks import collect_all, collect_data_files, collect_submodules, copy_metadata
import sys

# Retain the tokenizer's Rust extension and native-wheel resources. The
# reviewed vocabulary is core package data; no first-use download is needed.
_token_data, _token_binaries, _token_imports = collect_all('tiktoken')
_desktop_data, _desktop_binaries, _desktop_imports = [], [], []
_desktop_packages = ('objc', 'CoreFoundation', 'Foundation', 'AppKit') if sys.platform == 'darwin' else (
    ('Xlib',) if sys.platform.startswith('linux') else ())
for _package in _desktop_packages:
    _data, _binaries, _imports = collect_all(_package)
    _desktop_data += _data
    _desktop_binaries += _binaries
    _desktop_imports += _imports

# Bundle the .dist-info metadata so `maverick version` can read the
# installed package versions from inside the frozen binary.
# Collect both packages' declared non-Python data.  Dashboard templates were
# already bundled; core also owns domain TOML packs, built-in skill Markdown,
# the gRPC contract, and environment-hunter Sigma rules.  Hidden imports alone
# do not make those resources available in a frozen binary.
_datas = (
    _token_data + _desktop_data
    + collect_data_files('maverick')
    + collect_data_files('maverick_dashboard')
    + collect_data_files('maverick_shield')
    + collect_data_files('latex2mathml')
    + collect_data_files('jsonschema_specifications')
    + collect_data_files('boto3')
    + collect_data_files('botocore')
    # Copied into the offline worker at runtime; PYZ bytecode is not a source
    # resource. Retain this one reviewed standalone script in frozen builds.
    + collect_data_files('maverick', includes=['sandbox/document_engine.py'], include_py_files=True)
    + collect_data_files('maverick', includes=['sandbox/plugin_probe.py', 'sandbox/plugin_contracts.py'], include_py_files=True)
)
for _dist in (
    'maverick-agent', 'maverick-shield', 'maverick-channels',
    'maverick-evolve', 'maverick-dashboard', 'maverick-mcp-server',
    'maverick-knowledge', 'maverick-installer', 'pywhispercpp',
    'openai', 'openpyxl', 'lxml', 'pypdf', 'pdfplumber', 'pdfminer.six', 'pypdfium2',
    'sqlalchemy', 'psycopg', 'psycopg-binary', 'psycopg-pool',
    'latex2mathml', 'prometheus-client',
    'jsonschema', 'jsonschema-specifications', 'referencing', 'rpds-py',
    'tiktoken', 'regex',
    'boto3', 'botocore', 's3transfer',
):
    try:
        _datas += copy_metadata(_dist)
    except Exception:
        pass  # not every dist is installed in every build env

a = Analysis(
    ['pyinstaller_entry.py'],
    pathex=[],
    binaries=_token_binaries + _desktop_binaries,
    datas=_datas,
    hiddenimports=[
        'sqlite3',
        '_sqlite3',
        'sqlite3.dbapi2',
        'hashlib',
        'hmac',
        'base64',
        'secrets',
        'tomllib',
        'email.mime.base',
        'email.mime.multipart',
        'email.mime.nonmultipart',
        'email.mime.text',
        'asyncio.events',
        'asyncio.queues',
        'asyncio.subprocess',
        'multipart',
        '_pywhispercpp',
        # SQLAlchemy loads URL-selected dialects dynamically; Psycopg loads
        # its native libpq implementation dynamically. Their hooks retain DLLs.
        'sqlalchemy.dialects.sqlite',
        'sqlalchemy.dialects.postgresql.psycopg',
    ] + _token_imports + _desktop_imports + collect_submodules('maverick')
      # The maverick_* siblings are separate top-level packages imported only
      # inside function bodies (cli.py: `from maverick_dashboard...`), which
      # PyInstaller's static analysis doesn't follow -- so collect_submodules('maverick')
      # alone shipped a binary where `maverick dashboard/mcp` failed at runtime.
      + collect_submodules('maverick_dashboard')
      + collect_submodules('maverick_mcp')
      + collect_submodules('maverick_channels')
      + collect_submodules('maverick_shield')
      + collect_submodules('maverick_evolve')
      + collect_submodules('maverick_knowledge')
      + collect_submodules('maverick_installer')
      + collect_submodules('pywhispercpp')
      + collect_submodules('openai')
      + collect_submodules('openpyxl')
      + collect_submodules('lxml')
      + collect_submodules('pypdf')
      + collect_submodules('pdfplumber')
      + collect_submodules('psycopg')
      + collect_submodules('psycopg_binary')
      + collect_submodules('psycopg_pool')
      + collect_submodules('latex2mathml')
      + collect_submodules('prometheus_client')
      + collect_submodules('jsonschema')
      + collect_submodules('jsonschema_specifications')
      + collect_submodules('referencing')
      + collect_submodules('boto3')
      + collect_submodules('botocore')
      + collect_submodules('s3transfer')
      + collect_submodules('rpds'),
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='maverick',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
