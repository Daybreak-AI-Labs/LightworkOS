"""The code vault: a company's repositories held inside Lightwork, sealed at rest.

Each registered repository is one git bundle (every branch and tag), sealed with
the tenant's at-rest key and bound to ``codebase/<name>`` when encryption is on.
Plaintext exists only in a private working copy for as long as a task needs it
(:func:`checkout`), and every run over it starts labelled ``code:<name>`` so
information-flow control keeps the code inside (:mod:`maverick.ifc`).

Git runs host-side with the hardened environment from :mod:`maverick.git_safety`
(no user/system config, no fsmonitor, no inherited secrets). A remote credential
is never stored: the registry names an environment variable, read at use time
and passed through ``GIT_ASKPASS``, never argv or a persisted URL.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.parse import urlsplit

from ..file_lock import atomic_write_bytes, atomic_write_text, cross_process_lock
from ..git_safety import git_env_without_user_config
from ..paths import data_dir

NAME = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}\Z")
PROTECT = ("audit", "approve", "block")
_GIT_TIMEOUT = 600


class VaultError(RuntimeError):
    """A vault operation could not be completed safely."""


@dataclass(frozen=True)
class Repo:
    name: str
    source: str
    default_branch: str
    test_command: str | None = None
    protect: str = "block"
    token_env: str | None = None
    head: str = ""
    updated_at: float = 0.0


def enabled() -> bool:
    from ..config import get_codebase
    return get_codebase()["enable"]


def _root(*parts: str) -> Path:
    return data_dir("codebase", *parts)


def _context(name: str) -> str:
    return f"codebase/{name}"


def _seal(data: bytes, context: str) -> bytes:
    from ..crypto_at_rest import at_rest_enabled, seal_bound
    return seal_bound(data, context) if at_rest_enabled() else data


def _unseal(data: bytes, context: str) -> bytes:
    from ..crypto_at_rest import is_bound, strict_at_rest, unseal_bound
    if is_bound(data):
        return unseal_bound(data, context)
    if strict_at_rest():
        raise VaultError("refusing unsealed vault data while strict at-rest encryption is on")
    return data


# Every host-side git call runs with these on top of git_safety's scrubbed
# environment: repository hooks, external diff drivers and textconv can never run,
# whatever a working tree or its metadata says. Automatic maintenance is off too:
# git 2.54+ follows a fetch with a detached geometric repack, which deleted packs
# while clone_work copied them, and these repositories are temporary anyway.
_HARDEN = {"core.hooksPath": os.devnull, "diff.external": "", "core.fsmonitor": "false",
           "protocol.ext.allow": "never", "maintenance.auto": "false", "gc.auto": "0"}


def _env(token_env: str | None, extra: dict[str, str] | None = None) -> dict[str, str]:
    env = git_env_without_user_config()
    n = int(env.get("GIT_CONFIG_COUNT", "0"))
    for i, (k, v) in enumerate(_HARDEN.items(), start=n):
        env[f"GIT_CONFIG_KEY_{i}"], env[f"GIT_CONFIG_VALUE_{i}"] = k, v
    env["GIT_CONFIG_COUNT"] = str(n + len(_HARDEN))
    env.update(extra or {})
    return env


def _git(args: list[str], cwd: Path | None = None, *, git_dir: Path | None = None,
         work_tree: Path | None = None, token_env: str | None = None,
         env: dict[str, str] | None = None, timeout: int = _GIT_TIMEOUT) -> str:
    prefix = ([f"--git-dir={git_dir}"] if git_dir else []) + \
             ([f"--work-tree={work_tree}"] if work_tree else [])
    run_env = _env(token_env, env)
    askpass = None
    try:
        if token_env:
            token = os.environ.get(token_env)
            if not token:
                raise VaultError(f"credential variable {token_env} is not set")
            fd, askpass = tempfile.mkstemp(prefix="lw-askpass-")
            with os.fdopen(fd, "w") as fh:
                fh.write('#!/bin/sh\nprintf "%s\\n" "$LW_GIT_TOKEN"\n')
            os.chmod(askpass, stat.S_IRWXU)
            run_env.update({"GIT_ASKPASS": askpass, "LW_GIT_TOKEN": token})
        done = subprocess.run(["git", *prefix, *args], cwd=cwd, env=run_env,
                              capture_output=True, encoding="utf-8", errors="replace",
                              timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise VaultError(f"git {args[0]} failed: {type(exc).__name__}") from exc
    finally:
        if askpass:
            os.unlink(askpass)
    if done.returncode != 0:
        from ..secrets import scrub
        raise VaultError(scrub(f"git {args[0]} failed: {done.stderr.strip()[:500]}"))
    return done.stdout


def _check_source(source: str) -> str:
    parts = urlsplit(source)
    if parts.scheme in ("http", "https", "ssh", "git"):
        if parts.username or parts.password:
            raise VaultError("put credentials in token_env, not in the source URL")
        return source
    path = Path(source).expanduser()
    if not path.exists():
        raise VaultError(f"source {source!r} is neither a URL nor an existing path")
    return str(path.resolve())


# -- registry ----------------------------------------------------------------------

def _registry_path() -> Path:
    return _root("registry.json")


def _load() -> dict[str, dict]:
    try:
        return json.loads(_registry_path().read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}


def _save(registry: dict[str, dict]) -> None:
    atomic_write_text(_registry_path(), json.dumps(registry, indent=2, sort_keys=True))


def list_repos() -> list[Repo]:
    return [Repo(**v) for _, v in sorted(_load().items())]


def get(name: str) -> Repo:
    try:
        return Repo(**_load()[name])
    except KeyError:
        raise VaultError(f"no repository named {name!r}") from None


def _bundle_path(name: str) -> Path:
    return _root(name, "vault.bundle")


def _store_bundle(name: str, host: Path, default_branch: str) -> str:
    """Seal every branch and tag of the host-owned bare repository ``host``."""
    with tempfile.TemporaryDirectory(prefix="lw-bundle-") as tmp:
        out = Path(tmp) / "b.bundle"
        _git(["bundle", "create", str(out), "--branches", "--tags"], git_dir=host)
        atomic_write_bytes(_bundle_path(name), _seal(out.read_bytes(), _context(name)))
    return _git(["rev-parse", "--verify", f"refs/heads/{default_branch}"], git_dir=host).strip()


def _private_tmp(prefix: str) -> Path:
    tmp = Path(tempfile.mkdtemp(prefix=prefix))
    os.chmod(tmp, stat.S_IRWXU)
    return tmp


def register(name: str, source: str, *, default_branch: str | None = None,
             test_command: str | None = None, protect: str = "block",
             token_env: str | None = None, timeout: int = _GIT_TIMEOUT) -> Repo:
    """Import a repository (every branch and tag) into the vault.

    ``timeout`` bounds each network step (the dashboard uses a short one)."""
    if not NAME.fullmatch(name):
        raise VaultError("name: lowercase letters, digits, '.', '_' and '-' (max 64)")
    if protect not in PROTECT:
        raise VaultError(f"protect must be one of {PROTECT}")
    source = _check_source(source)
    with cross_process_lock(_registry_path(), strict=True):
        if name in _load():
            raise VaultError(f"{name!r} is already registered")
        tmp = _private_tmp("lw-import-")
        try:
            host = tmp / "host.git"
            _git(["init", "-q", "--bare", str(host)])
            _git(["fetch", "-q", source, "+refs/heads/*:refs/heads/*",
                  "+refs/tags/*:refs/tags/*"], git_dir=host, token_env=token_env,
                 timeout=timeout)
            branch = default_branch or _remote_default(source, token_env, timeout) or "main"
            head = _store_bundle(name, host, branch)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        repo = Repo(name, source, branch, test_command, protect, token_env, head, time.time())
        registry = _load()
        registry[name] = asdict(repo)
        _save(registry)
    return repo


def _remote_default(source: str, token_env: str | None,
                    timeout: int = _GIT_TIMEOUT) -> str | None:
    try:
        out = _git(["ls-remote", "--symref", source, "HEAD"], token_env=token_env,
                   timeout=timeout)
    except VaultError:
        return None
    m = re.search(r"ref: refs/heads/(\S+)\s+HEAD", out)
    return m.group(1) if m else None


def update_registry(name: str, **changes) -> Repo:
    with cross_process_lock(_registry_path(), strict=True):
        registry = _load()
        if name not in registry:
            raise VaultError(f"no repository named {name!r}")
        registry[name].update(changes)
        _save(registry)
        return Repo(**registry[name])


@contextmanager
def host_repo(name: str) -> Iterator[Path]:
    """The vault opened as a private, host-owned BARE repository. Only the host
    runs git in it; working trees handed to agents are separate clones, so no
    file an agent can write is ever read as git metadata by the host."""
    repo = get(name)
    tmp = _private_tmp("lw-code-")
    try:
        host = tmp / "host.git"
        _git(["init", "-q", "--bare", str(host)])
        bundle = tmp / "in.bundle"
        bundle.write_bytes(_unseal(_bundle_path(name).read_bytes(), _context(name)))
        _git(["fetch", "-q", str(bundle), "+refs/heads/*:refs/heads/*",
              "+refs/tags/*:refs/tags/*"], git_dir=host)
        bundle.unlink()
        _git(["symbolic-ref", "HEAD", f"refs/heads/{repo.default_branch}"], git_dir=host)
        yield host
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def clone_work(host: Path, dest: Path, branch: str) -> Path:
    """A working copy of ``branch`` from the host repository (its own .git)."""
    _git(["clone", "-q", "--no-hardlinks", "--branch", branch, str(host), str(dest)])
    return dest


@contextmanager
def checkout(name: str) -> Iterator[Path]:
    """A private plaintext working copy of the default branch, removed on exit."""
    repo = get(name)
    with host_repo(name) as host, work_dir() as tmp:
        yield clone_work(host, tmp / name, repo.default_branch)


@contextmanager
def work_dir() -> Iterator[Path]:
    """A private directory for a working copy handed to an agent -- never the
    host repository's parent, so nothing written there can reach host git
    metadata (its config, hooks or filter definitions)."""
    tmp = _private_tmp("lw-work-")
    try:
        yield tmp
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def commit_back(name: str, host: Path) -> str:
    """Seal the host repository's refs back into the vault (callers hold the lock)."""
    head = _store_bundle(name, host, get(name).default_branch)
    update_registry(name, head=head, updated_at=time.time())
    return head


def _is_ancestor(host: Path, a: str, b: str) -> bool:
    try:
        _git(["merge-base", "--is-ancestor", a, b], git_dir=host)
        return True
    except VaultError:
        return False


def sync(name: str, *, timeout: int = _GIT_TIMEOUT) -> dict:
    """Bring upstream commits into the vault without losing vault-only work.

    Upstream branches are fetched as ``refs/remotes/upstream/*``. A vault branch
    behind upstream fast-forwards; one ahead (approved merges not pushed yet) is
    kept; a diverged default branch gets upstream merged in (a conflict changes
    nothing and is reported); other diverged branches keep the vault's version and
    are reported. New upstream branches and tags are added."""
    repo = get(name)
    report: dict[str, list[str]] = {"fast_forwarded": [], "added": [], "kept_ahead": [],
                                    "merged": [], "diverged_kept": []}
    with cross_process_lock(_bundle_path(name), strict=True), host_repo(name) as host:
        _git(["fetch", "-q", repo.source, "+refs/heads/*:refs/remotes/upstream/*",
              "+refs/tags/*:refs/tags/*"], git_dir=host, token_env=repo.token_env,
             timeout=timeout)
        upstream = _git(["for-each-ref", "--format=%(refname:strip=3)",
                         "refs/remotes/upstream/"], git_dir=host).split()
        for branch in upstream:
            up, local = f"refs/remotes/upstream/{branch}", f"refs/heads/{branch}"
            try:
                _git(["rev-parse", "--verify", "-q", local], git_dir=host)
            except VaultError:
                _git(["update-ref", local, up], git_dir=host)
                report["added"].append(branch)
                continue
            if _is_ancestor(host, up, local):
                if _git(["rev-parse", local], git_dir=host) != _git(["rev-parse", up], git_dir=host):
                    report["kept_ahead"].append(branch)
            elif _is_ancestor(host, local, up):
                _git(["update-ref", local, up], git_dir=host)
                report["fast_forwarded"].append(branch)
            elif branch == repo.default_branch:
                work = clone_work(host, host.parent / "sync-work", branch)
                _git(["fetch", "-q", str(host), f"{up}:refs/remotes/upstream/{branch}"], cwd=work)
                try:
                    _git(["-c", "user.name=Lightwork", "-c", "user.email=lightwork@localhost",
                          "merge", "-q", "--no-ff", "--no-edit",
                          f"refs/remotes/upstream/{branch}"], cwd=work)
                except VaultError as exc:
                    raise VaultError(f"upstream {branch} conflicts with vault-only merges; "
                                     "nothing was changed") from exc
                _git(["fetch", "-q", str(work), f"+refs/heads/{branch}:{local}"], git_dir=host)
                report["merged"].append(branch)
            else:
                report["diverged_kept"].append(branch)
        for ref in _git(["for-each-ref", "--format=%(refname)", "refs/remotes/"],
                        git_dir=host).split():
            _git(["update-ref", "-d", ref], git_dir=host)
        commit_back(name, host)
    return report


def export(name: str, dest: Path) -> Path:
    """A plaintext clone for the owner, outside the vault's protection."""
    dest = Path(dest)
    if dest.exists():
        raise VaultError(f"{dest} already exists")
    with checkout(name) as work:
        shutil.copytree(work, dest, symlinks=True)
    return dest


__all__ = ["PROTECT", "Repo", "VaultError", "checkout", "clone_work", "commit_back",
           "enabled", "export", "get", "host_repo", "list_repos", "register", "sync",
           "update_registry"]
