# Kubernetes workspace delivery and recovery

The Kubernetes backend copies a private snapshot into a transient Linux pod.
After the command, it stops leftover same-user processes in the pod and streams
a bounded TAR archive into private local recovery storage. It rejects links,
special files, path escapes, duplicate paths and oversized exports before
publishing changes. File deletions and renames are reflected locally.

Publication compares the initial, current and exported workspaces. Conflicting
local edits are retained, and new local files are preserved. Originals are saved
before publication. Each changed leaf is checked again before replacement.
Publication is atomic per file, not a filesystem-wide transaction: disk failure
can leave some changes applied. Other applications should stop editing the
workspace during a run; they do not participate in Lightwork's workspace lock.

## When a transfer fails

An otherwise successful command returns exit code 74 if its files could not be
delivered. A command's existing nonzero status is preserved. Do not rerun a
command with external effects just because file delivery failed.

The error gives a private `sandbox-recovery/k8s-…` directory containing:

- `transfer.json`: original workspace manifest, namespace, context and pod name.
- `input/`: the exact input snapshot, available once execution begins.
- `export.tar`: a complete or partial raw export; treat its contents as untrusted.
- `exported/` and `export.complete`: locally validated output, when export succeeded.
- `originals/`: pre-publication local files, when publication began.

If `export.complete` exists, the pod can be deleted because a validated local
copy is available. Compare `exported/` with the workspace and `originals/`, then
copy reviewed changes into place. Do not blindly restore a whole tree over newer
work. Remove the named recovery directory only after confirming delivery.

If export failed, the pod is retained for recovery. Use the **exact** context,
namespace and pod from `transfer.json`, within one hour of the reported failure:

```sh
kubectl --context YOUR_CONTEXT -n YOUR_NAMESPACE get pod YOUR_POD
kubectl --context YOUR_CONTEXT -n YOUR_NAMESPACE cp YOUR_POD:/workspace/. ./recovered-output
```

Use a new empty recovery directory. `kubectl cp` is a manual recovery aid, not
the application's validated importer; review names, links and file contents
before using them. Omit `--context` when no explicit context was configured.
When recovery is verified, delete the exact pod:

```sh
kubectl --context YOUR_CONTEXT -n YOUR_NAMESPACE delete pod YOUR_POD
```

The pod's active deadline stops its containers after the execution and transfer
budgets plus a one-hour recovery allowance. It does not guarantee retention
through node eviction, cluster deletion or storage failure. If the cluster is
unreachable, stopping background writers also cannot be confirmed; the active
deadline remains the backstop. Expired pod objects may need operator cleanup.
There is no automatic deletion of failed-transfer local recovery directories.

## Limits and deployment qualification

Transfers accept at most 20,000 entries, 64 MiB per file and 512 MiB total file
data. Archive and diagnostic output are bounded while streaming. Use a dedicated
workspace outside any directory containing Lightwork settings, keys or recovery
storage. Linux pods need `sh`, `tar`, `mkdir`, `rmdir`, and a private PID namespace.

The worker's image filesystem is read-only. Its single bounded `emptyDir` at
`/workspace` remains writable. After copying the inputs, each command receives a
fresh private temporary directory inside that volume through `TMPDIR`. Creating
it fails closed if the randomly chosen path already exists. Tools can clear that
directory without treating customer inputs as disposable temporary data. The
image's `HOME` is preserved; no additional home or `/tmp` mount is added. Tools
that write to hard-coded `/tmp` paths or the image's home must be
configured to write inside `/workspace`, or included in the image with the needed
read-only assets. Installation into the image filesystem is not supported.

Use managed temporary files and remove scratch data before a command finishes.
Only the empty, newly allocated directory is removed after a command returns.
There are no reserved customer names, recursive cleanup or export exclusions:
nonempty scratch directories, including those left after interruption, remain
ordinary workspace data and count against transfer limits. This preserves
customer files and recovery output instead of guessing which files are disposable.
The read-only image filesystem is a required security floor for this backend,
not an optional execution capability. Root-filesystem enforcement and
the actual image's shell, archive, Python, cache and temporary-file behavior must
be qualified on the target Linux cluster; synthetic transport tests do not prove
read-only mount enforcement.

Use a dedicated namespace, least-privilege pod/exec permissions and an enforced
deny-all NetworkPolicy when networking is disabled. The API checks cannot prove
the CNI filters live traffic. Before customer use, qualify create/edit/rename/
delete, command timeout, lost export connection and recovery on the actual
cluster; behavior on a live cluster is not qualified.
