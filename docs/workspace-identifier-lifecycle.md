# Workspace identifiers and retained data

A workspace identifier belongs to one workspace incarnation. Deleting a
workspace never releases that identifier, even when its data directory is
purged. Suspending and resuming an existing workspace preserves its identity.

For a new workspace, enter its display name in the workspace creation form.
Lightwork chooses an unused identifier, adding a numeric suffix when needed.
An explicit identifier supplied through the API or CLI is refused if it was
previously used. The same rule applies to case aliases and equivalent Unicode
spellings. SCIM reprovisioning creates a new UUID and does not adopt the old
workspace's contents or memberships.

Existing active workspaces remain usable. On upgrade, an orphan data directory,
namespace reservation, or global membership entry is treated as retained
history. Creating a workspace cannot claim that history. Unreadable membership
history blocks new provisioning until an operator resolves the storage problem.
Roles are neither erased nor reassigned to make an identifier available.

An interrupted setup can reserve a name without publishing a usable workspace.
Retry with a display name to receive a fresh identifier. An uncertain SCIM
creation leaves its reservation for operator review; compensation only removes
the incarnation whose creation returned successfully.

Retained-data recovery is separate from new provisioning. Review the original
workspace and its authority through the recovery process before reading or
restoring retained state. Removing lifecycle files to reuse an identifier is
unsupported and can reattach old data or memberships. The installation-level
`.tenant-namespaces` reservations and `.tenant-deletions` tombstones must be
preserved with the control-plane backup. Tombstones also deny admission when an
older roster still contains a deleted workspace or the roster is missing.
