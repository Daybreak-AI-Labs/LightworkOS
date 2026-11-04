# Project workspaces

Enable **Project workspaces** in deployment Settings, or opt in during the installer's advanced setup. A workspace can disable the feature within that deployment ceiling. Open **Projects → Project outcomes and milestones** or **Open project workspace** from an existing project. No existing tasks, task owners, execution graph, or review packets are replaced.

The project owner defines an outcome, acceptance criteria, labels and a default list, board or timeline view. Milestones link actual tasks or fixed review packets selected from the owner's currently permitted project work. A task reaching `done` is presented as **work complete**. **Accepted** requires a current independently approved review. The latest accepted deliverable is projected only from review packets the viewer can currently read; later source changes invalidate that acceptance projection.

Milestone ordering changes presentation. Planning prerequisites are separate explicit, reviewed operations with cycle rejection; they never edit execution dependencies or start work. Target dates sort the timeline. The board groups milestones by the current observed outcome state. Personal reusable structures copy outcome wording, criteria, labels, view and milestone names. They exclude people, source references, target dates and dependency edges, and can only populate a project without existing milestones.

## Sharing and sources

Project planning membership is a separate, deliberate metadata-only grant. Existing review-team membership does not grant planning access. The owner selects named current workspace colleagues and reviews the sharing scope before saving. Removing a grant, losing workspace/suite permission, deactivation, a tenant change, project retirement or project ownership change makes the old grant unavailable. A planning member cannot edit, execute or open someone else's task, chat or artifacts. Fixed review packets retain their original exact-owner/assigned-reviewer access.

The context bundle stores references to reviewed versions of saved task results or authorized fixed review packets. Source content is never copied into the shared metadata record. Each open checks current project access, independent source authority and the pinned source version. Changed or revoked sources require an owner review or are hidden. Attaching a source does not send it to a model, run a task, or grant its private contents to planning members.

## Save and recovery behavior

Native and Copilot controls use the same typed planning service, current authority, revision checks and durable request receipts. The UI shows the exact before/after change and requires a separate confirmation. Unsaved outcome and milestone editors keep their contents across status refreshes and use the existing encrypted account/workspace draft recovery service. No project contents are placed in local storage.

Each request has an owned 20-second wait and a Stop waiting control. Stopping a wait does not imply a server save was cancelled. An uncertain save blocks new changes until the exact receipt is checked, or the user explicitly retries that same reviewed request identity. It is never automatically resent. A successful earlier save cannot clear a newer draft typed while the request was pending. Current account/context changes close the private projection and clear editor plaintext; encrypted recovery remains governed by its original owner and context.

Copilot exposes status, outcomes, milestone editing/removal/order/prerequisites, context attachment/removal, planning grants and personal reusable structures under the existing administrator-controlled **reviews** family. It uses named choices and typed multiple-selection controls. A source exceeding 12,000 characters must be fully reviewed in the native source editor; no truncation or hidden model input is used.

## Operational limits and validation

The implementation uses the existing tenant-scoped governed-record backend, encryption, monotonic revisions and durable audit outbox. Enterprise/shared deployments retain that backend's fail-closed Postgres requirement. Local change serialization uses a strict per-project process/file lock; defaults copied from a project use a source revision fence on Postgres. Existing-project identity includes its original owner and creation time. No schema migration is required.

Per workspace: 100 planning members, 100 milestones, 50 linked task/review references per milestone, 100 context sources, 30 criteria and 20 labels. Ordinary change receipts are retained up to 2,000 operations, after which new changes close while existing grants can still be revoked. No receipt eviction permits replay. The selection controls explicitly show the latest 500 permitted project tasks. Namespace listings are bounded to 10,000 records and report overflow rather than silently returning a complete-looking result.

Multi-process failure handling on PostgreSQL, full browser rendering, assistive technology and cross-device visual behavior are not qualified.
