# Shared fact controls

Facts offers native search, current detail/history, editing, tags, restoration and removal. When an administrator enables Copilot actions and its existing **learning** family, the same operations are available from Copilot on `/facts`. Tag writes also require the existing **Memory & learning → fact tags** setting; its installer choice remains authoritative.

Open **Details and history** or **Edit** to select one exact fact for Copilot. Explicit multi-selection permits read-only review. Search uses current server pages of 50 shared fact records, with name, source, tag and UTC date filters. Personal and task namespaces are excluded before results and history are returned. Each separately requested Copilot results page starts a fresh authorized view; native Facts paging provides a continuous revision-bound sequence.

Changes require the current workspace, named or local actor's native operate permission, the exact reviewed selection and database revision. Restoration writes a new version. Removal stops future recall; retained history still follows workspace policy. No individual expiry is invented where the store does not record one.

The `fact_operation_receipts` governed namespace records only actor, a review digest and outcome/revision metadata. It retains no fact names or values. A durable receipt precedes each effect; an interrupted or unaudited attempt remains unconfirmed and is never automatically dispatched again. A completed create cannot recreate a subsequently deleted fact when its old review is retried. A completed removal remains recoverable when its selected fact no longer exists. A receipt confirms its historical attempt, not the current value after later edits.

These minimal replay barriers are disclosed as retained evidence in My Data and are not automatically erased or expired. The store is bounded to 10,000 receipts; capacity or unavailable storage refuses new admission rather than evicting replay protection. Restored authority must remain held under the installation recovery policy before admitting new actions. No source contents or credentials are added to audit events, and no provider call is required.

PostgreSQL execution and installed-browser accessibility are not qualified.
