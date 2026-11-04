# Shared fact tags and migration 43

Migration 43 adds a tags_json metadata column to the existing tenant-scoped facts table on SQLite and PostgreSQL. Existing rows receive an empty list. No fact values or historical versions are rewritten or decrypted by the migration; tags are shared business metadata and never grant access. Normal value edits preserve tags. Tag edits use the same optimistic fact revision, advancing the logical write clock atomically.

Enable Organize shared facts with tags in Settings, Memory & learning, or choose it during installation. Operators edit tags from a fact's details; viewers can filter. Private personal/task namespaces remain excluded before pagination. Name/source/date/tag filters run in the database and only the bounded returned page decrypts values. Page sequences bind the active account/workspace, exact filters, and shared-fact revision, rejecting concurrent changes instead of silently skipping rows.

The migration only adds a column. Disable the feature to stop new tag edits; existing facts remain usable and tagged metadata stays stored. Do not drop the column or lower the schema version during rollback. Older binaries reject newer schemas by design; roll forward with a compatible build, or restore the verified pre-upgrade backup with the corresponding old binary. Restoring a backup loses subsequent writes and requires the ordinary administrator backup/recovery review.

Filtering is bounded by page, so large fact tables are read one page at a time. A live PostgreSQL service and the interactive browser journey are not qualified.
