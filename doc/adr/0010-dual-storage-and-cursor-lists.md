# 0010. Dual storage and cursor lists

- Status: Accepted
- Date: 2026-09-29

## Context

Administration lists can use page numbers and offsets, or an increasing primary-key cursor. Offsets are familiar, but they skip and duplicate rows under concurrent writes and they hide a total-page count that Tokenstream does not want to promise.

Storage can be a single engine or two engines with equivalent behavior. SQLite is enough for development. Production needs PostgreSQL. Divergent uniqueness, time, or deletion rules would make one backend a lie.

Provider rows can be deleted freely, or they can be pinned by request-log association so history is not silently reparented.

## Decision

SQLite and PostgreSQL provide equivalent behavior. Provider and request-log primary keys are database-generated, increasing positive integers. Lists use `id > after_id` with a bounded `limit`, never page numbers, offsets, or total-page counts. Timestamps use UTC.

The internal request ID is generated before logging and remains separate from the request-log row ID, because best-effort logging may drop a row ([ADR 0005](./0005-best-effort-metadata-logging.md)). Request logs retain their provider association, so a referenced provider cannot be deleted; disabling is the normal retirement operation.

The data model is in the [architecture document](../architecture.md). Write rules are in the [providers design](../modules/providers.md). Filter-and-cursor pairing on the page is in the [administration design](../modules/administration.md).

## Consequences

- Filter values stay fixed while advancing a cursor. Changing filters restarts from the beginning. A half-edited form must never combine one condition set with another set's cursor.
- The cursor is for list navigation, not a guaranteed change feed under concurrent writes.
- Delete of a referenced provider returns `409` with `provider_in_use`.
