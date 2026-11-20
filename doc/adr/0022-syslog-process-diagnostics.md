# 0022. Readable lines for process diagnostics

- Status: Accepted
- Date: 2026-11-20

## Context

Process diagnostics are the lines an operator reads on standard error while starting or running the gateway. A JSON object hides the sentence behind braces. An RFC 5424 line keeps a priority, a process id, and a structured-data element, and the sentence is still not the first thing a person sees.

The line has to stay one record per event, with the closed level, target, event name, constant sentence, and audited context. The one-time bootstrap credential on standard output stays JSON because a program reads that record once.

## Decision

Each process diagnostic is one plain line on standard error. The pre-subscriber fatal writer uses the same line.

```text
2026-11-20T01:20:00.123456Z ERROR [tokenstream::process] - Tokenstream failed to start. | event: process_start_failed | stage: database_connection | error_kind: storage_unavailable
```

- The timestamp is UTC, with microsecond resolution. One space separates it from the level.
- The level is the textual name: `ERROR`, `WARN`, `INFO`, `DEBUG`, or `TRACE`.
- The target is in brackets.
- A space, a hyphen, and a space introduce the constant sentence.
- Fields follow the sentence, separated by ` | `, each written as `key: value`. The first field is the stable event name. Audited context that applies follows, in this order: `stage`, `error_kind`, `backend`, `operation`, `subscriber`, `data_address`, `control_address`, `configured`, `setting`, `requirement`. Absent context is omitted.
- The safety gate, the verbosity filter, and the exclusion of secrets are unchanged.

## Consequences

- A collector that assumed JSON or RFC 5424 on standard error must read this line instead.
- The one-time bootstrap credential on standard output stays a separate JSON record. It is not a diagnostic.
