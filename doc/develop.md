# Development

Requires Rust 1.97 or newer and Node.js 22 or newer. The process exposes independent data-plane and control-plane listeners, each with its own health endpoint and closed-by-default authentication boundary. The control-plane listener also serves the compiled administration page, so the page and its API share one origin and the session cookie and CSRF protection work without exceptions.

Design constraints and public contracts are in the [architecture document](./architecture.md). Module procedures are under [modules](./modules/).

## Build

Compile a release binary and the administration page:

```sh
./scripts/build.sh
```

The release binary is `target/release/tokenstream` and the compiled page is `web/dist`.

## Local development

Every setting has a compiled default, so the gateway starts with no Tokenstream-specific environment. Listeners bind `127.0.0.1:3300` and `127.0.0.1:3301`. SQLite, the generated master key, and the administrator password hash live under `~/.tokenstream` unless `TOKENSTREAM_DATA_DIR` is set. The default administrator password is `tokenstream`; change it from the administration page after sign-in. Loopback listeners default development mode to on so a plaintext local origin can keep a session cookie.

Run the gateway and the administration development server in separate terminals:

```sh
cargo run --locked
```

```sh
cd web && npm ci && npm run dev
```

The data-plane and control-plane health endpoints are `http://127.0.0.1:3300/healthz` and `http://127.0.0.1:3301/healthz`. The administration development server prints the local address of the page. In development that server serves the page and proxies the administration API, health, and metrics paths to the control plane, so the page issues same-origin requests and needs no separate origin configuration; set `TOKENSTREAM_ADMIN_PROXY_TARGET` when the control plane is not on `http://127.0.0.1:3301`. Environment values override files and defaults. `TOKENSTREAM_DEVELOPMENT_MODE=false` is required when the control plane is not a plaintext loopback origin. Startup migrations finish before either listener binds, and a configured page directory is confirmed to hold a built entry document before either listener binds. On shutdown, both listeners stop accepting immediately and active connections drain only up to the configured timeout.

## Settings

Password hashing and verification run on independent, non-queueing data-plane and control-plane budgets whose sizes sum to at most `TOKENSTREAM_PASSWORD_MAX_CONCURRENCY`. The control plane reserves `TOKENSTREAM_ADMIN_PASSWORD_CONCURRENCY` slots (default 1) and the data plane receives the remainder, so a burst of sign-ins or credential rotations cannot consume gateway verification capacity. Admission never queues: when a plane's budget is exhausted the request is rejected with `503 resource_exhausted`, and a request that is cancelled while its computation runs keeps holding capacity until that computation finishes, so slow hashing cannot block traffic that is already streaming. Authentication lookups may reserve `TOKENSTREAM_AUTH_DATABASE_CONNECTIONS` pooled connections inside `TOKENSTREAM_DATABASE_MAX_CONNECTIONS`. Authentication queries, administration statements, and log batches each have their own execution deadline (`TOKENSTREAM_AUTH_DB_TIMEOUT_MS`, `TOKENSTREAM_ADMIN_DB_TIMEOUT_MS`, `TOKENSTREAM_LOG_DB_TIMEOUT_MS`); a deadline cancels the operation, rolls back an open transaction, and returns the connection to the pool without delaying proxy streaming. `TOKENSTREAM_DATA_MAX_CONNECTIONS` and `TOKENSTREAM_ADMIN_MAX_CONNECTIONS` bound the accepted connections of each plane; the data plane defaults to the proxy capacity plus an overload-rejection margin and never accepts a value below it. Idle HTTP connections to an upstream origin are capped by `TOKENSTREAM_UPSTREAM_IDLE_PER_HOST` (default 8; 0 disables reuse) and reaped after `TOKENSTREAM_UPSTREAM_POOL_IDLE_TIMEOUT_MS`, so a changing endpoint cannot retain sockets indefinitely. Each request still looks up its credential and replaces the upstream authentication header; a cancelled or failed exchange is never retried onto another connection. `TOKENSTREAM_HTTP_BUFFER_BYTES` also bounds each connection's actual read chunk and upstream read buffer, and `TOKENSTREAM_DOWNSTREAM_HEADER_TIMEOUT_MS` and `TOKENSTREAM_ADMIN_BODY_TIMEOUT_MS` bound unfinished request headers and management bodies. Each of these settings, and every setting above, is defaulted or overridden and validated before the process listens. The master key is exactly 32 bytes encoded as 64 hexadecimal characters, and the administrator hash must use Argon2id. Secrets are accepted through the environment (or an environment populated by a secret manager) or as files in the data directory, never command-line flags. After sign-in, the administration page can change settings; the password and master key apply immediately, and bind-time settings apply on the next start.

## Production launch

After a release build:

```sh
./target/release/tokenstream
```

When `TOKENSTREAM_ADMIN_STATIC_ROOT` is unset, the process serves a compiled page from `admin/` next to the executable, or from `web/dist` in the working directory, if either contains an entry document. The control-plane listener serves that entry document and its `assets/` files and nothing else, with a strict content security policy, `nosniff`, `no-referrer`, and no-store on the entry document so a redeploy is picked up on the next navigation. Administration JSON responses, including errors and empty success bodies, also send `Cache-Control: no-store`; hashed page assets keep their own long-lived cache policy. When no page directory is found, only the administration API is served. In production, terminate TLS in front of the control plane and keep the page and the API on that one origin: the session cookie is `HttpOnly`, `SameSite=Strict`, and `Secure` in production. A development deployment over plaintext has no secure origin to hold the cookie on and drops only the `Secure` attribute; every other restriction stays. Sessions last 15 minutes unless `TOKENSTREAM_ADMIN_SESSION_TTL_MS` is set.

GitHub Release archives place the compiled page next to the binary in an `admin/` directory, which the process serves automatically.

## Verification

Basic checks are `cargo fmt --check`, `cargo clippy --locked --all-targets -- -D warnings`, `cargo test --locked`, and, in `web/`, `npm run check`, `npm run test`, and `npm run build`. Dual-backend repository tests need a PostgreSQL server through `TOKENSTREAM_TEST_POSTGRES_URL`; absence is a failure, not a skip.

The release gate runs the full verification set: formatting and strict static analysis, the unit, repository, protocol, and security suites, a fast component load profile, a sustained mixed load profile measured against a real gateway process, the administration frontend checks and production build, real-browser administration acceptance against both the control-plane hosted page and the development-server proxy, the pinned client suite, and the pinned clients driven through a real gateway process. The gate provisions an ephemeral PostgreSQL server when one is not supplied through `TOKENSTREAM_TEST_POSTGRES_URL`, and fails rather than skipping when no server is available. A supplied server that is not reachable is a gate failure, not a reason to record the dual-backend layers as unexecuted, and the storage layers themselves report a missing server as a failure rather than skipping.

```sh
./scripts/release-gate.sh
```

The real-process stages start the compiled binary, configure providers through the administration API, and measure the gateway's own resource use:

- The gateway load profile drives documented default-hashing and declared-admission profiles through the formal listeners, samples success and rejection rates, latency percentiles, resident memory, and file descriptors, compares bounded HTTP connection reuse against no reuse, and exercises slow consumers, authentication pressure, logging saturation, a slow database, bounded capacity, and a storage fault.
- The pinned-client gateway suite runs the pinned OpenAI and Anthropic SDKs and the pinned Codex CLI through the production entry points, including a WebSocket success path and the client's own fallback when the upstream refuses the handshake, and requires every route to be refused when no gateway is listening.

## Continuous integration

Pull requests and pushes run the CI workflow: formatting, Clippy, the locked test suite (including dual-backend layers against PostgreSQL and real-browser administration acceptance), and the administration frontend checks and production build.

## GitHub Release

A GitHub Release is created from the Release workflow. Run it manually, enter a version such as `0.1.0`, and the workflow verifies the tree, builds the administration page once, and packages native binaries for:

- Linux amd64 and arm64
- macOS amd64 and arm64
- Windows amd64

Each archive contains the gateway binary and the compiled administration page under `admin/`. The workflow tags `v<version>` from the selected branch and attaches the archives plus SHA-256 checksums. A version that is already tagged is rejected.
