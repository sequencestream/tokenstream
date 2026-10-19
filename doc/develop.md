# Development

## Prerequisites

| Tool | Version / requirement |
| --- | --- |
| Rust | 1.97+ |
| Node.js | 22+ |
| PostgreSQL | Required for dual-backend tests; the release gate can provision a temporary server using local PostgreSQL tools or Docker |

Run commands from the repository root unless stated otherwise.

## Local development

1. Start the gateway in terminal 1. No Tokenstream environment variables are required.

   ```sh
   cargo run --locked
   ```

2. Start the administration development server in terminal 2.

   ```sh
   cd web
   npm ci
   npm run dev
   ```

3. Open the page URL printed by the development server. Sign in and change the default password.

   | Item | Default |
   | --- | --- |
   | Administrator name | `admin` |
   | Administrator password | `tokenstream` |
   | Data plane | `http://127.0.0.1:3300` |
   | Control plane / compiled administration page | `http://127.0.0.1:3301` |
   | Data directory | `~/.tokenstream` (SQLite, master key, administrator password hash) |

4. Check both listeners.

   ```sh
   curl --fail http://127.0.0.1:3300/healthz
   curl --fail http://127.0.0.1:3301/healthz
   ```

Stop the gateway with `Ctrl+C`. Both listeners stop accepting connections; active work drains up to the configured timeout.

The development server proxies `/admin/api`, `/healthz`, and `/metrics` to the control plane. To use a different control-plane address, run this from `web`:

```sh
TOKENSTREAM_ADMIN_PROXY_TARGET=http://127.0.0.1:4301 npm run dev
```

## Settings

All settings have defaults. Environment values override saved settings and defaults. Sign in as an administrator and open Settings to view or change process settings.

### Common parameters

| Environment variable | Default / format | Purpose |
| --- | --- | --- |
| `TOKENSTREAM_DATA_DIR` | `~/.tokenstream` | Persistent local data |
| `TOKENSTREAM_DATA_LISTEN_ADDR` | `127.0.0.1:3300` | Data-plane listener |
| `TOKENSTREAM_ADMIN_LISTEN_ADDR` | `127.0.0.1:3301` | Control-plane listener |
| `TOKENSTREAM_DATABASE_URL` | SQLite in the data directory | SQLite or PostgreSQL connection |
| `TOKENSTREAM_BOOTSTRAP_ACCOUNT` | `admin` | Initial administrator name |
| `TOKENSTREAM_ADMIN_PASSWORD` | `tokenstream` on first setup | Bootstrap password |
| `TOKENSTREAM_ADMIN_PASSWORD_HASH` | Argon2id hash | Bootstrap password hash |
| `TOKENSTREAM_MASTER_KEY` | Generated and saved on first setup; 64 hex characters (32 bytes) | Upstream-secret encryption |
| `TOKENSTREAM_DEVELOPMENT_MODE` | `true` when both listeners use loopback | Allow a session cookie over local plaintext HTTP |
| `TOKENSTREAM_ADMIN_SESSION_TTL_MS` | `900000` (15 minutes) | Session lifetime |
| `TOKENSTREAM_LOG_FILTER` | `info`; e.g. `warn` or `tokenstream::process=debug,tokenstream::persistence=warn` | Process diagnostic verbosity; restart required |
| `TOKENSTREAM_ADMIN_PROXY_TARGET` | `http://127.0.0.1:3301` | Development-server proxy target only |

Example: change local ports and data directory.

```sh
TOKENSTREAM_DATA_DIR="$HOME/.tokenstream-dev" \
TOKENSTREAM_DATA_LISTEN_ADDR=127.0.0.1:4300 \
TOKENSTREAM_ADMIN_LISTEN_ADDR=127.0.0.1:4301 \
cargo run --locked
```

- Supply secrets through environment variables, a secret manager, or files in the data directory; never through command-line flags.
- Settings-page changes to the password and master key apply immediately. Bind-time settings apply after restart; the page marks settings that require one.
- Invalid settings, secrets, migrations, or a missing compiled administration page prevent startup.

### Resource limits and timeouts

Keep defaults for local development. Change these only when tuning capacity; all are validated before startup. Timeout values are in milliseconds.

| Parameter | Controls / constraint |
| --- | --- |
| `TOKENSTREAM_PASSWORD_MAX_CONCURRENCY` | Total password-work budget across both planes |
| `TOKENSTREAM_ADMIN_PASSWORD_CONCURRENCY` | Control-plane reservation (default `1`); data plane gets the remainder |
| `TOKENSTREAM_DATABASE_MAX_CONNECTIONS` | Database pool size |
| `TOKENSTREAM_AUTH_DATABASE_CONNECTIONS` | Authentication reservation within that pool |
| `TOKENSTREAM_AUTH_DB_TIMEOUT_MS` | Authentication query deadline |
| `TOKENSTREAM_ADMIN_DB_TIMEOUT_MS` | Administration statement deadline |
| `TOKENSTREAM_LOG_DB_TIMEOUT_MS` | Request-log batch deadline |
| `TOKENSTREAM_MAX_PROXY_CONNECTIONS` | Proxy admission limit |
| `TOKENSTREAM_DATA_MAX_CONNECTIONS` | Accepted data-plane connections; must exceed proxy capacity |
| `TOKENSTREAM_ADMIN_MAX_CONNECTIONS` | Accepted control-plane connections |
| `TOKENSTREAM_UPSTREAM_IDLE_PER_HOST` | Idle upstream connections per origin (default `8`; `0` disables reuse) |
| `TOKENSTREAM_UPSTREAM_POOL_IDLE_TIMEOUT_MS` | Idle upstream connection lifetime |
| `TOKENSTREAM_HTTP_BUFFER_BYTES` | HTTP read chunks and upstream read buffer |
| `TOKENSTREAM_DOWNSTREAM_HEADER_TIMEOUT_MS` | Request-header deadline |
| `TOKENSTREAM_ADMIN_BODY_TIMEOUT_MS` | Administration request-body deadline |
| `TOKENSTREAM_LOG_QUEUE_CAPACITY` | Request-log subscriber queue size |

Exhausted hashing capacity rejects new work with `503 resource_exhausted`; it does not queue. A full or stopped log subscriber drops its own events without changing the proxy result. See [Process](./modules/process.md), [Events](./modules/events.md), and [Logging](./modules/logging.md) for behavior and bounds.

### Diagnostic output

| Stream | Content | Handling |
| --- | --- | --- |
| Standard error | One JSON diagnostic per line: `timestamp`, `level`, `target`, `fields`; stable `event` and `message` in `fields` | Collect as process logs |
| Standard output | One generated bootstrap-password record, only when needed and the account is first created | Capture securely on first production start |

Default and explicitly supplied passwords are never printed. A generated password is not printed again on restart. Diagnostic filters select only audited Tokenstream events; dependency and unknown targets stay excluded. Empty or invalid filters prevent startup without echoing the value.

## Build and production launch

1. Build the release binary with the administration page included.

   ```sh
   make build
   ```

2. Configure production secrets and set `TOKENSTREAM_DEVELOPMENT_MODE=false`.
3. Terminate TLS in front of the control plane. Keep the administration page and API on the same origin.
4. Start the gateway.

   ```sh
   TOKENSTREAM_DEVELOPMENT_MODE=false ./target/release/tokenstream
   ```

The administration page is served by the control-plane listener. Production session cookies use `HttpOnly`, `SameSite=Strict`, and `Secure`. Administration JSON responses and the page entry document are not cached; hashed assets use long-lived caching.

## Verification

### During development

| Command | Checks |
| --- | --- |
| `make` | List available commands |
| `make lint` | Rust formatting, strict Clippy, frontend typecheck |
| `make arch-check` | Production module classification and dependency boundaries; no external service required |
| `make test` | Locked Rust test suite; PostgreSQL required |
| `make test-web` | Administration frontend unit tests |
| `make test-compat` | Pinned client compatibility |
| `make ci` | Frontend dependency install, typecheck, tests and build; Rust formatting, Clippy, architecture checks and tests |

Install frontend dependencies before individual lint or frontend test commands:

```sh
npm --prefix web ci
```

For `make test` or `make ci`, supply a reachable PostgreSQL server:

```sh
export TOKENSTREAM_TEST_POSTGRES_URL='postgres://postgres:postgres@127.0.0.1:5432/postgres'
make ci
```

Missing or unreachable PostgreSQL fails verification; dual-backend tests are never skipped.

### Before release

Install the browser used by administration acceptance tests, then run the full gate:

```sh
npm --prefix web ci
npm --prefix web exec -- playwright install chromium
make gate
```

The gate uses `TOKENSTREAM_TEST_POSTGRES_URL` when set. Otherwise it provisions temporary PostgreSQL using local tools or Docker; absence of either fails the gate.

The gate covers:

- Formatting, strict static analysis, architecture boundaries, frontend checks and production build.
- Unit, SQLite/PostgreSQL repository, HTTP/SSE, WebSocket, and security tests.
- Component and real-process mixed load: latency, success/rejection rates, memory, file descriptors, connection reuse, slow consumers, authentication pressure, and storage faults.
- Real-browser administration acceptance through both the hosted page and development proxy.
- Pinned OpenAI and Anthropic SDKs and Codex CLI, both against a mock upstream and through the real gateway, including WebSocket and client-owned fallback.

Full acceptance criteria: [Architecture verification](./architecture.md#12-verification).

## Continuous integration

Pull requests and pushes to `develop` or `main` run CI: frontend checks and build, formatting, Clippy, architecture checks, and the locked test suite, including PostgreSQL and browser acceptance.

## GitHub Release

1. Run `make gate` and resolve failures.
2. In GitHub, open **Actions → Release → Run workflow**.
3. Select the branch and enter a new version, such as `0.1.0`. Enable `prerelease` if needed.
4. Run the workflow. It verifies the tree, builds, tags `v<version>`, and publishes archives with SHA-256 checksums. Existing tags are rejected.

| Platform | Architectures |
| --- | --- |
| Linux | amd64, arm64 |
| macOS | amd64, arm64 |
| Windows | amd64 |

Each archive contains one gateway binary with the administration page included.

Design reference: [Architecture](./architecture.md), [module designs](./modules/), and [ADRs](./adr/).
