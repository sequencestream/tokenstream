# tokenstream

Tokenstream is an MVP-stage design for a high-performance, transparent AI gateway. Its planned scope is native HTTP/SSE and WebSocket forwarding without application-payload parsing, protocol conversion, or stored payloads.

## Core Features

### Fast
- Fully asynchronous Rust and Tokio architecture with no garbage collector.
- Bounded streaming for HTTP request and response bodies; WebSocket messages subject to configured size and connection limits.
- Optimized for high concurrency and long-lived streams with stable, bounded memory.

### Transparent
- Transparent relay of application payloads for OpenAI Chat Completions, OpenAI Responses, and Anthropic Messages.
- Native HTTP, SSE, and WebSocket forwarding without application-payload transformation.
- WebSocket application messages relayed bidirectionally without deserialization.
- The gateway never reads, injects, validates, or rewrites application fields such as `model`, messages, or streaming events.

### Manageable
- Multi-provider configuration with encrypted upstream API keys and provider-scoped gateway credentials.
- Non-blocking transport-layer metadata logging that never stores request or response payloads.
- Minimal administration UI for provider management and request-log queries.

See the [architecture](doc/architecture.md) for binding principles, the [MVP specification](doc/mvp/mvp.md) for scope and acceptance criteria, and the [MVP design](doc/mvp/design.md) for implementation behavior.

## Build and run the scaffold

Requires Rust 1.97 or newer and Node.js 22 or newer. The Rust process exposes independent data-plane and control-plane listeners, each with its own health endpoint and closed-by-default authentication boundary. The administration page is a static scaffold. Provider management and proxy traffic are not available yet.

Development, in separate terminals:

```sh
export TOKENSTREAM_DATA_LISTEN_ADDR=127.0.0.1:3000
export TOKENSTREAM_ADMIN_LISTEN_ADDR=127.0.0.1:3001
export TOKENSTREAM_DATABASE_URL=sqlite://tokenstream.db
export TOKENSTREAM_MASTER_KEY=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
export TOKENSTREAM_ADMIN_PASSWORD_HASH='$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA'
export TOKENSTREAM_UPSTREAM_CONNECT_TIMEOUT_MS=5000
export TOKENSTREAM_UPSTREAM_HEADER_TIMEOUT_MS=30000
export TOKENSTREAM_STREAM_IDLE_TIMEOUT_MS=60000
export TOKENSTREAM_SHUTDOWN_DRAIN_TIMEOUT_MS=30000
export TOKENSTREAM_LOG_FLUSH_TIMEOUT_MS=5000
export TOKENSTREAM_DATABASE_MAX_CONNECTIONS=16
export TOKENSTREAM_MAX_PROXY_CONNECTIONS=4096
export TOKENSTREAM_PASSWORD_MAX_CONCURRENCY=4
export TOKENSTREAM_DATA_MAX_CONNECTIONS=4160
export TOKENSTREAM_ADMIN_MAX_CONNECTIONS=128
export TOKENSTREAM_DOWNSTREAM_HEADER_TIMEOUT_MS=10000
export TOKENSTREAM_ADMIN_BODY_TIMEOUT_MS=30000
export TOKENSTREAM_HTTP_BUFFER_BYTES=65536
export TOKENSTREAM_WEBSOCKET_MAX_FRAME_BYTES=1048576
export TOKENSTREAM_WEBSOCKET_MAX_MESSAGE_BYTES=8388608
export TOKENSTREAM_WEBSOCKET_QUEUE_CAPACITY=32
export TOKENSTREAM_LOG_QUEUE_CAPACITY=8192
export TOKENSTREAM_LOG_BATCH_SIZE=128
export TOKENSTREAM_LOG_BATCH_INTERVAL_MS=100
cargo run --locked
cd web && npm ci && npm run dev
```

The data-plane and control-plane health endpoints are `http://127.0.0.1:3000/healthz` and `http://127.0.0.1:3001/healthz`. Vite prints the local address of the administration page. Startup migrations finish before either listener binds. On shutdown, both listeners stop accepting immediately and active connections drain only up to the configured timeout.

Password hashing and verification run on a dedicated blocking budget of at most `TOKENSTREAM_PASSWORD_MAX_CONCURRENCY` concurrent computations shared by administration sign-in, credential issuance, credential rotation, and gateway verification. Admission never queues: when the budget is exhausted the request is rejected, and a request that is cancelled while its computation runs keeps holding capacity until that computation finishes, so slow hashing cannot block traffic that is already streaming. `TOKENSTREAM_DATA_MAX_CONNECTIONS` and `TOKENSTREAM_ADMIN_MAX_CONNECTIONS` bound the accepted connections of each plane; the data plane defaults to the proxy capacity plus an overload-rejection margin and never accepts a value below it. `TOKENSTREAM_HTTP_BUFFER_BYTES` also bounds each connection's actual read chunk and upstream read buffer, and `TOKENSTREAM_DOWNSTREAM_HEADER_TIMEOUT_MS` and `TOKENSTREAM_ADMIN_BODY_TIMEOUT_MS` bound unfinished request headers and management bodies. Each of these settings, and every setting above, is required or defaulted and validated before the process listens. The master key is exactly 32 bytes encoded as 64 hexadecimal characters, and the administrator hash must use Argon2id. Secrets are accepted only through the environment (or an environment populated by a secret manager), never command-line flags.

Production build and launch of the current scaffold:

```sh
cargo build --release --locked
cd web && npm ci && npm run check && npm run build
../target/release/tokenstream
```

The compiled frontend is in `web/dist/`. It is not served by the Rust process yet. Basic checks are `cargo fmt --check`, `cargo clippy --locked --all-targets -- -D warnings`, `cargo test --locked`, and, in `web/`, `npm run check` and `npm run build`.
