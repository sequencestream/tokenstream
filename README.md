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

Requires Rust 1.97 or newer and Node.js 22 or newer. The Rust process currently exposes only a loopback health endpoint; the administration page is a static scaffold. Provider management and proxy traffic are not available yet.

Development, in separate terminals:

```sh
cargo run --locked
cd web && npm ci && npm run dev
```

The health endpoint is `http://127.0.0.1:3000/healthz`. Vite prints the local address of the administration page.

Production build and launch of the current scaffold:

```sh
cargo build --release --locked
cd web && npm ci && npm run check && npm run build
../target/release/tokenstream
```

The compiled frontend is in `web/dist/`. It is not served by the Rust process yet. Basic checks are `cargo fmt --check`, `cargo clippy --locked --all-targets -- -D warnings`, `cargo test --locked`, and, in `web/`, `npm run check` and `npm run build`.
