# tokenstream

Tokenstream is a high-performance, transparent AI gateway. It provides native HTTP/SSE and WebSocket forwarding without application-payload parsing, protocol conversion, or stored payloads.

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
- Minimal administration UI for provider management, request-log queries, and process settings.

See the [architecture](doc/architecture.md) for binding principles, contracts, and verification, the [module designs](doc/modules/) for how each module works, and the [architecture decisions](doc/adr/) for why those rules were chosen.

## Build

Requires Rust 1.97 or newer and Node.js 22 or newer.

```sh
make build
```

That compiles the release binary, including the administration page. `make` lists lint, test, and verification shortcuts. Local development, environment settings, production launch, tests, and publishing a GitHub Release are in the [development guide](doc/develop.md).

Prebuilt binaries for Linux, macOS, and Windows are attached to GitHub Releases.
