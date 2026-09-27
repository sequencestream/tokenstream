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
