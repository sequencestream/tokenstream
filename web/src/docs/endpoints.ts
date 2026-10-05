// The static copy of the data-plane public contract the Docs view shows.
//
// The architecture document holds the authoritative route allowlist. This table
// repeats it so a credential holder can find it without reading developer
// material; the unit test pins the rows so an allowlist change that skips this
// view fails the page build rather than shipping stale addresses.

export type ProtocolType = 'openai' | 'anthropic'

export interface EndpointRow {
  protocol: ProtocolType
  method: string
  path: string
  auth: string
  transport: string
}

/** The placeholder every example writes in place of this instance's host. */
export const BASE_URL_PLACEHOLDER = '<base-url>'

/** The placeholder every example writes in place of an issued credential. */
export const CREDENTIAL_PLACEHOLDER = '<key-id>.<secret>'

export const ENDPOINTS: EndpointRow[] = [
  {
    protocol: 'openai',
    method: 'POST',
    path: '/v1/chat/completions',
    auth: 'Authorization: Bearer',
    transport: 'HTTP / SSE',
  },
  {
    protocol: 'openai',
    method: 'POST',
    path: '/v1/responses',
    auth: 'Authorization: Bearer',
    transport: 'HTTP / SSE',
  },
  {
    protocol: 'openai',
    method: 'GET',
    path: '/v1/responses',
    auth: 'Authorization: Bearer',
    transport: 'WebSocket',
  },
  {
    protocol: 'anthropic',
    method: 'POST',
    path: '/v1/messages',
    auth: 'x-api-key',
    transport: 'HTTP / SSE',
  },
]

export const PROTOCOL_LABELS: Record<ProtocolType, string> = {
  openai: 'OpenAI',
  anthropic: 'Anthropic',
}

/** A shell line continuation, so a copied example stays one command. */
const LINE_CONTINUATION = ' \\' + '\n'

export interface CurlExample {
  id: string
  title: string
  command: string
}

/**
 * One runnable example per allowed endpoint, built from the pinned table so an
 * address change can never leave one example describing an older route.
 *
 * The credential is always the placeholder pair, so nothing here can leak or
 * require a real secret to run. Lines carry no trailing backslash: the join
 * supplies exactly one continuation between them.
 */
export function curlExamples(): CurlExample[] {
  const example = (id: string, title: string, lines: string[]) => ({
    id,
    title,
    command: lines.join(LINE_CONTINUATION),
  })
  return [
    example('chat-completions', 'OpenAI — Chat Completions', [
      `curl ${BASE_URL_PLACEHOLDER}/v1/chat/completions`,
      `  -H "Authorization: Bearer ${CREDENTIAL_PLACEHOLDER}"`,
      '  -H "Content-Type: application/json"',
      `-d '{"model":"gpt-4.1-mini","messages":[{"role":"user","content":"ping"}]}'`,
    ]),
    example('responses', 'OpenAI — Responses', [
      `curl ${BASE_URL_PLACEHOLDER}/v1/responses`,
      `  -H "Authorization: Bearer ${CREDENTIAL_PLACEHOLDER}"`,
      '  -H "Content-Type: application/json"',
      `-d '{"model":"gpt-4.1-mini","input":"ping"}'`,
    ]),
    example('messages', 'Anthropic — Messages', [
      `curl ${BASE_URL_PLACEHOLDER}/v1/messages`,
      `  -H "x-api-key: ${CREDENTIAL_PLACEHOLDER}"`,
      '  -H "Content-Type: application/json"',
      `-d '{"model":"claude-sonnet-4-5","max_tokens":64,"messages":[{"role":"user","content":"ping"}]}'`,
    ]),
  ]
}

export interface TroubleshootingNote {
  symptom: string
  cause: string
}

export const TROUBLESHOOTING: TroubleshootingNote[] = [
  {
    symptom: '401',
    cause: 'The credential is wrong, expired, disabled, or sent in the wrong header. OpenAI routes take Authorization: Bearer; Anthropic routes take x-api-key.',
  },
  {
    symptom: '404',
    cause: 'The protocol and the path do not match. Each protocol answers only its own allowed paths, and a path valid for one protocol is rejected when presented to another.',
  },
  {
    symptom: '503, or no upstream at all',
    cause: 'The selected provider is unavailable or in maintenance. The request is refused rather than rerouted to another provider, so a retry reaches the same provider again.',
  },
]

export const BASE_URL_NOTE =
  `The addresses below are this instance's data-plane listen address, written as ${BASE_URL_PLACEHOLDER}. ` +
  'Replace it with the host you were given, together with its port when the port is not the default.'

export const WEBSOCKET_NOTE =
  'The WebSocket route upgrades the same GET path. Send the Bearer credential in the upgrade request; the payload is relayed message by message and is never parsed.'
