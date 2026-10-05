// Pins the Docs view's copy of the public data-plane contract.
//
// The route allowlist lives in the architecture document; the page repeats it for
// credential holders. These assertions are the only thing that makes the repeat
// safe, so they are written as literal expectations: an allowlist change that
// does not also update the page fails here.
import assert from 'node:assert/strict'
import { test } from 'node:test'

import {
  BASE_URL_PLACEHOLDER,
  CREDENTIAL_PLACEHOLDER,
  ENDPOINTS,
  TROUBLESHOOTING,
  curlExamples,
} from './endpoints.ts'

test('the endpoint table is exactly the public allowlist', () => {
  assert.deepEqual(ENDPOINTS, [
    { protocol: 'openai', method: 'POST', path: '/v1/chat/completions', auth: 'Authorization: Bearer', transport: 'HTTP / SSE' },
    { protocol: 'openai', method: 'POST', path: '/v1/responses', auth: 'Authorization: Bearer', transport: 'HTTP / SSE' },
    { protocol: 'openai', method: 'GET', path: '/v1/responses', auth: 'Authorization: Bearer', transport: 'WebSocket' },
    { protocol: 'anthropic', method: 'POST', path: '/v1/messages', auth: 'x-api-key', transport: 'HTTP / SSE' },
  ])
})

test('every protocol names its own credential header', () => {
  for (const row of ENDPOINTS) {
    if (row.protocol === 'openai') assert.equal(row.auth, 'Authorization: Bearer')
    else assert.equal(row.auth, 'x-api-key')
  }
})

test('an OpenAI and an Anthropic example exist and carry no real secret', () => {
  const commands = curlExamples().map((item) => item.command)
  assert.ok(commands.some((command) => command.includes('/v1/chat/completions')))
  assert.ok(commands.some((command) => command.includes('/v1/messages')))
  for (const command of commands) {
    assert.ok(command.includes(CREDENTIAL_PLACEHOLDER))
    assert.ok(command.includes(BASE_URL_PLACEHOLDER))
    assert.equal(/https?:\/\/(?!<base-url>)/.test(command), false)
    assert.equal(command.includes('api.openai.com'), false)
    assert.equal(command.includes('api.anthropic.com'), false)
  }
  const anthropic = commands.find((command) => command.includes('/v1/messages')) ?? ''
  assert.ok(anthropic.includes('x-api-key:'))
  assert.ok(anthropic.includes('max_tokens'))
})

test('troubleshooting covers 401, 404, and provider isolation', () => {
  const text = TROUBLESHOOTING.map((note) => `${note.symptom} ${note.cause}`).join(' ')
  assert.ok(text.includes('401'))
  assert.ok(text.includes('404'))
  assert.ok(/unavailable|maintenance/.test(text))
  assert.ok(/refused|routed/.test(text))
})

test('each example is one command, continued by a single backslash', () => {
  for (const item of curlExamples()) {
    const lines = item.command.split('\n')
    assert.ok(lines.length > 1, 'an example should wrap rather than run off one line')
    for (const line of lines.slice(0, -1)) {
      assert.ok(line.endsWith(' \\'), `expected one continuation in: ${line}`)
      assert.equal(line.endsWith(' \\\\'), false, `a doubled continuation breaks the command: ${line}`)
    }
    assert.equal(lines.at(-1)?.endsWith('\\'), false, 'the last line must not dangle a continuation')
    // The wrapped form must collapse back into exactly one shell command.
    assert.equal(/ \\\\/.test(item.command), false, 'a doubled continuation breaks the command')
  }
})
