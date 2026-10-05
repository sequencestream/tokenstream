// Drives the page's own edit module against the shape the HTTP contract
// accepts, so the payload the page submits is proven without a browser.
import assert from 'node:assert/strict'
import { test } from 'node:test'

import { changeSetFor, editDraftFor, moveProvider, readExpiry, removeProvider } from './edit.ts'
import type { ApiKey } from '../api/client.ts'

const stored: ApiKey = {
  id: 1,
  account_id: 1,
  name: 'ci',
  key_id: 'ts_abc',
  status: 'enabled',
  expires_at: null,
  default_provider_id: 1,
  provider_ids: [1, 2],
  max_concurrent_requests: 10,
  max_requests_per_second: 20,
  max_websockets: 5,
  created_at: '2026-01-01T00:00:00Z',
}

test('the page submits exactly the fields the credential edit accepts', () => {
  const draft = editDraftFor(stored)
  // Reorder the set, drop a provider, and let the default be cleared with it.
  draft.provider_ids = moveProvider(draft.provider_ids, 2, -1)
  const dropped = removeProvider(draft.provider_ids, draft.default_provider_id, 1)
  draft.provider_ids = dropped.provider_ids
  draft.default_provider_id = dropped.default_provider_id
  draft.name = 'edited'
  draft.status = 'disabled'
  draft.bounds.max_concurrent_requests = '7'
  draft.bounds.max_requests_per_second = ''
  draft.bounds.max_websockets = ''
  const expiry = readExpiry(draft.expires_at)

  const payload = changeSetFor(draft, expiry.value, {
    max_concurrent_requests: Number(draft.bounds.max_concurrent_requests),
    max_requests_per_second: null,
    max_websockets: null,
  })

  // Exactly the keys the edit endpoint accepts, so a rename cannot slip a field
  // the contract does not carry.
  assert.deepEqual(Object.keys(payload).sort(), [
    'admission',
    'default_provider_id',
    'expires_at',
    'name',
    'provider_ids',
    'status',
  ])
  // All three bounds travel together, and a cleared one is an explicit null.
  assert.deepEqual(payload.admission, {
    max_concurrent_requests: 7,
    max_requests_per_second: null,
    max_websockets: null,
  })
  assert.equal(payload.expires_at, null)
  assert.deepEqual(payload.provider_ids, [2])
  assert.equal(payload.default_provider_id, null)
  assert.equal(payload.name, 'edited')
  assert.equal(payload.status, 'disabled')
  // A request body survives JSON unchanged.
  assert.deepEqual(JSON.parse(JSON.stringify(payload)), payload)
})

test('the page carries an expiration when the operator sets one', () => {
  const draft = editDraftFor(stored)
  const expiry = readExpiry('2030-01-02T03:04')
  assert.equal('error' in expiry, false)
  const payload = changeSetFor(draft, (expiry as { value: string }).value, {
    max_concurrent_requests: null,
    max_requests_per_second: null,
    max_websockets: null,
  })
  assert.equal(typeof payload.expires_at, 'string')
  assert.equal(Number.isNaN(new Date(payload.expires_at as string).getTime()), false)
})
