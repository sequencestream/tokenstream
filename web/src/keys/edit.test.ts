import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  changeSetFor,
  editDraftFor,
  moveProvider,
  readExpiry,
  removeProvider,
  toggleProvider,
} from './edit.ts'
import type { ApiKey } from '../api/client.ts'

function key(overrides: Partial<ApiKey> = {}): ApiKey {
  return {
    id: 7,
    account_id: 1,
    name: 'ci',
    key_id: 'ts_abc',
    status: 'enabled',
    expires_at: null,
    default_provider_id: 1,
    provider_ids: [1, 2, 3],
    max_concurrent_requests: 10,
    max_requests_per_second: null,
    max_websockets: 5,
    created_at: '2026-09-01T00:00:00Z',
    ...overrides,
  }
}

test('a stored credential reads back into a draft with its own order and bounds', () => {
  const draft = editDraftFor(key())
  assert.equal(draft.name, 'ci')
  assert.equal(draft.status, 'enabled')
  assert.deepEqual(draft.provider_ids, [1, 2, 3])
  assert.equal(draft.default_provider_id, 1)
  assert.equal(draft.bounds.max_concurrent_requests, '10')
  // An absent bound is unbounded, which the page shows as an empty field.
  assert.equal(draft.bounds.max_requests_per_second, '')
  assert.equal(draft.bounds.max_websockets, '5')
})

test('the draft copies the provider order instead of sharing it with the list', () => {
  const source = key()
  const draft = editDraftFor(source)
  draft.provider_ids.push(4)
  assert.deepEqual(source.provider_ids, [1, 2, 3])
})

test('an unbound credential edits with an empty expiry and no default', () => {
  const draft = editDraftFor(key({ expires_at: null, default_provider_id: null }))
  assert.equal(draft.expires_at, '')
  assert.equal(draft.default_provider_id, null)
})

test('a stored expiration becomes an editable local date and time', () => {
  const draft = editDraftFor(key({ expires_at: '2030-01-02T03:04:00Z' }))
  // Rendered in the operator's own timezone, which is what makes it checkable.
  const parsed = new Date(draft.expires_at)
  assert.equal(Number.isNaN(parsed.getTime()), false)
  assert.equal(parsed.getFullYear(), 2030)
})

test('an unparsable stored expiration reads as no expiry rather than as a bad value', () => {
  const draft = editDraftFor(key({ expires_at: 'not-a-date' }))
  assert.equal(draft.expires_at, '')
})

test('an empty expiry draft clears the expiration', () => {
  assert.deepEqual(readExpiry(''), { value: null })
  assert.deepEqual(readExpiry('   '), { value: null })
})

test('an expiry draft converts back to the instant it names', () => {
  const read = readExpiry('2030-01-02T03:04')
  assert.equal('error' in read, false)
  // The draft is a local wall-clock time, so the round trip is checked against
  // the same local reading rather than a fixed UTC string.
  const value = new Date((read as { value: string }).value)
  assert.equal(value.getFullYear(), 2030)
  assert.equal(value.getMonth(), 0)
  assert.equal(value.getDate(), 2)
  assert.equal(value.getHours(), 3)
  assert.equal(value.getMinutes(), 4)
})

test('a stored expiration survives a round trip through the draft', () => {
  const original = '2031-06-15T12:30:00Z'
  const draft = editDraftFor(key({ expires_at: original }))
  const read = readExpiry(draft.expires_at)
  assert.equal('error' in read, false)
  assert.equal(
    new Date((read as { value: string }).value).getTime(),
    new Date(original).getTime(),
  )
})

test('an expiry in the past is refused in the page, before a request is sent', () => {
  const read = readExpiry('2000-01-01T00:00')
  assert.equal('error' in read, true)
})

test('an unparsable expiry is refused in the page', () => {
  const read = readExpiry('next tuesday')
  assert.equal('error' in read, true)
})

test('a provider moves one step earlier or later in the preference order', () => {
  assert.deepEqual(moveProvider([1, 2, 3], 3, -1), [1, 3, 2])
  assert.deepEqual(moveProvider([1, 2, 3], 1, 1), [2, 1, 3])
})

test('a provider cannot move past either end of the order', () => {
  assert.deepEqual(moveProvider([1, 2, 3], 1, -1), [1, 2, 3])
  assert.deepEqual(moveProvider([1, 2, 3], 3, 1), [1, 2, 3])
})

test('moving a provider that is not bound changes nothing', () => {
  assert.deepEqual(moveProvider([1, 2, 3], 9, 1), [1, 2, 3])
})

test('removing the current default clears it instead of stranding it', () => {
  const result = removeProvider([1, 2, 3], 1, 1)
  assert.deepEqual(result.provider_ids, [2, 3])
  assert.equal(result.default_provider_id, null)
})

test('removing another provider leaves the default in place', () => {
  const result = removeProvider([1, 2, 3], 1, 3)
  assert.deepEqual(result.provider_ids, [1, 2])
  assert.equal(result.default_provider_id, 1)
})

test('toggling a provider adds it at the end and removes it again', () => {
  const added = toggleProvider([1, 2], 1, 3)
  assert.deepEqual(added.provider_ids, [1, 2, 3])
  assert.equal(added.default_provider_id, 1)
  const removed = toggleProvider(added.provider_ids, 1, 3)
  assert.deepEqual(removed.provider_ids, [1, 2])
})

test('one change set carries the whole edit, including a cleared default', () => {
  const draft = editDraftFor(key())
  draft.name = '  edited  '
  draft.status = 'disabled'
  const change = changeSetFor(draft, null, {
    max_concurrent_requests: 2,
    max_requests_per_second: null,
    max_websockets: null,
  })
  assert.equal(change.name, 'edited')
  assert.equal(change.status, 'disabled')
  assert.equal(change.expires_at, null)
  assert.deepEqual(change.provider_ids, [1, 2, 3])
  assert.equal(change.default_provider_id, 1)
  assert.deepEqual(change.admission, {
    max_concurrent_requests: 2,
    max_requests_per_second: null,
    max_websockets: null,
  })
})
