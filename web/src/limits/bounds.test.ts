import { test } from 'node:test'
import assert from 'node:assert/strict'

import { boundDraft, boundSummary, emptyBoundDrafts, readBound, readBounds } from './bounds.ts'

test('an empty bound is unbounded rather than a mistake', () => {
  assert.deepEqual(readBound(''), { value: null })
  assert.deepEqual(readBound('   '), { value: null })
})

test('a positive count is read as written', () => {
  assert.deepEqual(readBound('1'), { value: 1 })
  assert.deepEqual(readBound(' 250 '), { value: 250 })
})

test('zero is refused because it would forbid all traffic', () => {
  assert.ok('error' in readBound('0'))
})

test('text that is not a count is refused', () => {
  for (const raw of ['-1', '1.5', 'ten', '1e3', '1,000', '12px']) {
    assert.ok('error' in readBound(raw), `${raw} should be refused`)
  }
})

test('a count beyond the safe range is refused rather than truncated', () => {
  assert.ok('error' in readBound('99999999999999999999'))
})

test('one invalid bound fails the whole set, so no partial edit is sent', () => {
  const drafts = { max_concurrent_requests: '4', max_requests_per_second: 'oops', max_websockets: '2' }
  const result = readBounds(drafts, ['max_concurrent_requests', 'max_requests_per_second', 'max_websockets'])
  assert.ok('error' in result)
})

test('a valid set reads every bound at once', () => {
  const drafts = { max_concurrent_requests: '4', max_requests_per_second: '', max_websockets: '2' }
  const result = readBounds(drafts, ['max_concurrent_requests', 'max_requests_per_second', 'max_websockets'])
  assert.deepEqual(result, { values: { max_concurrent_requests: 4, max_requests_per_second: null, max_websockets: 2 } })
})

test('a stored bound round-trips through the draft, and unbounded drafts are empty', () => {
  assert.equal(boundDraft(12), '12')
  assert.equal(boundDraft(null), '')
  assert.deepEqual(emptyBoundDrafts(), {
    max_concurrent_requests: '',
    max_requests_per_second: '',
    max_websockets: '',
  })
})

test('a summary names only the bounds that are set', () => {
  assert.equal(
    boundSummary([['concurrency', 4], ['rate', null]]),
    'concurrency 4',
  )
  assert.equal(
    boundSummary([
      ['concurrency', 4],
      ['rate', 10],
      ['WebSockets', 2],
    ]),
    'concurrency 4, rate 10, WebSockets 2',
  )
  assert.equal(boundSummary([['concurrency', null]]), 'Unbounded')
})
