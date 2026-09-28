import { test } from 'node:test'
import assert from 'node:assert/strict'

import { emptyLogFilters, logFiltersChanged, logQuery } from './filters.ts'

test('paging uses only the applied conditions', () => {
  const applied = { ...emptyLogFilters(), provider_id: '7', transport_type: 'http' as const }
  const query = logQuery(applied, 42)
  assert.equal(query.get('after_id'), '42')
  assert.equal(query.get('provider_id'), '7')
  assert.equal(query.get('transport_type'), 'http')
})

test('a first page omits the cursor and keeps the limit', () => {
  const query = logQuery(emptyLogFilters(), null)
  assert.equal(query.has('after_id'), false)
  assert.equal(query.get('limit'), '100')
})

test('time conditions are sent as timestamps', () => {
  const applied = {
    ...emptyLogFilters(),
    start_time_gte: '2026-09-01T00:00',
    start_time_lt: '2026-09-02T00:00',
  }
  const query = logQuery(applied, null)
  assert.equal(query.get('start_time_gte'), new Date('2026-09-01T00:00').toISOString())
  assert.equal(query.get('start_time_lt'), new Date('2026-09-02T00:00').toISOString())
})

test('editing a condition marks the form as not applied', () => {
  const applied = emptyLogFilters()
  const draft = { ...applied, transport_type: 'websocket' as const }
  assert.equal(logFiltersChanged(draft, applied), true)
  assert.equal(logFiltersChanged({ ...applied }, applied), false)
})
