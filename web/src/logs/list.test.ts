import { test } from 'node:test'
import assert from 'node:assert/strict'

import { emptyLogFilters } from './filters.ts'
import { loadLogs, type LogPage } from './list.ts'
import type { AdminApi, Page, RequestLog } from '../api/client.ts'

const EMPTY: LogPage = { items: [], cursor: null, exhausted: true }

function row(id: number): RequestLog {
  return {
    id,
    request_id: `request-${id}`,
    account_id: 1,
    api_key_id: 1,
    provider_id: 1,
    protocol_type: 'openai',
    transport_type: 'http',
    path: '/v1/chat/completions',
    status_code: 200,
    start_time: '2026-09-01T00:00:00Z',
    end_time: '2026-09-01T00:00:01Z',
    error_msg: null,
    incomplete: false,
  }
}

/** Records the queries the page issues so a test can assert their contents. */
function recordingApi(pages: Page<RequestLog>[]): { api: AdminApi; queries: URLSearchParams[] } {
  const queries: URLSearchParams[] = []
  const api = {
    async list(path: string, query: URLSearchParams) {
      queries.push(new URLSearchParams(query))
      assert.equal(path, '/admin/api/request-logs')
      return pages.shift() ?? { items: [], next_after_id: null }
    },
  } as unknown as AdminApi
  return { api, queries }
}

test('a reset starts from the beginning without a cursor', async () => {
  const { api, queries } = recordingApi([{ items: [row(1), row(2)], next_after_id: 2 }])
  const page = await loadLogs(api, EMPTY, emptyLogFilters(), true)
  assert.equal(queries[0].has('after_id'), false)
  assert.deepEqual(page.items.map((item) => item.id), [1, 2])
  assert.equal(page.cursor, 2)
  assert.equal(page.exhausted, false)
})

test('paging a partial result set reuses only the applied conditions and cursor', async () => {
  const applied = { ...emptyLogFilters(), transport_type: 'websocket' as const }
  const { api, queries } = recordingApi([
    { items: [row(3)], next_after_id: 3 },
    { items: [row(5)], next_after_id: null },
  ])
  const first = await loadLogs(api, EMPTY, applied, true)
  const second = await loadLogs(api, first, applied, false)
  assert.equal(queries[1].get('after_id'), '3')
  assert.equal(queries[1].get('transport_type'), 'websocket')
  assert.deepEqual(second.items.map((item) => item.id), [3, 5])
  assert.equal(second.exhausted, true)
})

test('an empty page exhausts the list', async () => {
  const { api } = recordingApi([{ items: [], next_after_id: null }])
  const page = await loadLogs(api, EMPTY, emptyLogFilters(), true)
  assert.deepEqual(page.items, [])
  assert.equal(page.exhausted, true)
})
