import { test } from 'node:test'
import assert from 'node:assert/strict'

import { emptyProviderPage, loadProviders, PAGE_LIMIT, type ProviderPage } from './list.ts'
import type { AdminApi, Page, Provider } from '../api/client.ts'

function provider(id: number): Provider {
  return {
    id,
    name: `provider-${id}`,
    protocol_type: 'openai',
    endpoint: 'https://api.example.com',
    status: 'enabled',
    has_upstream_api_key: true,
    max_concurrent_requests: null,
    max_requests_per_second: null,
    health: 'healthy',
    health_probe: null,
    created_at: '2026-09-01T00:00:00Z',
  }
}

function recordingApi(pages: Page<Provider>[]): { api: AdminApi; queries: URLSearchParams[] } {
  const queries: URLSearchParams[] = []
  const api = {
    async list(path: string, query: URLSearchParams) {
      queries.push(new URLSearchParams(query))
      assert.equal(path, '/admin/api/providers')
      return pages.shift() ?? { items: [], next_after_id: null }
    },
  } as unknown as AdminApi
  return { api, queries }
}

test('the first page starts at the beginning and keeps the shared page limit', async () => {
  const { api, queries } = recordingApi([{ items: [provider(1)], next_after_id: 1 }])
  const page = await loadProviders(api, emptyProviderPage, true)
  assert.equal(queries[0].has('after_id'), false)
  assert.equal(queries[0].get('limit'), String(PAGE_LIMIT))
  assert.deepEqual(page.items.map((item) => item.id), [1])
  assert.equal(page.exhausted, false)
})

test('paging appends and advances the increasing-ID cursor', async () => {
  const { api, queries } = recordingApi([{ items: [provider(2)], next_after_id: null }])
  const first = await loadProviders(api, { items: [provider(1)], cursor: 1, exhausted: false }, false)
  const second = await loadProviders(api, first, false)
  assert.equal(queries[0].get('after_id'), '1')
  assert.deepEqual(second.items.map((item) => item.id), [1, 2])
  assert.equal(second.exhausted, true)
})

test('a reset discards the rows already loaded', async () => {
  const { api } = recordingApi([{ items: [provider(7)], next_after_id: null }])
  const page = await loadProviders(
    api,
    { items: [provider(1), provider(2)], cursor: 2, exhausted: false },
    true,
  )
  assert.deepEqual(page.items.map((item) => item.id), [7])
})
