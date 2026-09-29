import { test } from 'node:test'
import assert from 'node:assert/strict'

import { emptyApiKeyPage, loadApiKeys, PAGE_LIMIT, type ApiKeyPage } from './list.ts'
import type { AdminApi, ApiKey, Page } from '../api/client.ts'

function key(id: number, accountId = 1): ApiKey {
  return {
    id,
    account_id: accountId,
    name: `key-${id}`,
    key_id: `tokenstream-key-${id}`,
    status: 'enabled',
    expires_at: null,
    default_provider_id: 3,
    provider_ids: [3, 4],
    created_at: '2026-09-01T00:00:00Z',
  }
}

function recordingApi(pages: Page<ApiKey>[]): { api: AdminApi; queries: URLSearchParams[] } {
  const queries: URLSearchParams[] = []
  const api = {
    async list(path: string, query: URLSearchParams) {
      queries.push(new URLSearchParams(query))
      assert.equal(path, '/admin/api/api-keys')
      return pages.shift() ?? { items: [], next_after_id: null }
    },
  } as unknown as AdminApi
  return { api, queries }
}

test('the first page starts at the beginning and keeps the shared page limit', async () => {
  const { api, queries } = recordingApi([{ items: [key(1)], next_after_id: 1 }])
  const page = await loadApiKeys(api, emptyApiKeyPage, true)
  assert.equal(queries[0].has('after_id'), false)
  assert.equal(queries[0].get('limit'), String(PAGE_LIMIT))
  assert.deepEqual(page.items.map((item) => item.id), [1])
  assert.equal(page.exhausted, false)
})

test('paging appends and advances the increasing-ID cursor', async () => {
  const { api, queries } = recordingApi([{ items: [key(2)], next_after_id: null }])
  const first = await loadApiKeys(api, { items: [key(1)], cursor: 1, exhausted: false }, false)
  const second = await loadApiKeys(api, first, false)
  assert.equal(queries[0].get('after_id'), '1')
  assert.deepEqual(second.items.map((item) => item.id), [1, 2])
  assert.equal(second.exhausted, true)
})

test('the listing never carries a plaintext, only the lookup key id', async () => {
  const { api } = recordingApi([{ items: [key(1)], next_after_id: null }])
  const page = await loadApiKeys(api, emptyApiKeyPage, true)
  assert.equal(page.items[0].key_id, 'tokenstream-key-1')
  assert.equal(
    Object.keys(page.items[0]).some((field) => field.includes('secret')),
    false,
  )
})
