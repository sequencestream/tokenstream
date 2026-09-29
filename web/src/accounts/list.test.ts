import { test } from 'node:test'
import assert from 'node:assert/strict'

import { emptyAccountPage, loadAccounts, PAGE_LIMIT, type AccountPage } from './list.ts'
import type { Account, AdminApi, Page } from '../api/client.ts'

function account(id: number, role: 'admin' | 'user' = 'user'): Account {
  return {
    id,
    name: `account-${id}`,
    role,
    status: 'enabled',
    is_bootstrap: role === 'admin',
    created_at: '2026-09-01T00:00:00Z',
  }
}

function recordingApi(pages: Page<Account>[]): { api: AdminApi; queries: URLSearchParams[] } {
  const queries: URLSearchParams[] = []
  const api = {
    async list(path: string, query: URLSearchParams) {
      queries.push(new URLSearchParams(query))
      assert.equal(path, '/admin/api/accounts')
      return pages.shift() ?? { items: [], next_after_id: null }
    },
  } as unknown as AdminApi
  return { api, queries }
}

test('the first page starts at the beginning and keeps the shared page limit', async () => {
  const { api, queries } = recordingApi([{ items: [account(1, 'admin')], next_after_id: 1 }])
  const page = await loadAccounts(api, emptyAccountPage, true)
  assert.equal(queries[0].has('after_id'), false)
  assert.equal(queries[0].get('limit'), String(PAGE_LIMIT))
  assert.deepEqual(page.items.map((item) => item.id), [1])
  assert.equal(page.exhausted, false)
})

test('paging appends and advances the increasing-ID cursor', async () => {
  const { api, queries } = recordingApi([{ items: [account(2)], next_after_id: null }])
  const first = await loadAccounts(
    api,
    { items: [account(1)], cursor: 1, exhausted: false },
    false,
  )
  const second = await loadAccounts(api, first, false)
  assert.equal(queries[0].get('after_id'), '1')
  assert.deepEqual(second.items.map((item) => item.id), [1, 2])
  assert.equal(second.exhausted, true)
})

test('a reset discards the rows already loaded', async () => {
  const { api } = recordingApi([{ items: [account(7)], next_after_id: null }])
  const page = await loadAccounts(
    api,
    { items: [account(1), account(2)], cursor: 2, exhausted: false },
    true,
  )
  assert.deepEqual(page.items.map((item) => item.id), [7])
})
