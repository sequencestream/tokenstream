import { AdminApi, API_KEYS_PATH, type ApiKey } from '../api/client.ts'
import { PAGE_LIMIT } from '../providers/list.ts'

/** The credentials the page has loaded so far, with their paging state. */
export interface ApiKeyPage {
  items: ApiKey[]
  cursor: number | null
  exhausted: boolean
}

const EMPTY: ApiKeyPage = { items: [], cursor: null, exhausted: true }

function query(cursor: number | null, limit: number): URLSearchParams {
  const query = new URLSearchParams({ limit: String(limit) })
  if (cursor !== null) query.set('after_id', String(cursor))
  return query
}

/**
 * Lists the credentials the signed-in account can reach.
 *
 * The scope is the server's decision: a regular user receives only its own
 * credentials, so the page never has to filter, and never has to be trusted to.
 */
export async function loadApiKeys(
  api: AdminApi,
  page: ApiKeyPage,
  reset: boolean,
  limit: number = PAGE_LIMIT,
): Promise<ApiKeyPage> {
  const cursor = reset ? null : page.cursor
  const result = await api.list<ApiKey>(API_KEYS_PATH, query(cursor, limit))
  return {
    items: reset ? result.items : [...page.items, ...result.items],
    cursor: result.next_after_id,
    exhausted: result.items.length === 0 || result.next_after_id === null,
  }
}

export { EMPTY as emptyApiKeyPage, PAGE_LIMIT, type ApiKey }
