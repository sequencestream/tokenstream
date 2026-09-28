import { AdminApi, PROVIDERS_PATH, type Provider, type ProviderUpdate, type ProviderWrite } from '../api/client.ts'

/** The page size of every cursor list. The API caps `limit` at the same value. */
export const PAGE_LIMIT = 100

/** The providers the page has loaded so far, with their paging state. */
export interface ProviderPage {
  items: Provider[]
  cursor: number | null
  exhausted: boolean
}

const EMPTY: ProviderPage = { items: [], cursor: null, exhausted: true }

function query(cursor: number | null, limit: number): URLSearchParams {
  const query = new URLSearchParams({ limit: String(limit) })
  if (cursor !== null) query.set('after_id', String(cursor))
  return query
}

/** Lists providers by increasing ID, appending a page unless resetting. */
export async function loadProviders(
  api: AdminApi,
  page: ProviderPage,
  reset: boolean,
  limit: number = PAGE_LIMIT,
): Promise<ProviderPage> {
  const cursor = reset ? null : page.cursor
  const result = await api.list<Provider>(PROVIDERS_PATH, query(cursor, limit))
  return {
    items: reset ? result.items : [...page.items, ...result.items],
    cursor: result.next_after_id,
    exhausted: result.items.length === 0 || result.next_after_id === null,
  }
}

export { EMPTY as emptyProviderPage, type Provider, type ProviderUpdate, type ProviderWrite }
