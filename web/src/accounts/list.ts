import { AdminApi, ACCOUNTS_PATH, type Account } from '../api/client.ts'
import { PAGE_LIMIT } from '../providers/list.ts'

/** The accounts the page has loaded so far, with their paging state. */
export interface AccountPage {
  items: Account[]
  cursor: number | null
  exhausted: boolean
}

const EMPTY: AccountPage = { items: [], cursor: null, exhausted: true }

function query(cursor: number | null, limit: number): URLSearchParams {
  const query = new URLSearchParams({ limit: String(limit) })
  if (cursor !== null) query.set('after_id', String(cursor))
  return query
}

/** Lists accounts by increasing ID, appending a page unless resetting. */
export async function loadAccounts(
  api: AdminApi,
  page: AccountPage,
  reset: boolean,
  limit: number = PAGE_LIMIT,
): Promise<AccountPage> {
  const cursor = reset ? null : page.cursor
  const result = await api.list<Account>(ACCOUNTS_PATH, query(cursor, limit))
  return {
    items: reset ? result.items : [...page.items, ...result.items],
    cursor: result.next_after_id,
    exhausted: result.items.length === 0 || result.next_after_id === null,
  }
}

export { EMPTY as emptyAccountPage, PAGE_LIMIT, type Account }
