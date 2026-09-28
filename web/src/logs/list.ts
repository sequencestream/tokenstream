import { AdminApi, REQUEST_LOGS_PATH, type RequestLog } from '../api/client.ts'
import { logQuery, type LogFilterValues } from './filters.ts'
import { PAGE_LIMIT } from '../providers/list.ts'

/** The request logs the page has loaded so far, with their paging state. */
export interface LogPage {
  items: RequestLog[]
  cursor: number | null
  exhausted: boolean
}

/**
 * Lists one page of the result set that `applied` produced.
 *
 * The caller passes the conditions the current rows came from, never the
 * conditions currently being edited, so a half-edited filter form cannot splice
 * a second result set onto the first. Changing conditions resets the page.
 */
export async function loadLogs(
  api: AdminApi,
  page: LogPage,
  applied: LogFilterValues,
  reset: boolean,
  limit: number = PAGE_LIMIT,
): Promise<LogPage> {
  const cursor = reset ? null : page.cursor
  const result = await api.list<RequestLog>(REQUEST_LOGS_PATH, logQuery(applied, cursor, limit))
  return {
    items: reset ? result.items : [...page.items, ...result.items],
    cursor: result.next_after_id,
    exhausted: result.items.length === 0 || result.next_after_id === null,
  }
}
