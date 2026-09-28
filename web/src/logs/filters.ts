export interface LogFilterValues {
  provider_id: string
  transport_type: '' | 'http' | 'websocket'
  start_time_gte: string
  start_time_lt: string
}

export function emptyLogFilters(): LogFilterValues {
  return { provider_id: '', transport_type: '', start_time_gte: '', start_time_lt: '' }
}

export function logFiltersChanged(
  draft: LogFilterValues,
  applied: LogFilterValues,
): boolean {
  return JSON.stringify(draft) !== JSON.stringify(applied)
}

/**
 * Builds the query for one page of the result set that `applied` produced.
 *
 * The cursor and the conditions belong to the same result set, so a caller can
 * never page with a cursor from one set and conditions from another.
 */
export function logQuery(
  applied: LogFilterValues,
  cursor: number | null,
  limit = 100,
): URLSearchParams {
  const query = new URLSearchParams({ limit: String(limit) })
  if (cursor !== null) query.set('after_id', String(cursor))
  if (applied.provider_id) query.set('provider_id', applied.provider_id)
  if (applied.transport_type) query.set('transport_type', applied.transport_type)
  if (applied.start_time_gte) {
    query.set('start_time_gte', new Date(applied.start_time_gte).toISOString())
  }
  if (applied.start_time_lt) {
    query.set('start_time_lt', new Date(applied.start_time_lt).toISOString())
  }
  return query
}
