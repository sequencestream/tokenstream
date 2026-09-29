/**
 * Admission bounds as the page edits them.
 *
 * A bound is a positive count or nothing. Nothing is unbounded, so the page
 * never sends a zero: a zero would forbid every request instead of bounding
 * one, and the server refuses it for the same reason.
 */
export interface BoundDrafts {
  max_concurrent_requests: string
  max_requests_per_second: string
  max_websockets: string
}

/** The drafts a provider edits: a provider carries no WebSocket bound. */
export type ProviderBoundDrafts = Omit<BoundDrafts, 'max_websockets'>

/** The drafts a provider starts from, so nothing is bounded yet. */
export function emptyBoundDrafts(): BoundDrafts {
  return { max_concurrent_requests: '', max_requests_per_second: '', max_websockets: '' }
}

/**
 * Reads one bound, or reports the text that is not a positive count.
 *
 * Empty is unbounded, which is a real choice and not a mistake, so it never
 * fails. Only a non-empty value that is not a positive whole number fails, and
 * it fails in the page rather than at the server.
 */
export function readBound(raw: string): { value: number | null } | { error: string } {
  const text = raw.trim()
  if (text === '') return { value: null }
  if (!/^\d+$/.test(text)) return { error: 'Enter a whole number, or leave it empty for no bound.' }
  const value = Number(text)
  if (!Number.isSafeInteger(value) || value < 1) {
    return { error: 'A bound must be at least 1. Zero would forbid all traffic.' }
  }
  return { value }
}

/** Reads every bound of one dimension, or reports the first that is invalid. */
export function readBounds<K extends keyof BoundDrafts>(
  drafts: Record<K, string>,
  fields: readonly K[],
): { values: Record<K, number | null> } | { error: string } {
  const values = {} as Record<K, number | null>
  for (const field of fields) {
    const read = readBound(drafts[field])
    if ('error' in read) return read
    values[field] = read.value
  }
  return { values }
}

/** Renders a stored bound for an input: a count, or the empty unbounded draft. */
export function boundDraft(value: number | null): string {
  return value === null ? '' : String(value)
}

/**
 * Summarises stored bounds for a table cell.
 *
 * A dimension with no bound shows "Unbounded" only when none of them is set, so
 * a column of numbers stays readable.
 */
export function boundSummary(parts: readonly (readonly [string, number | null])[]): string {
  const set = parts
    .filter(([, value]) => value !== null)
    .map(([label, value]) => `${label} ${value}`)
  return set.length === 0 ? 'Unbounded' : set.join(', ')
}
