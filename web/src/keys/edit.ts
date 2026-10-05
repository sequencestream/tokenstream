import type { ApiKey, ApiKeyAdmissionWrite } from '../api/client.ts'

/**
 * The credential edit, as the page holds it.
 *
 * Every editable field has a draft, so an operator can abandon an edit without
 * the list ever having shown a half-applied credential. Bounds are drafts for
 * the same reason: a bound of zero is refused, and the page says so before the
 * request leaves rather than after.
 */
export interface CredentialEditDraft {
  name: string
  status: 'enabled' | 'disabled'
  /** The expiration as the page edits it: empty means it never expires. */
  expires_at: string
  /** Bound providers in preference order, most preferred first. */
  provider_ids: number[]
  default_provider_id: number | null
  bounds: {
    max_concurrent_requests: string
    max_requests_per_second: string
    max_websockets: string
  }
}

/**
 * Reads a stored credential into an edit draft.
 *
 * The stored provider order is the preference order, so the draft starts in that
 * order and a reorder is visible rather than implied.
 */
export function editDraftFor(key: ApiKey): CredentialEditDraft {
  return {
    name: key.name,
    status: key.status,
    expires_at: expiryDraft(key.expires_at),
    provider_ids: [...key.provider_ids],
    default_provider_id: key.default_provider_id,
    bounds: {
      max_concurrent_requests: draftFor(key.max_concurrent_requests),
      max_requests_per_second: draftFor(key.max_requests_per_second),
      max_websockets: draftFor(key.max_websockets),
    },
  }
}

/** Renders a stored bound for an input: a count, or empty for unbounded. */
function draftFor(value: number | null): string {
  return value === null ? '' : String(value)
}

/**
 * Renders a stored expiration for an input as a local date and time.
 *
 * The instant is edited in the operator's own timezone and converted back on
 * save, because a raw instant is the one value nobody can check by eye.
 */
function expiryDraft(value: string | null): string {
  if (value === null) return ''
  const parsed = new Date(value)
  if (Number.isNaN(parsed.getTime())) return ''
  const pad = (part: number): string => String(part).padStart(2, '0')
  return (
    `${parsed.getFullYear()}-${pad(parsed.getMonth() + 1)}-${pad(parsed.getDate())}` +
    `T${pad(parsed.getHours())}:${pad(parsed.getMinutes())}`
  )
}

/**
 * Converts an expiration draft back to an instant.
 *
 * An empty draft clears the expiration, which the server expresses as an
 * explicit null rather than as an absent field.
 */
export function readExpiry(raw: string): { value: string | null } | { error: string } {
  const text = raw.trim()
  if (text === '') return { value: null }
  const parsed = new Date(text)
  if (Number.isNaN(parsed.getTime())) {
    return { error: 'Enter a date and time, or leave it empty for no expiry.' }
  }
  if (parsed.getTime() <= Date.now()) {
    return { error: 'An expiry in the past would never authenticate. Choose a future time.' }
  }
  return { value: parsed.toISOString() }
}

/**
 * Moves one provider earlier or later in the preference order.
 *
 * Order is the credential's routing preference, so the page lets an operator
 * change it directly instead of making them rebind from scratch.
 */
export function moveProvider(
  provider_ids: number[],
  providerId: number,
  offset: number,
): number[] {
  const from = provider_ids.indexOf(providerId)
  if (from < 0) return [...provider_ids]
  const to = from + offset
  if (to < 0 || to >= provider_ids.length) return [...provider_ids]
  const next = [...provider_ids]
  next.splice(from, 1)
  next.splice(to, 0, providerId)
  return next
}

/**
 * Drops a provider from the edit and clears a default it would strand.
 *
 * A default outside the final set is refused by the server, so the page removes
 * it here instead of submitting a value the contract cannot accept.
 */
export function removeProvider(
  provider_ids: number[],
  default_provider_id: number | null,
  providerId: number,
): { provider_ids: number[]; default_provider_id: number | null } {
  const remaining = provider_ids.filter((id) => id !== providerId)
  return {
    provider_ids: remaining,
    default_provider_id:
      default_provider_id === providerId ||
      (default_provider_id !== null && !remaining.includes(default_provider_id))
        ? null
        : default_provider_id,
  }
}

/** Adds or removes a provider, keeping the default consistent with the set. */
export function toggleProvider(
  provider_ids: number[],
  default_provider_id: number | null,
  providerId: number,
): { provider_ids: number[]; default_provider_id: number | null } {
  if (provider_ids.includes(providerId)) {
    return removeProvider(provider_ids, default_provider_id, providerId)
  }
  return { provider_ids: [...provider_ids, providerId], default_provider_id }
}

/**
 * The change set one edit submits.
 *
 * The provider set is always named, because the page edits it in order and a
 * reordered set is not expressible as "no change". Bounds are named together
 * for the same reason they are stored together.
 */
export function changeSetFor(
  draft: CredentialEditDraft,
  expiresAt: string | null,
  bounds: ApiKeyAdmissionWrite,
): {
  name: string
  status: 'enabled' | 'disabled'
  expires_at: string | null
  provider_ids: number[]
  default_provider_id: number | null
  admission: ApiKeyAdmissionWrite
} {
  return {
    name: draft.name.trim(),
    status: draft.status,
    expires_at: expiresAt,
    provider_ids: [...draft.provider_ids],
    default_provider_id: draft.default_provider_id,
    admission: bounds,
  }
}
