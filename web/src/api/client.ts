/**
 * The single place the page talks to the administration API.
 *
 * Every request is same-origin, so the session cookie and the CSRF token keep
 * working in every deployment. A deployment that serves the page from another
 * origin also serves the API from that origin, either directly or through the
 * development server's proxy.
 */
export const SESSION_PATH = '/admin/api/session'
export const PROVIDERS_PATH = '/admin/api/providers'
export const REQUEST_LOGS_PATH = '/admin/api/request-logs'
export const SETTINGS_PATH = '/admin/api/settings'

export type ProtocolType = 'openai' | 'anthropic'
export type ProviderStatus = 'enabled' | 'disabled'
export type TransportType = 'http' | 'websocket'

export interface Provider {
  id: number
  name: string
  protocol_type: ProtocolType
  endpoint: string
  status: ProviderStatus
  gateway_key_id: string
  has_upstream_api_key: boolean
  created_at: string
}

export interface RequestLog {
  id: number
  request_id: string
  provider_id: number
  protocol_type: ProtocolType
  transport_type: TransportType
  path: string
  status_code: number | null
  start_time: string
  end_time: string | null
  error_msg: string | null
  incomplete: boolean
}

/** One page of an increasing-ID cursor list. */
export interface Page<T> {
  items: T[]
  next_after_id: number | null
}

export interface SessionResponse {
  signed_in: boolean
  csrf_token: string
}

export interface ProviderWrite {
  name: string
  protocol_type: ProtocolType
  endpoint: string
  upstream_api_key: string
  status: ProviderStatus
}

export type ProviderUpdate = Partial<Omit<ProviderWrite, 'protocol_type'>>

/** A credential response is shown once and never persisted by the page. */
export interface CredentialResponse {
  provider: Provider
  gateway_api_key: string
}

export interface Setting {
  name: string
  label: string
  value: string | null
  configured: boolean
  secret: boolean
  restart_required: boolean
  pending_restart: boolean
}

export interface SettingsPage {
  items: Setting[]
}

export type SettingsPatch = Record<string, string>

/** Signals that the session ended, so the page returns to its sign-in view. */
export class SessionExpiredError extends Error {
  constructor() {
    super('The administrator session has ended. Sign in again.')
    this.name = 'SessionExpiredError'
  }
}

interface ErrorResponse {
  error?: { message?: string }
}

/**
 * Talks to the administration API on the page's own origin.
 *
 * The client owns the CSRF token and the same-origin credential policy, so no
 * caller can forget either. It also owns pagination for the cursor lists: a
 * page always carries the cursor and the conditions of one result set.
 */
export class AdminApi {
  #csrfToken = ''

  async #request<T>(path: string, options: RequestInit = {}): Promise<T> {
    const headers = new Headers(options.headers)
    if (options.body !== undefined) headers.set('content-type', 'application/json')
    if (options.method && !['GET', 'HEAD'].includes(options.method)) {
      headers.set('x-csrf-token', this.#csrfToken)
    }
    const response = await fetch(path, { ...options, headers, credentials: 'same-origin' })
    if (response.status === 401 && path !== SESSION_PATH) {
      this.#csrfToken = ''
      throw new SessionExpiredError()
    }
    if (!response.ok) {
      const body = (await response.json().catch(() => ({}))) as ErrorResponse
      throw new Error(body.error?.message ?? `Request failed (${response.status}).`)
    }
    if (response.status === 204) return undefined as T
    return response.json() as Promise<T>
  }

  /** Reads the current session state, including the CSRF token. */
  async session(): Promise<SessionResponse> {
    const session = await this.#request<SessionResponse>(SESSION_PATH)
    this.#csrfToken = session.csrf_token
    return session
  }

  /** Signs in with the administrator password and adopts the new session. */
  async signIn(password: string): Promise<SessionResponse> {
    const session = await this.#request<SessionResponse>(SESSION_PATH, {
      method: 'POST',
      body: JSON.stringify({ password }),
    })
    this.#csrfToken = session.csrf_token
    return session
  }

  /** Revokes the current session and forgets the CSRF token. */
  async signOut(): Promise<void> {
    await this.#request<void>(SESSION_PATH, { method: 'DELETE' })
    this.#csrfToken = ''
  }

  /** Reads one page of a cursor list. The query already carries its cursor. */
  list<T>(path: string, query: URLSearchParams): Promise<Page<T>> {
    return this.#request<Page<T>>(`${path}?${query}`)
  }

  /** Creates a provider and returns its first gateway credential. */
  createProvider(body: ProviderWrite): Promise<CredentialResponse> {
    return this.#request<CredentialResponse>(PROVIDERS_PATH, {
      method: 'POST',
      body: JSON.stringify(body),
    })
  }

  /** Changes a provider's name, endpoint, upstream key, or status. */
  updateProvider(id: number, body: ProviderUpdate): Promise<Provider> {
    return this.#request<Provider>(`${PROVIDERS_PATH}/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(body),
    })
  }

  /** Deletes an unreferenced provider. */
  deleteProvider(id: number): Promise<void> {
    return this.#request<void>(`${PROVIDERS_PATH}/${id}`, { method: 'DELETE' })
  }

  /** Issues a new gateway credential and retires the previous one. */
  rotateCredential(id: number): Promise<CredentialResponse> {
    return this.#request<CredentialResponse>(`${PROVIDERS_PATH}/${id}/gateway-key:rotate`, {
      method: 'POST',
    })
  }

  /** Reads the process settings table. Secret values are omitted. */
  settings(): Promise<SettingsPage> {
    return this.#request<SettingsPage>(SETTINGS_PATH)
  }

  /** Persists setting changes. Secret fields are write-only. */
  updateSettings(body: SettingsPatch): Promise<SettingsPage> {
    return this.#request<SettingsPage>(SETTINGS_PATH, {
      method: 'PATCH',
      body: JSON.stringify(body),
    })
  }
}
