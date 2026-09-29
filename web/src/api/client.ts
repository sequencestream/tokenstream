/**
 * The single place the page talks to the administration API.
 *
 * Every request is same-origin, so the session cookie and the CSRF token keep
 * working in every deployment. A deployment that serves the page from another
 * origin also serves the API from that origin, either directly or through the
 * development server's proxy.
 */
export const SESSION_PATH = '/admin/api/session'
export const ACCOUNTS_PATH = '/admin/api/accounts'
export const API_KEYS_PATH = '/admin/api/api-keys'
export const PROVIDERS_PATH = '/admin/api/providers'
export const REQUEST_LOGS_PATH = '/admin/api/request-logs'
export const SETTINGS_PATH = '/admin/api/settings'

export type ProtocolType = 'openai' | 'anthropic'
export type ProviderStatus = 'enabled' | 'disabled'
export type TransportType = 'http' | 'websocket'
export type AccountRole = 'admin' | 'user'
export type AccountStatus = 'enabled' | 'disabled'
export type ApiKeyStatus = 'enabled' | 'disabled'

/** A person or principal that owns data-plane credentials. */
export interface Account {
  id: number
  name: string
  role: AccountRole
  status: AccountStatus
  is_bootstrap: boolean
  created_at: string
}

export interface AccountWrite {
  name: string
  role: AccountRole
  status: AccountStatus
}

/** A credential belongs to an account, not to a provider. */
export interface ApiKey {
  id: number
  account_id: number
  name: string
  key_id: string
  status: ApiKeyStatus
  expires_at: string | null
  default_provider_id: number | null
  provider_ids: number[]
  created_at: string
}

export interface ApiKeyWrite {
  account_id: number
  name: string
  provider_ids: number[]
  default_provider_id?: number | null
  status: ApiKeyStatus
}

export interface Provider {
  id: number
  name: string
  protocol_type: ProtocolType
  endpoint: string
  status: ProviderStatus
  has_upstream_api_key: boolean
  created_at: string
}

export interface RequestLog {
  id: number
  request_id: string
  account_id: number
  api_key_id: number
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
  /** The signed-in account, so the page renders only what its role reaches. */
  account_name: string
  role: AccountRole
}

export interface ProviderWrite {
  name: string
  protocol_type: ProtocolType
  endpoint: string
  upstream_api_key: string
  status: ProviderStatus
}

export type ProviderUpdate = Partial<Omit<ProviderWrite, 'protocol_type'>>

/** A one-time plaintext, present only at creation and at rotation. */
export interface ApiKeyIssueResponse {
  api_key: ApiKey
  api_key_secret: string
}

/** An account created without a password, whose password is shown once. */
export interface AccountCreateResponse {
  account: Account
  generated_password: string | null
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

  /** Signs in with an account name and password, and adopts the new session. */
  async signIn(name: string, password: string): Promise<SessionResponse> {
    const session = await this.#request<SessionResponse>(SESSION_PATH, {
      method: 'POST',
      body: JSON.stringify({ name, password }),
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

  /** Creates a provider. A provider no longer issues any credential. */
  createProvider(body: ProviderWrite): Promise<Provider> {
    return this.#request<Provider>(PROVIDERS_PATH, {
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

  /** Creates an account, optionally with a password the caller supplies. */
  createAccount(body: Partial<AccountWrite> & { name: string; password?: string }): Promise<AccountCreateResponse> {
    return this.#request<AccountCreateResponse>(ACCOUNTS_PATH, {
      method: 'POST',
      body: JSON.stringify(body),
    })
  }

  /** Changes an account's name, password, role, or status. */
  updateAccount(id: number, body: Partial<AccountWrite> & { password?: string }): Promise<Account> {
    return this.#request<Account>(`${ACCOUNTS_PATH}/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(body),
    })
  }

  /** Deletes an account that owns nothing. */
  deleteAccount(id: number): Promise<void> {
    return this.#request<void>(`${ACCOUNTS_PATH}/${id}`, { method: 'DELETE' })
  }

  /** Issues a credential for an account and returns its one-time plaintext. */
  createApiKey(body: ApiKeyWrite): Promise<ApiKeyIssueResponse> {
    return this.#request<ApiKeyIssueResponse>(API_KEYS_PATH, {
      method: 'POST',
      body: JSON.stringify(body),
    })
  }

  /** Issues a fresh plaintext and retires the previous one. */
  rotateApiKey(id: number): Promise<ApiKeyIssueResponse> {
    return this.#request<ApiKeyIssueResponse>(`${API_KEYS_PATH}/${id}:rotate`, { method: 'POST' })
  }

  /** Changes a credential's name, status, providers, or default provider. */
  updateApiKey(
    id: number,
    body: Partial<Pick<ApiKeyWrite, 'name' | 'status' | 'provider_ids' | 'default_provider_id'>>,
  ): Promise<ApiKey> {
    return this.#request<ApiKey>(`${API_KEYS_PATH}/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(body),
    })
  }

  /** Deletes a credential. */
  deleteApiKey(id: number): Promise<void> {
    return this.#request<void>(`${API_KEYS_PATH}/${id}`, { method: 'DELETE' })
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
