import { computed, ref } from 'vue'

import {
  AdminApi,
  type AccountRole,
  SessionExpiredError,
  UnreadableResponseError,
} from '../api/client.ts'

/** Why an administration action failed, without choosing a language for it. */
export type ActionFailure =
  | { reason: 'session-ended' }
  | { reason: 'transport'; status: number }
  | { reason: 'server'; message: string }
  | { reason: 'unknown' }

/**
 * Owns the administrator session for the page.
 *
 * The session is the page's authentication state: it decides whether the
 * working views render at all, and it restores an existing session on load
 * without prompting. An ended session always returns the page to sign-in
 * rather than leaving stale administrative data on screen.
 */
export function useAdminSession(api: AdminApi) {
  const signedIn = ref(false)
  const checking = ref(true)
  const accountName = ref('')
  const role = ref<AccountRole>('user')
  /** Whether the session may reach the views only an administrator owns. */
  const isAdmin = computed(() => role.value === 'admin')

  function adopt(session: { signed_in: boolean; account_name: string; role: AccountRole }): boolean {
    signedIn.value = session.signed_in
    accountName.value = session.account_name
    role.value = session.role
    return session.signed_in
  }

  /** Reads an existing session so a refresh keeps the administrator signed in. */
  async function restore(): Promise<boolean> {
    checking.value = true
    try {
      return adopt(await api.session())
    } catch {
      signedIn.value = false
      accountName.value = ''
      role.value = 'user'
      return false
    } finally {
      checking.value = false
    }
  }

  /** Signs in, reporting the sanitized reason on failure. */
  async function signIn(name: string, password: string): Promise<void> {
    adopt(await api.signIn(name, password))
  }

  /** Revokes the session so later navigation and refresh require sign-in. */
  async function signOut(): Promise<void> {
    await api.signOut()
    signedIn.value = false
    accountName.value = ''
    role.value = 'user'
  }

  /**
   * Classifies an action failure so the page can drop a dead session.
   *
   * An expired session never leaves provider or log rows from the previous
   * session behind. The sentences themselves are chosen by the page.
   */
  function handleFailure(error: unknown): ActionFailure {
    if (error instanceof SessionExpiredError) {
      signedIn.value = false
      return { reason: 'session-ended' }
    }
    if (error instanceof UnreadableResponseError) {
      return { reason: 'transport', status: error.status }
    }
    if (error instanceof Error && error.message) {
      return { reason: 'server', message: error.message }
    }
    return { reason: 'unknown' }
  }

  return {
    signedIn,
    checking,
    accountName,
    role,
    isAdmin,
    restore,
    signIn,
    signOut,
    handleFailure,
  }
}
