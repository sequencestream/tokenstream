import { computed, ref } from 'vue'

import { AdminApi, type AccountRole, SessionExpiredError } from '../api/client.ts'

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
   * Reports whether an action failed because the session ended.
   *
   * The page uses this to drop its session-dependent state, so an expired
   * session never leaves provider or log rows from the previous session behind.
   */
  function handleFailure(error: unknown): string {
    if (error instanceof SessionExpiredError) {
      signedIn.value = false
      return error.message
    }
    return error instanceof Error ? error.message : 'The request could not be completed.'
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
