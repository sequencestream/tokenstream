import { ref } from 'vue'

import { AdminApi, SessionExpiredError } from '../api/client.ts'

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

  /** Reads an existing session so a refresh keeps the administrator signed in. */
  async function restore(): Promise<boolean> {
    checking.value = true
    try {
      const session = await api.session()
      signedIn.value = session.signed_in
      return session.signed_in
    } catch {
      signedIn.value = false
      return false
    } finally {
      checking.value = false
    }
  }

  /** Signs in, reporting the sanitized reason on failure. */
  async function signIn(password: string): Promise<void> {
    const session = await api.signIn(password)
    signedIn.value = session.signed_in
  }

  /** Revokes the session so later navigation and refresh require sign-in. */
  async function signOut(): Promise<void> {
    await api.signOut()
    signedIn.value = false
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

  return { signedIn, checking, restore, signIn, signOut, handleFailure }
}
