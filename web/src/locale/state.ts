import { ref } from 'vue'

import type { MessagePath } from './en.ts'
import {
  LOCALE_STORAGE_KEY,
  type Locale,
  type MessageVars,
  resolveLocale,
  settingLabel as labelFor,
  translate,
} from './resolve.ts'

export type { Locale, MessagePath, MessageVars }

/** A browser store for the operator's language choice. */
export interface LocaleStorage {
  getItem(key: string): string | null
  setItem(key: string, value: string): void
}

/** The language the page is drawing right now. */
export const locale = ref<Locale>('en')

/**
 * Applies a stored choice, or the browser language, before the page paints.
 *
 * Call this before the application mounts so the first screen, including
 * sign-in, is already in the operator's language.
 */
export function installLocale(storage: LocaleStorage = browserStorage(), languages?: readonly string[]): void {
  locale.value = resolveLocale(storage.getItem(LOCALE_STORAGE_KEY), languages ?? browserLanguages())
  applyDocument(locale.value)
}

/** Remembers a choice and redraws the page in that language. */
export function setLocale(next: Locale, storage: LocaleStorage = browserStorage()): void {
  locale.value = next
  storage.setItem(LOCALE_STORAGE_KEY, next)
  applyDocument(next)
}

/** The sentence for `path` in the current language. */
export function t(path: MessagePath, vars?: MessageVars): string {
  return translate(locale.value, path, vars)
}

/** The display name of a process setting in the current language. */
export function settingLabel(name: string, fallback: string): string {
  return labelFor(locale.value, name, fallback)
}

function applyDocument(next: Locale) {
  if (typeof document === 'undefined') return
  document.documentElement.lang = next
  document.title = translate(next, 'documentTitle')
}

function browserStorage(): LocaleStorage {
  if (typeof localStorage === 'undefined') {
    return { getItem: () => null, setItem: () => {} }
  }
  return localStorage
}

function browserLanguages(): readonly string[] {
  if (typeof navigator === 'undefined') return []
  if (navigator.languages.length > 0) return navigator.languages
  return navigator.language ? [navigator.language] : []
}
