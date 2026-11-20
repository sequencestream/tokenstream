import { en, type MessagePath } from './en.ts'
import { zhCN } from './zh-CN.ts'

export const LOCALES = ['en', 'zh-CN'] as const
export type Locale = (typeof LOCALES)[number]
export const LOCALE_STORAGE_KEY = 'tokenstream.locale'

export type MessageVars = Record<string, string | number>

const catalogs = { en, 'zh-CN': zhCN }

/** The language to show: a stored choice, otherwise the first matching browser tag. */
export function resolveLocale(stored: string | null, languages: readonly string[]): Locale {
  if (stored === 'en' || stored === 'zh-CN') return stored
  for (const tag of languages) {
    if (isSimplifiedChinese(tag)) return 'zh-CN'
  }
  return 'en'
}

function isSimplifiedChinese(tag: string): boolean {
  const lower = tag.trim().toLowerCase().replace(/_/g, '-')
  if (!lower.startsWith('zh')) return false
  if (
    lower === 'zh-tw' ||
    lower.startsWith('zh-tw-') ||
    lower === 'zh-hk' ||
    lower.startsWith('zh-hk-') ||
    lower === 'zh-mo' ||
    lower.startsWith('zh-mo-') ||
    lower === 'zh-hant' ||
    lower.startsWith('zh-hant-')
  ) {
    return false
  }
  return (
    lower === 'zh' ||
    lower === 'zh-cn' ||
    lower.startsWith('zh-cn-') ||
    lower === 'zh-sg' ||
    lower.startsWith('zh-sg-') ||
    lower === 'zh-hans' ||
    lower.startsWith('zh-hans-')
  )
}

/** The sentence for one key, with `{name}` replaced from `vars`. */
export function translate(language: Locale, path: MessagePath, vars?: MessageVars): string {
  const template = readPath(catalogs[language], path)
  if (!vars) return template
  return template.replace(/\{([A-Za-z0-9_]+)\}/g, (token, name: string) => {
    const value = vars[name]
    return value === undefined ? token : String(value)
  })
}

/** A known process setting's display name, or the label the API returned. */
export function settingLabel(language: Locale, name: string, fallback: string): string {
  const table = catalogs[language].settingName
  if (!Object.prototype.hasOwnProperty.call(table, name)) return fallback
  const label = table[name as keyof typeof table]
  return label || fallback
}

function readPath(tree: object, path: string): string {
  let node: unknown = tree
  for (const part of path.split('.')) {
    if (!node || typeof node !== 'object' || !(part in node)) return path
    node = (node as Record<string, unknown>)[part]
  }
  return typeof node === 'string' ? node : path
}

/** Every leaf path in a catalog, used to prove the two languages name the same sentences. */
export function messageLeaves(tree: object): Map<string, string> {
  const leaves = new Map<string, string>()
  walk(tree, '', leaves)
  return leaves
}

function walk(node: unknown, prefix: string, leaves: Map<string, string>) {
  if (typeof node === 'string') {
    leaves.set(prefix, node)
    return
  }
  if (!node || typeof node !== 'object') return
  for (const [key, value] of Object.entries(node)) {
    walk(value, prefix ? `${prefix}.${key}` : key, leaves)
  }
}
