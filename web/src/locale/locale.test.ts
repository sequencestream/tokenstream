import assert from 'node:assert/strict'
import { test } from 'node:test'

import { BASE_URL_NOTE, TROUBLESHOOTING, WEBSOCKET_NOTE, curlExamples } from '../docs/endpoints.ts'
import { en } from './en.ts'
import {
  messageLeaves,
  resolveLocale,
  settingLabel,
  translate,
} from './resolve.ts'
import { installLocale, locale, setLocale, type LocaleStorage } from './state.ts'
import { zhCN } from './zh-CN.ts'

function memory(): LocaleStorage & { values: Map<string, string> } {
  const values = new Map<string, string>()
  return {
    values,
    getItem: (key) => values.get(key) ?? null,
    setItem: (key, value) => {
      values.set(key, value)
    },
  }
}

test('a stored choice wins over the browser language', () => {
  assert.equal(resolveLocale('en', ['zh-CN']), 'en')
  assert.equal(resolveLocale('zh-CN', ['en-US']), 'zh-CN')
})

test('simplified Chinese browser tags select zh-CN', () => {
  for (const tag of ['zh', 'zh-CN', 'zh-cn', 'zh_SG', 'zh-Hans', 'zh-Hans-CN']) {
    assert.equal(resolveLocale(null, [tag]), 'zh-CN', tag)
  }
})

test('traditional Chinese browser tags stay on English', () => {
  for (const tag of ['zh-TW', 'zh-HK', 'zh-MO', 'zh-Hant', 'zh-Hant-TW']) {
    assert.equal(resolveLocale(null, [tag]), 'en', tag)
  }
})

test('a later simplified tag still wins when a traditional tag is listed first', () => {
  assert.equal(resolveLocale(null, ['zh-TW', 'zh-CN']), 'zh-CN')
})

test('an unrecognized stored value falls through to the browser', () => {
  assert.equal(resolveLocale('zh', ['en-US']), 'en')
  assert.equal(resolveLocale('fr', ['zh-CN']), 'zh-CN')
  assert.equal(resolveLocale(null, ['en-US', 'fr']), 'en')
})

test('both catalogs name the same sentences and none are empty', () => {
  const english = messageLeaves(en)
  const chinese = messageLeaves(zhCN)
  assert.deepEqual([...chinese.keys()].sort(), [...english.keys()].sort())
  for (const [path, sentence] of english) {
    assert.notEqual(sentence.trim(), '', path)
    assert.notEqual(chinese.get(path)?.trim(), '', path)
  }
})

test('english docs prose is the pinned contract copy', () => {
  assert.equal(en.docs.baseUrl, BASE_URL_NOTE)
  assert.equal(en.docs.websocket, WEBSOCKET_NOTE)
  for (const note of TROUBLESHOOTING) {
    assert.equal(en.docs.symptom[note.id], note.symptom)
    assert.equal(en.docs.cause[note.id], note.cause)
  }
  for (const example of curlExamples()) {
    const id = example.id as keyof typeof en.docs.example
    assert.equal(en.docs.example[id], example.title)
  }
})

test('a sentence interpolates named values and leaves unknown names in place', () => {
  assert.equal(translate('en', 'account.created', { name: 'ada' }), 'Account ada created.')
  assert.equal(translate('zh-CN', 'signIn.title'), '登录')
  assert.equal(translate('en', 'request.failed', { status: 503 }), 'Request failed (503).')
  assert.equal(translate('en', 'account.created', {}), 'Account {name} created.')
})

test('an unknown setting keeps the label the API returned', () => {
  assert.equal(settingLabel('zh-CN', 'TOKENSTREAM_DATA_DIR', 'Process data directory'), '进程数据目录')
  assert.equal(settingLabel('en', 'TOKENSTREAM_FUTURE', 'Future setting'), 'Future setting')
})

test('installing and choosing a language remembers the choice', () => {
  const store = memory()
  installLocale(store, ['zh-CN'])
  assert.equal(locale.value, 'zh-CN')
  setLocale('en', store)
  assert.equal(locale.value, 'en')
  assert.equal(store.values.get('tokenstream.locale'), 'en')
  installLocale(store, ['zh-CN'])
  assert.equal(locale.value, 'en')
  setLocale('en', store)
})
