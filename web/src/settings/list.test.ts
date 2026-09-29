import { test } from 'node:test'
import assert from 'node:assert/strict'

import type { AdminApi, SettingsPage } from '../api/client.ts'
import { loadSettings } from './list.ts'

function page(items: SettingsPage['items']): SettingsPage {
  return { items }
}

test('loadSettings asks the settings table endpoint', async () => {
  const captured: string[] = []
  const api = {
    async settings() {
      captured.push('loaded')
      return page([
        {
          name: 'TOKENSTREAM_DATA_LISTEN_ADDR',
          label: 'Data-plane listen address',
          value: '127.0.0.1:3300',
          configured: true,
          secret: false,
          restart_required: true,
          pending_restart: false,
        },
      ])
    },
  } as unknown as AdminApi
  const loaded = await loadSettings(api)
  assert.equal(captured.length, 1)
  assert.equal(loaded.items[0]?.name, 'TOKENSTREAM_DATA_LISTEN_ADDR')
})
