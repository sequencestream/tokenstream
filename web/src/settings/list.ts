import type { AdminApi, SettingsPage } from '../api/client.ts'

/** Loads the process settings table. */
export async function loadSettings(api: AdminApi): Promise<SettingsPage> {
  return api.settings()
}
