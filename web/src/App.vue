<script setup lang="ts">
import { computed, onMounted, reactive, ref, watch } from 'vue'

import { AdminApi, type ProviderHealthWrite, type ProviderStatus, type ProtocolType } from './api/client.ts'
import { emptyAccountPage, loadAccounts, type AccountPage } from './accounts/list.ts'
import { emptyApiKeyPage, loadApiKeys, type ApiKeyPage } from './keys/list.ts'
import { boundDraft, boundSummary, emptyBoundDrafts, readBounds, type BoundDrafts } from './limits/bounds.ts'
import { emptyLogFilters, logFiltersChanged, type LogFilterValues } from './logs/filters.ts'
import { loadLogs, type LogPage } from './logs/list.ts'
import { emptyProviderPage, loadProviders, type ProviderPage } from './providers/list.ts'
import { loadSettings } from './settings/list.ts'
import { useAdminSession } from './session/useAdminSession.ts'

const api = new AdminApi()
const session = useAdminSession(api)

const accountName = ref('')
const password = ref('')
const busy = ref(false)
const notice = ref('')
const errorMessage = ref('')
type View = 'providers' | 'keys' | 'accounts' | 'logs' | 'settings'
const activeView = ref<View>('keys')

const settingsPage = ref({ items: [] as import('./api/client.ts').Setting[] })
const settingDrafts = ref<Record<string, string>>({})

const providerPage = ref<ProviderPage>({ ...emptyProviderPage })
const keyPage = ref<ApiKeyPage>({ ...emptyApiKeyPage })
const accountPage = ref<AccountPage>({ ...emptyAccountPage })
const editingProviderId = ref<number | null>(null)
const creatingProvider = ref(false)
const oneTimeSecret = ref<string | null>(null)
const oneTimeAction = ref('')
const oneTimePassword = ref<string | null>(null)

function emptyCreateForm() {
  return {
    name: '',
    protocol_type: 'openai' as ProtocolType,
    endpoint: 'https://',
    upstream_api_key: '',
    status: 'enabled' as ProviderStatus,
    health: { probe_path: '', failure_threshold: '3', probe_interval_ms: '30000', probe_timeout_ms: '5000' },
    bounds: { ...emptyBoundDrafts(), max_websockets: '' },
  }
}

const createForm = reactive(emptyCreateForm())
const editForm = reactive({
  name: '',
  endpoint: '',
  upstream_api_key: '',
  status: 'enabled' as ProviderStatus,
  health: { probe_path: '', failure_threshold: '3', probe_interval_ms: '30000', probe_timeout_ms: '5000' },
  bounds: { ...emptyBoundDrafts(), max_websockets: '' },
})

const PROVIDER_BOUND_FIELDS = ['max_concurrent_requests', 'max_requests_per_second'] as const
const CREDENTIAL_BOUND_FIELDS = [
  'max_concurrent_requests',
  'max_requests_per_second',
  'max_websockets',
] as const

const accountForm = reactive({ name: '', role: 'user' as 'admin' | 'user' })
const creatingAccount = ref(false)
const keyForm = reactive({
  account_id: 0,
  name: '',
  provider_ids: [] as number[],
  default_provider_id: null as number | null,
  bounds: emptyBoundDrafts(),
})

const logPage = ref<LogPage>({ items: [], cursor: null, exhausted: true })

// The conditions the administrator is editing, and the conditions that produced
// the rows currently shown. Paging always uses the applied conditions and their
// cursor, so a half-edited form can never splice a second result set onto the
// first.
const logFilters = reactive<LogFilterValues>(emptyLogFilters())
const appliedLogFilters = reactive<LogFilterValues>(emptyLogFilters())
const logFiltersDirty = computed(() => logFiltersChanged(logFilters, appliedLogFilters))

const providers = computed(() => providerPage.value.items)
const providerById = computed(() => new Map(providers.value.map((item) => [item.id, item])))
const accountById = computed(() => new Map(accountPage.value.items.map((item) => [item.id, item])))
const isAdmin = computed(() => session.isAdmin.value)

/** A regular user's own account identifier, once it is known. */
const ownAccountId = computed(
  () => accountPage.value.items.find((item) => item.name === session.accountName.value)?.id ?? 0,
)

function clearFeedback() {
  notice.value = ''
  errorMessage.value = ''
}

/**
 * Runs one administrative action with the page's shared busy and feedback state.
 *
 * A failure that ended the session also discards the loaded providers and logs,
 * because those rows belong to a session that no longer exists.
 */
async function runAction(action: () => Promise<void>) {
  clearFeedback()
  busy.value = true
  try {
    await action()
  } catch (error) {
    errorMessage.value = session.handleFailure(error)
    if (!session.signedIn.value) {
      providerPage.value = { ...emptyProviderPage }
      logPage.value = { items: [], cursor: null, exhausted: true }
      keyPage.value = { ...emptyApiKeyPage }
      accountPage.value = { ...emptyAccountPage }
      cancelCreate()
      dismissSecret()
    }
  } finally {
    busy.value = false
  }
}

/** Loads the views this session's role can actually reach. */
async function loadReachableViews(): Promise<void> {
  const [nextProviders, nextLogs, nextKeys] = await Promise.all([
    loadProviders(api, providerPage.value, true),
    loadLogs(api, logPage.value, appliedLogFilters, true),
    loadApiKeys(api, keyPage.value, true),
  ])
  providerPage.value = nextProviders
  logPage.value = nextLogs
  keyPage.value = nextKeys
  if (session.isAdmin.value) {
    const [nextAccounts, nextSettings] = await Promise.all([
      loadAccounts(api, accountPage.value, true),
      loadSettings(api),
    ])
    accountPage.value = nextAccounts
    settingsPage.value = nextSettings
    resetSettingDrafts()
    keyForm.account_id = ownAccountId.value || (accountPage.value.items[0]?.id ?? 0)
  }
}

async function restoreSession() {
  if (await session.restore()) {
    await runAction(loadReachableViews)
  }
}

async function signIn() {
  await runAction(async () => {
    await session.signIn(accountName.value, password.value)
    accountName.value = ''
    password.value = ''
    activeView.value = 'keys'
    await loadReachableViews()
  })
}

async function signOut() {
  await runAction(async () => {
    await session.signOut()
    providerPage.value = { ...emptyProviderPage }
    logPage.value = { items: [], cursor: null, exhausted: true }
    keyPage.value = { ...emptyApiKeyPage }
    accountPage.value = { ...emptyAccountPage }
    cancelCreate()
    dismissSecret()
    activeView.value = 'keys'
  })
}

/** Keeps the credential form pointing at the signed-in account by default. */
watch(ownAccountId, (id) => {
  if (id && !keyForm.account_id) keyForm.account_id = id
})

async function loadMoreProviders() {
  await runAction(async () => {
    providerPage.value = await loadProviders(api, providerPage.value, false)
  })
}

async function loadMoreKeys() {
  await runAction(async () => {
    keyPage.value = await loadApiKeys(api, keyPage.value, false)
  })
}

async function loadMoreAccounts() {
  await runAction(async () => {
    accountPage.value = await loadAccounts(api, accountPage.value, false)
  })
}

function beginCreate() {
  Object.assign(createForm, emptyCreateForm())
  creatingProvider.value = true
  clearFeedback()
}

function cancelCreate() {
  Object.assign(createForm, emptyCreateForm())
  creatingProvider.value = false
}

async function createProvider() {
  const bounds = readBounds(createForm.bounds, PROVIDER_BOUND_FIELDS)
  if ('error' in bounds) {
    errorMessage.value = bounds.error
    return
  }
  const health = readHealth(createForm.health)
  if ('error' in health) {
    errorMessage.value = health.error
    return
  }
  await runAction(async () => {
    const { bounds: _drafts, ...fields } = createForm
    const { health: _health, ...providerFields } = fields
    await api.createProvider({ ...providerFields, ...bounds.values, ...(health.value ? { health: health.value } : {}) })
    Object.assign(createForm, emptyCreateForm())
    creatingProvider.value = false
    notice.value = 'Provider created. Issue a credential to call it.'
    providerPage.value = await loadProviders(api, providerPage.value, true)
  })
}

function beginEdit(providerId: number, source: typeof providers.value[number]) {
  editingProviderId.value = providerId
  Object.assign(editForm, {
    name: source.name,
    endpoint: source.endpoint,
    upstream_api_key: '',
    status: source.status,
    health: {
      probe_path: source.health_probe?.probe_path ?? '',
      failure_threshold: String(source.health_probe?.failure_threshold ?? 3),
      probe_interval_ms: String(source.health_probe?.probe_interval_ms ?? 30000),
      probe_timeout_ms: String(source.health_probe?.probe_timeout_ms ?? 5000),
    },
    bounds: {
      max_concurrent_requests: boundDraft(source.max_concurrent_requests),
      max_requests_per_second: boundDraft(source.max_requests_per_second),
      max_websockets: '',
    },
  })
  clearFeedback()
}

async function saveProvider(id: number) {
  const bounds = readBounds(editForm.bounds, PROVIDER_BOUND_FIELDS)
  if ('error' in bounds) {
    errorMessage.value = bounds.error
    return
  }
  const health = readHealth(editForm.health, true)
  if ('error' in health) {
    errorMessage.value = health.error
    return
  }
  await runAction(async () => {
    await api.updateProvider(id, {
      name: editForm.name,
      endpoint: editForm.endpoint,
      status: editForm.status,
      admission: bounds.values,
      health: health.value!,
      ...(editForm.upstream_api_key ? { upstream_api_key: editForm.upstream_api_key } : {}),
    })
    editingProviderId.value = null
    notice.value = 'Provider updated.'
    providerPage.value = await loadProviders(api, providerPage.value, true)
  })
}

function readHealth(
  fields: { probe_path: string; failure_threshold: string; probe_interval_ms: string; probe_timeout_ms: string },
  includeDisabled = false,
): { value: ProviderHealthWrite | null } | { error: string } {
  const probePath = fields.probe_path.trim()
  if (!probePath) {
    return includeDisabled
      ? { value: { probe_path: null, failure_threshold: null, probe_interval_ms: null, probe_timeout_ms: null } }
      : { value: null }
  }
  const values = [fields.failure_threshold, fields.probe_interval_ms, fields.probe_timeout_ms].map((value) => Number(value))
  if (values.some((value) => !Number.isSafeInteger(value) || value <= 0)) {
    return { error: 'Probe threshold, interval, and timeout must be positive integers.' }
  }
  return {
    value: {
      probe_path: probePath,
      failure_threshold: values[0],
      probe_interval_ms: values[1],
      probe_timeout_ms: values[2],
    },
  }
}

async function toggleMaintenance(id: number, maintenance: boolean) {
  await runAction(async () => {
    await api.setProviderMaintenance(id, maintenance)
    notice.value = maintenance ? 'Provider entered maintenance.' : 'Provider left maintenance.'
    providerPage.value = await loadProviders(api, providerPage.value, true)
  })
}

async function toggleProvider(id: number, current: ProviderStatus) {
  await runAction(async () => {
    const status: ProviderStatus = current === 'enabled' ? 'disabled' : 'enabled'
    await api.updateProvider(id, { status })
    notice.value = status === 'disabled' ? 'Provider disabled.' : 'Provider enabled.'
    providerPage.value = await loadProviders(api, providerPage.value, true)
  })
}

async function deleteProvider(id: number, name: string) {
  if (!window.confirm(`Delete ${name}? Providers referenced by request logs or a model alias cannot be deleted.`)) {
    return
  }
  await runAction(async () => {
    await api.deleteProvider(id)
    notice.value = 'Provider deleted.'
    providerPage.value = await loadProviders(api, providerPage.value, true)
  })
}

function beginAccount() {
  accountForm.name = ''
  accountForm.role = 'user'
  creatingAccount.value = true
  clearFeedback()
}

function cancelAccount() {
  creatingAccount.value = false
}

async function createAccount() {
  await runAction(async () => {
    const created = await api.createAccount({
      name: accountForm.name,
      role: accountForm.role,
      status: 'enabled',
    })
    creatingAccount.value = false
    if (created.generated_password) {
      oneTimePassword.value = created.generated_password
    }
    notice.value = `Account ${created.account.name} created.`
    accountPage.value = await loadAccounts(api, accountPage.value, true)
  })
}

async function toggleAccount(id: number, current: string, name: string) {
  const status = current === 'enabled' ? 'disabled' : 'enabled'
  if (status === 'disabled' && !window.confirm(`Disable ${name}? Its credentials stop working immediately.`)) {
    return
  }
  await runAction(async () => {
    await api.updateAccount(id, { status })
    notice.value = status === 'disabled' ? 'Account disabled.' : 'Account enabled.'
    accountPage.value = await loadAccounts(api, accountPage.value, true)
  })
}

async function deleteAccount(id: number, name: string) {
  if (!window.confirm(`Delete ${name}?`)) return
  await runAction(async () => {
    await api.deleteAccount(id)
    notice.value = 'Account deleted.'
    accountPage.value = await loadAccounts(api, accountPage.value, true)
  })
}

function resetKeyForm() {
  keyForm.name = ''
  keyForm.provider_ids = []
  keyForm.default_provider_id = null
  keyForm.account_id = ownAccountId.value || keyForm.account_id
  Object.assign(keyForm.bounds, emptyBoundDrafts())
}

async function issueKey() {
  const bounds = readBounds(keyForm.bounds, CREDENTIAL_BOUND_FIELDS)
  if ('error' in bounds) {
    errorMessage.value = bounds.error
    return
  }
  await runAction(async () => {
    const issued = await api.createApiKey({
      account_id: keyForm.account_id,
      name: keyForm.name,
      provider_ids: keyForm.provider_ids,
      default_provider_id: keyForm.default_provider_id,
      status: 'enabled',
      ...bounds.values,
    })
    showSecret(issued.api_key_secret, `Credential for ${issued.api_key.name}`)
    resetKeyForm()
    keyPage.value = await loadApiKeys(api, keyPage.value, true)
  })
}

async function toggleProviderBinding(providerId: number) {
  const bound = keyForm.provider_ids.includes(providerId)
  keyForm.provider_ids = bound
    ? keyForm.provider_ids.filter((id) => id !== providerId)
    : [...keyForm.provider_ids, providerId]
  if (keyForm.default_provider_id !== null && !keyForm.provider_ids.includes(keyForm.default_provider_id)) {
    keyForm.default_provider_id = null
  }
}

async function rotateKey(id: number, name: string) {
  if (!window.confirm(`Rotate the credential for ${name}? The old credential stops working immediately.`)) {
    return
  }
  await runAction(async () => {
    const rotated = await api.rotateApiKey(id)
    showSecret(rotated.api_key_secret, `New credential for ${rotated.api_key.name}`)
    keyPage.value = await loadApiKeys(api, keyPage.value, true)
  })
}

async function deleteKey(id: number, name: string) {
  if (!window.confirm(`Delete the credential for ${name}? Clients using it stop working immediately.`)) {
    return
  }
  await runAction(async () => {
    await api.deleteApiKey(id)
    notice.value = 'Credential deleted.'
    keyPage.value = await loadApiKeys(api, keyPage.value, true)
  })
}

function showSecret(value: string, action: string) {
  oneTimeSecret.value = value
  oneTimeAction.value = action
}

function dismissSecret() {
  oneTimeSecret.value = null
  oneTimeAction.value = ''
  oneTimePassword.value = null
}

async function copyPassword() {
  if (!oneTimePassword.value) return
  await navigator.clipboard.writeText(oneTimePassword.value)
  notice.value = 'Password copied.'
}

async function copySecret() {
  if (!oneTimeSecret.value) return
  await navigator.clipboard.writeText(oneTimeSecret.value)
  notice.value = 'Credential copied. Store it securely before closing this message.'
}

async function loadMoreLogs() {
  await runAction(async () => {
    logPage.value = await loadLogs(api, logPage.value, appliedLogFilters, false)
  })
}

async function applyLogFilters() {
  await runAction(async () => {
    Object.assign(appliedLogFilters, { ...logFilters })
    logPage.value = await loadLogs(api, logPage.value, appliedLogFilters, true)
  })
}

function resetLogFilters() {
  Object.assign(logFilters, emptyLogFilters())
  void applyLogFilters()
}

function resetSettingDrafts() {
  const drafts: Record<string, string> = {}
  for (const item of settingsPage.value.items) {
    drafts[item.name] = item.secret ? '' : (item.value ?? '')
  }
  settingDrafts.value = drafts
}

async function saveSettings() {
  await runAction(async () => {
    const patch: Record<string, string> = {}
    for (const item of settingsPage.value.items) {
      const draft = settingDrafts.value[item.name] ?? ''
      if (item.secret) {
        if (draft) patch[item.name] = draft
        continue
      }
      if (draft !== (item.value ?? '')) patch[item.name] = draft
    }
    if (Object.keys(patch).length === 0) {
      notice.value = 'No settings were changed.'
      return
    }
    settingsPage.value = await api.updateSettings(patch)
    resetSettingDrafts()
    const pending = settingsPage.value.items.some((item) => item.pending_restart)
    notice.value = pending
      ? 'Settings saved. Some values apply after the process restarts.'
      : 'Settings saved.'
  })
}

function formatDate(value: string | null) {
  if (!value) return '—'
  return new Intl.DateTimeFormat(undefined, {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  }).format(new Date(value))
}

function providerName(providerId: number) {
  return providerById.value.get(providerId)?.name ?? `#${providerId}`
}

function accountLabel(accountId: number) {
  const account = accountById.value.get(accountId)
  return account ? account.name : `#${accountId}`
}

function viewTitle(view: View) {
  if (view === 'providers') return 'Providers'
  if (view === 'accounts') return 'Accounts'
  if (view === 'logs') return 'Request logs'
  if (view === 'settings') return 'Settings'
  return 'Credentials'
}

function viewLede(view: View) {
  if (view === 'providers') return 'Upstream identities and endpoints. A provider issues no credential.'
  if (view === 'accounts') return 'Principals that own data-plane credentials.'
  if (view === 'logs') return 'Transport metadata for proxied requests. Payloads are not stored.'
  if (view === 'settings') return 'Process configuration. Secrets are write-only; bind-time values apply after restart.'
  return 'API keys owned by an account, each bound to the providers it may reach.'
}

onMounted(restoreSession)
</script>

<template>
  <div class="shell">
    <header class="masthead">
      <a class="brand" href="/" aria-label="Tokenstream administration">
        <span class="brand-mark">T</span>
        <span>Tokenstream</span>
      </a>
      <nav v-if="session.signedIn.value" class="tabs" aria-label="Administration views">
        <button
          :class="{ active: activeView === 'keys' }"
          :aria-current="activeView === 'keys' ? 'page' : undefined"
          @click="activeView = 'keys'"
        >Credentials</button>
        <button
          v-if="isAdmin"
          :class="{ active: activeView === 'providers' }"
          :aria-current="activeView === 'providers' ? 'page' : undefined"
          @click="activeView = 'providers'"
        >Providers</button>
        <button
          v-if="isAdmin"
          :class="{ active: activeView === 'accounts' }"
          :aria-current="activeView === 'accounts' ? 'page' : undefined"
          @click="activeView = 'accounts'"
        >Accounts</button>
        <button
          :class="{ active: activeView === 'logs' }"
          :aria-current="activeView === 'logs' ? 'page' : undefined"
          @click="activeView = 'logs'"
        >Request logs</button>
        <button
          v-if="isAdmin"
          :class="{ active: activeView === 'settings' }"
          :aria-current="activeView === 'settings' ? 'page' : undefined"
          @click="activeView = 'settings'"
        >Settings</button>
      </nav>
      <span v-if="session.signedIn.value" class="identity">
        {{ session.accountName.value }}
        <span class="badge neutral">{{ session.role.value }}</span>
      </span>
      <button v-if="session.signedIn.value" class="button ghost sign-out" :disabled="busy" @click="signOut">Sign out</button>
    </header>

    <main v-if="session.checking.value" class="center-card" aria-live="polite">
      <div class="spinner"></div>
      <p>Checking your session…</p>
    </main>

    <main v-else-if="!session.signedIn.value" class="login-layout">
      <form class="card login-card" @submit.prevent="signIn">
        <h2>Sign in</h2>
        <p class="login-note">Access to this control plane.</p>
        <label>
          Account
          <input v-model="accountName" autocomplete="username" required autofocus placeholder="admin" />
        </label>
        <label>
          Password
          <input v-model="password" type="password" autocomplete="current-password" required />
        </label>
        <p v-if="errorMessage" class="alert error" role="alert">{{ errorMessage }}</p>
        <button class="button primary" :disabled="busy">{{ busy ? 'Signing in…' : 'Sign in' }}</button>
      </form>
    </main>

    <main v-else class="workspace">
      <section class="page-heading">
        <div>
          <h1>{{ viewTitle(activeView) }}</h1>
          <p class="lede">{{ viewLede(activeView) }}</p>
        </div>
        <button
          v-if="isAdmin && activeView === 'providers' && !creatingProvider"
          class="button primary"
          type="button"
          :disabled="busy"
          @click="beginCreate"
        >New provider</button>
        <button
          v-if="isAdmin && activeView === 'accounts' && !creatingAccount"
          class="button primary"
          type="button"
          :disabled="busy"
          @click="beginAccount"
        >New account</button>
      </section>

      <p v-if="errorMessage" class="alert error" role="alert">{{ errorMessage }}</p>
      <p v-if="notice" class="alert success" role="status">{{ notice }}</p>

      <section v-if="oneTimeSecret" class="credential-card" aria-live="assertive">
        <div>
          <h2>{{ oneTimeAction }}</h2>
          <p>Shown once. Copy it now; it disappears when dismissed or when the page is refreshed.</p>
        </div>
        <code>{{ oneTimeSecret }}</code>
        <div class="actions">
          <button class="button primary" @click="copySecret">Copy credential</button>
          <button class="button ghost" @click="dismissSecret">I have stored it</button>
        </div>
      </section>

      <section v-if="oneTimePassword" class="credential-card" aria-live="assertive">
        <div>
          <h2>Password for the new account</h2>
          <p>Shown once. It is never returned again; a new password can be set at any time.</p>
        </div>
        <code>{{ oneTimePassword }}</code>
        <div class="actions">
          <button class="button primary" @click="copyPassword">Copy password</button>
          <button class="button ghost" @click="dismissSecret">I have stored it</button>
        </div>
      </section>

      <template v-if="activeView === 'keys'">
        <section class="card create-card">
          <div class="section-title">
            <h2>Issue credential</h2>
            <span class="section-note">The plaintext is shown once.</span>
          </div>
          <form class="provider-form" @submit.prevent="issueKey">
            <label>Name<input v-model="keyForm.name" maxlength="128" required placeholder="ci" /></label>
            <label v-if="isAdmin">
              Owning account
              <select v-model.number="keyForm.account_id" required>
                <option v-for="account in accountPage.items" :key="account.id" :value="account.id">{{ account.name }}</option>
              </select>
            </label>
            <fieldset class="wide bindings">
              <legend>Providers this credential may reach</legend>
              <label v-for="provider in providers" :key="provider.id" class="binding">
                <input
                  type="checkbox"
                  :value="provider.id"
                  :checked="keyForm.provider_ids.includes(provider.id)"
                  @change="toggleProviderBinding(provider.id)"
                />
                {{ provider.name }}
              </label>
              <p v-if="providers.length === 0" class="section-note">No providers exist yet.</p>
            </fieldset>
            <label v-if="isAdmin" class="wide">
              Default provider
              <select v-model="keyForm.default_provider_id">
                <option :value="null">First bound provider</option>
                <option v-for="id in keyForm.provider_ids" :key="id" :value="id">{{ providerName(id) }}</option>
              </select>
            </label>
            <fieldset class="wide bounds">
              <legend>Admission bounds for this credential</legend>
              <label>Max concurrent
                <input v-model="keyForm.bounds.max_concurrent_requests" inputmode="numeric" placeholder="unbounded" aria-label="Max concurrent requests" />
              </label>
              <label>Requests per second
                <input v-model="keyForm.bounds.max_requests_per_second" inputmode="numeric" placeholder="unbounded" aria-label="Max requests per second" />
              </label>
              <label>Max WebSockets
                <input v-model="keyForm.bounds.max_websockets" inputmode="numeric" placeholder="unbounded" aria-label="Max WebSocket connections" />
              </label>
              <p class="section-note">Leave a field empty for no bound. A bound of 0 is refused.</p>
            </fieldset>
            <div class="actions wide">
              <button class="button primary" :disabled="busy" :title="keyForm.provider_ids.length === 0 ? 'Bind at least one provider' : undefined">Create credential</button>
            </div>
          </form>
        </section>

        <section class="card table-card" aria-label="Credentials">
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Name</th>
                  <th v-if="isAdmin">Account</th>
                  <th>Status</th>
                  <th class="fill">Providers</th>
                  <th>Bounds</th>
                  <th>Key ID</th>
                  <th>Expires</th>
                  <th>Created</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="key in keyPage.items" :key="key.id">
                  <td>{{ key.id }}</td>
                  <td>{{ key.name }}</td>
                  <td v-if="isAdmin">{{ accountLabel(key.account_id) }}</td>
                  <td><span class="badge" :class="key.status">{{ key.status }}</span></td>
                  <td class="fill">
                    <span v-for="(id, index) in key.provider_ids" :key="id">
                      {{ providerName(id) }}<span v-if="id === key.default_provider_id"> (default)</span>{{ index < key.provider_ids.length - 1 ? ', ' : '' }}
                    </span>
                  </td>
                  <td>{{ boundSummary([['conc', key.max_concurrent_requests], ['rate', key.max_requests_per_second], ['WS', key.max_websockets]]) }}</td>
                  <td><code>{{ key.key_id }}</code></td>
                  <td>{{ formatDate(key.expires_at) }}</td>
                  <td>{{ formatDate(key.created_at) }}</td>
                  <td class="row-actions">
                    <div class="actions">
                      <button class="button ghost" :disabled="busy" @click="rotateKey(key.id, key.name)">Rotate credential</button>
                      <button class="button danger" :disabled="busy" @click="deleteKey(key.id, key.name)">Delete</button>
                    </div>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
          <div v-if="keyPage.items.length === 0" class="empty-state">No credentials issued.</div>
          <button v-if="!keyPage.exhausted" class="button load-more" :disabled="busy" @click="loadMoreKeys">Load more</button>
        </section>
      </template>

      <template v-else-if="activeView === 'providers'">
        <section v-if="creatingProvider" class="card create-card">
          <div class="section-title">
            <h2>Add provider</h2>
            <span class="section-note">The upstream key is write-only.</span>
          </div>
          <form class="provider-form" @submit.prevent="createProvider">
            <label>Name<input v-model="createForm.name" maxlength="128" required placeholder="primary-openai" /></label>
            <label>Protocol<select v-model="createForm.protocol_type"><option value="openai">OpenAI</option><option value="anthropic">Anthropic</option></select></label>
            <label>Status<select v-model="createForm.status"><option value="enabled">Enabled</option><option value="disabled">Disabled</option></select></label>
            <label class="wide">Endpoint<input v-model="createForm.endpoint" type="url" required placeholder="https://api.example.com" /></label>
            <label class="wide">Upstream API key<input v-model="createForm.upstream_api_key" type="password" autocomplete="new-password" required /></label>
            <fieldset class="wide bounds">
              <legend>Admission bounds</legend>
              <label>Max concurrent
                <input v-model="createForm.bounds.max_concurrent_requests" inputmode="numeric" placeholder="unbounded" aria-label="Max concurrent requests" />
              </label>
              <label>Requests per second
                <input v-model="createForm.bounds.max_requests_per_second" inputmode="numeric" placeholder="unbounded" aria-label="Max requests per second" />
              </label>
              <p class="section-note">Leave a field empty for no bound. A bound of 0 is refused.</p>
            </fieldset>
            <fieldset class="wide bounds">
              <legend>Health probe</legend>
              <label>Path<input v-model="createForm.health.probe_path" placeholder="disabled" aria-label="Probe path" /></label>
              <label>Failure threshold<input v-model="createForm.health.failure_threshold" inputmode="numeric" aria-label="Probe failure threshold" /></label>
              <label>Interval (ms)<input v-model="createForm.health.probe_interval_ms" inputmode="numeric" aria-label="Probe interval milliseconds" /></label>
              <label>Timeout (ms)<input v-model="createForm.health.probe_timeout_ms" inputmode="numeric" aria-label="Probe timeout milliseconds" /></label>
              <p class="section-note">Leave the path empty to disable probing. Probes carry no credentials or request body.</p>
            </fieldset>
            <div class="actions wide">
              <button class="button primary" :disabled="busy">Create provider</button>
              <button class="button ghost" type="button" @click="cancelCreate">Cancel</button>
            </div>
          </form>
        </section>

        <section class="card table-card" aria-label="Providers">
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Name</th>
                  <th>Protocol</th>
                  <th>Status</th>
                  <th>Health</th>
                  <th class="fill">Endpoint</th>
                  <th>Upstream key</th>
                  <th>Bounds</th>
                  <th>Created</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                <template v-for="provider in providers" :key="provider.id">
                  <tr v-if="editingProviderId === provider.id">
                    <td>{{ provider.id }}</td>
                    <td><input v-model="editForm.name" maxlength="128" required aria-label="Name" /></td>
                    <td><span class="badge neutral">{{ provider.protocol_type }}</span></td>
                    <td>
                      <select v-model="editForm.status" aria-label="Status">
                        <option value="enabled">Enabled</option>
                        <option value="disabled">Disabled</option>
                      </select>
                    </td>
                    <td>
                      <div class="row-probe">
                        <span class="badge" :class="provider.health">{{ provider.health }}</span>
                        <input v-model="editForm.health.probe_path" placeholder="probe disabled" aria-label="Probe path" />
                        <input v-model="editForm.health.failure_threshold" inputmode="numeric" aria-label="Probe failure threshold" />
                        <input v-model="editForm.health.probe_interval_ms" inputmode="numeric" aria-label="Probe interval milliseconds" />
                        <input v-model="editForm.health.probe_timeout_ms" inputmode="numeric" aria-label="Probe timeout milliseconds" />
                      </div>
                    </td>
                    <td class="fill"><input v-model="editForm.endpoint" type="url" required aria-label="Endpoint" /></td>
                    <td>
                      <input
                        v-model="editForm.upstream_api_key"
                        type="password"
                        autocomplete="new-password"
                        placeholder="unchanged"
                        aria-label="Replace upstream API key"
                      />
                    </td>
                    <td>
                      <div class="row-bounds">
                        <input
                          v-model="editForm.bounds.max_concurrent_requests"
                          inputmode="numeric"
                          placeholder="unbounded"
                          aria-label="Max concurrent requests"
                        />
                        <input
                          v-model="editForm.bounds.max_requests_per_second"
                          inputmode="numeric"
                          placeholder="unbounded"
                          aria-label="Max requests per second"
                        />
                      </div>
                    </td>
                    <td>{{ formatDate(provider.created_at) }}</td>
                    <td class="row-actions">
                      <div class="actions">
                        <button class="button primary" :disabled="busy" @click="saveProvider(provider.id)">Save changes</button>
                        <button class="button ghost" type="button" @click="editingProviderId = null">Cancel</button>
                      </div>
                    </td>
                  </tr>
                  <tr v-else>
                    <td>{{ provider.id }}</td>
                    <td>{{ provider.name }}</td>
                    <td><span class="badge neutral">{{ provider.protocol_type }}</span></td>
                    <td><span class="badge" :class="provider.status">{{ provider.status }}</span></td>
                    <td>
                      <span class="badge" :class="provider.health">{{ provider.health }}</span>
                      <small v-if="provider.health_probe">{{ provider.health_probe.probe_path }} · {{ provider.health_probe.failure_threshold }} failures · {{ provider.health_probe.probe_interval_ms }} ms</small>
                      <small v-else>Probe disabled</small>
                    </td>
                    <td class="fill">{{ provider.endpoint }}</td>
                    <td>{{ provider.has_upstream_api_key ? 'Configured' : 'Not configured' }}</td>
                    <td>{{ boundSummary([['conc', provider.max_concurrent_requests], ['rate', provider.max_requests_per_second]]) }}</td>
                    <td>{{ formatDate(provider.created_at) }}</td>
                    <td class="row-actions">
                      <div class="actions">
                        <button class="button ghost" @click="beginEdit(provider.id, provider)">Edit</button>
                        <button
                          class="button ghost"
                          :disabled="busy"
                          @click="toggleMaintenance(provider.id, provider.health !== 'maintenance')"
                        >{{ provider.health === 'maintenance' ? 'Leave maintenance' : 'Maintenance' }}</button>
                        <button class="button ghost" :disabled="busy" @click="toggleProvider(provider.id, provider.status)">{{ provider.status === 'enabled' ? 'Disable' : 'Enable' }}</button>
                        <button class="button danger" :disabled="busy" @click="deleteProvider(provider.id, provider.name)">Delete</button>
                      </div>
                    </td>
                  </tr>
                </template>
              </tbody>
            </table>
          </div>
          <div v-if="providers.length === 0" class="empty-state">No providers configured.</div>
          <button v-if="!providerPage.exhausted" class="button load-more" :disabled="busy" @click="loadMoreProviders">Load more</button>
        </section>
      </template>

      <template v-else-if="activeView === 'accounts'">
        <section v-if="creatingAccount" class="card create-card">
          <div class="section-title">
            <h2>Add account</h2>
            <span class="section-note">The password is shown once.</span>
          </div>
          <form class="provider-form" @submit.prevent="createAccount">
            <label>Name<input v-model="accountForm.name" maxlength="128" required placeholder="analyst" /></label>
            <label>Role<select v-model="accountForm.role"><option value="user">User</option><option value="admin">Administrator</option></select></label>
            <div class="actions wide">
              <button class="button primary" :disabled="busy">Create account</button>
              <button class="button ghost" type="button" @click="cancelAccount">Cancel</button>
            </div>
          </form>
        </section>

        <section class="card table-card" aria-label="Accounts">
          <div class="table-wrap">
            <table>
              <thead>
                <tr><th>ID</th><th>Name</th><th>Role</th><th>Status</th><th>Created</th><th>Actions</th></tr>
              </thead>
              <tbody>
                <tr v-for="account in accountPage.items" :key="account.id">
                  <td>{{ account.id }}</td>
                  <td>
                    {{ account.name }}
                    <span v-if="account.is_bootstrap" class="badge neutral">bootstrap</span>
                  </td>
                  <td><span class="badge neutral">{{ account.role }}</span></td>
                  <td><span class="badge" :class="account.status">{{ account.status }}</span></td>
                  <td>{{ formatDate(account.created_at) }}</td>
                  <td class="row-actions">
                    <div class="actions">
                      <button
                        class="button ghost"
                        :disabled="busy || account.is_bootstrap"
                        :title="account.is_bootstrap ? 'The bootstrap account cannot be disabled' : undefined"
                        @click="toggleAccount(account.id, account.status, account.name)"
                      >{{ account.status === 'enabled' ? 'Disable' : 'Enable' }}</button>
                      <button
                        class="button danger"
                        :disabled="busy || account.is_bootstrap"
                        :title="account.is_bootstrap ? 'The bootstrap account cannot be deleted' : undefined"
                        @click="deleteAccount(account.id, account.name)"
                      >Delete</button>
                    </div>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
          <div v-if="accountPage.items.length === 0" class="empty-state">No accounts.</div>
          <button v-if="!accountPage.exhausted" class="button load-more" :disabled="busy" @click="loadMoreAccounts">Load more</button>
        </section>
      </template>

      <template v-else-if="activeView === 'logs'">
        <section class="card filters-card">
          <form class="filters" @submit.prevent="applyLogFilters">
            <label>Provider<select v-model="logFilters.provider_id"><option value="">All providers</option><option v-for="provider in providers" :key="provider.id" :value="String(provider.id)">{{ provider.name }}</option></select></label>
            <label>Transport<select v-model="logFilters.transport_type"><option value="">All transports</option><option value="http">HTTP / SSE</option><option value="websocket">WebSocket</option></select></label>
            <label>Started after<input v-model="logFilters.start_time_gte" type="datetime-local" /></label>
            <label>Started before<input v-model="logFilters.start_time_lt" type="datetime-local" /></label>
            <div class="actions filter-actions"><button class="button primary" :disabled="busy">Apply filters</button><button class="button ghost" type="button" @click="resetLogFilters">Reset</button></div>
          </form>
          <p v-if="logFiltersDirty" class="filters-pending" role="status">
            Filters are edited but not applied. Paging continues in the applied result set.
          </p>
        </section>

        <section class="card table-card">
          <div class="table-wrap">
            <table>
              <thead><tr><th>Request</th><th>Account</th><th>Provider</th><th>Transport</th><th class="fill">Route</th><th>Status</th><th>Started</th><th>Completed</th></tr></thead>
              <tbody>
                <tr v-for="log in logPage.items" :key="log.id">
                  <td><code>{{ log.request_id }}</code></td>
                  <td>{{ isAdmin ? accountLabel(log.account_id) : session.accountName.value }}</td>
                  <td>{{ providerName(log.provider_id) }}</td>
                  <td>{{ log.transport_type }}</td>
                  <td class="fill"><code>{{ log.path }}</code></td>
                  <td><span v-if="log.incomplete" class="badge incomplete">Incomplete</span><span v-else>{{ log.status_code ?? '—' }}</span><small v-if="log.error_msg" class="row-error">{{ log.error_msg }}</small></td>
                  <td>{{ formatDate(log.start_time) }}</td>
                  <td>{{ formatDate(log.end_time) }}</td>
                </tr>
              </tbody>
            </table>
          </div>
          <div v-if="logPage.items.length === 0" class="empty-state">No request metadata matches these filters.</div>
          <button v-if="!logPage.exhausted" class="button load-more" :disabled="busy" @click="loadMoreLogs">Load more</button>
        </section>
      </template>

      <template v-else>
        <section class="card table-card">
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Setting</th>
                  <th class="fill">Value</th>
                  <th>Applies</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="item in settingsPage.items" :key="item.name">
                  <td>
                    <strong>{{ item.label }}</strong>
                    <small>{{ item.name }}</small>
                  </td>
                  <td class="fill">
                    <input
                      v-model="settingDrafts[item.name]"
                      :type="item.secret ? 'password' : 'text'"
                      :placeholder="item.secret ? 'unchanged' : ''"
                      :autocomplete="item.secret ? 'new-password' : 'off'"
                    />
                  </td>
                  <td>
                    <span v-if="item.pending_restart" class="badge incomplete">Restart pending</span>
                    <span v-else-if="item.restart_required" class="badge neutral">Next start</span>
                    <span v-else class="badge enabled">Live</span>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
          <div class="actions settings-actions">
            <button class="button primary" :disabled="busy" @click="saveSettings">Save settings</button>
          </div>
        </section>
      </template>
    </main>
  </div>
</template>
<style>
:root {
  --color-ink: #1a211d;
  --color-muted: #5d6a63;
  --color-line: #d7dcd6;
  --color-fill: #f3f4f1;
  --color-paper: #fcfdfb;
  --color-control-fill: #f7f8f5;
  --color-control-ink: #24352b;
  --color-accent: #1d6b49;
  --color-accent-ink: #154e35;
  --color-on-accent: #ffffff;
  --color-inverse: #173d2a;
  --color-on-inverse: #effff4;
  --color-credential-fill: #e7f3e4;
  --color-credential-line: #c3dcc0;
  --color-danger: #8d2e27;
  --color-danger-fill: #fff8f7;
  --color-danger-line: #e3c4bf;
  --color-danger-wash: #fce8e5;
  --color-success: #24593c;
  --color-success-fill: #e3f1e7;
  --color-success-line: #c2dfca;
  --color-warning: #7c570e;
  --color-warning-fill: #f7e9bc;
  --color-enabled: #20613f;
  --color-enabled-fill: #d9efdf;
  --color-neutral: #47584d;
  --color-neutral-fill: #e8ece6;
  --color-focus: rgba(29, 107, 73, .14);
  --opacity-disabled: .58;

  --font-ui: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  --font-mono: ui-monospace, "SFMono-Regular", Consolas, monospace;
  --font-size-root: 13px;
  --font-size-page: 15px;
  --font-size-title: 12px;
  --font-size-body: 12px;
  --font-size-ui: 11px;
  --font-size-meta: 10px;
  --font-weight-medium: 500;
  --font-weight-semibold: 600;
  --font-weight-bold: 700;
  --line-height: 1.4;
  --tracking-tight: -.03em;
  --tracking-meta: .05em;

  --space-1: 4px;
  --space-compact: 6px;
  --space-2: 8px;
  --space-3: 12px;
  --space-4: 16px;
  --space-5: 20px;
  --space-6: 24px;
  --space-8: 32px;

  --radius-sm: 3px;
  --radius-md: 5px;
  --control-height: 24px;
  --control-height-lg: 28px;
  --masthead-height: 44px;
  --page-min-width: 1024px;
  --login-width: 352px;
  --mark-size: 18px;
  --z-masthead: 10;

  font-size: var(--font-size-root);
  color: var(--color-ink);
  background: var(--color-fill);
  font-family: var(--font-ui);
  line-height: var(--line-height);
  font-synthesis: none;
}

* { box-sizing: border-box; }
html, body { min-width: var(--page-min-width); }
body { margin: 0; min-height: 100vh; }
button, input, select { font: inherit; }
button { cursor: pointer; }
button:disabled { cursor: wait; opacity: var(--opacity-disabled); }
code { font-family: var(--font-mono); font-size: .92em; overflow-wrap: anywhere; }

.shell { min-width: var(--page-min-width); min-height: 100vh; background: var(--color-fill); }
.masthead {
  position: sticky;
  top: 0;
  z-index: var(--z-masthead);
  display: grid;
  grid-template-columns: auto 1fr auto auto;
  align-items: stretch;
  column-gap: var(--space-3);
  min-height: var(--masthead-height);
  padding: 0 var(--space-5);
  border-bottom: 1px solid var(--color-line);
  background: var(--color-paper);
}
.identity {
  display: inline-flex;
  align-items: center;
  gap: var(--space-2);
  align-self: center;
  color: var(--color-muted);
  font-size: var(--font-size-ui);
  white-space: nowrap;
}
.brand {
  display: inline-flex;
  align-items: center;
  gap: var(--space-2);
  color: inherit;
  text-decoration: none;
  font-size: var(--font-size-title);
  font-weight: var(--font-weight-semibold);
  letter-spacing: -.02em;
}
.brand-mark {
  display: grid;
  place-items: center;
  width: var(--mark-size);
  height: var(--mark-size);
  color: var(--color-on-inverse);
  background: var(--color-accent);
  border-radius: var(--radius-sm);
  font-size: var(--font-size-meta);
  font-weight: var(--font-weight-bold);
}
.tabs { display: flex; align-items: stretch; min-width: 0; }
.tabs button {
  padding: 0 var(--space-3);
  border: 0;
  border-bottom: 2px solid transparent;
  color: var(--color-muted);
  background: transparent;
  font-size: var(--font-size-ui);
  font-weight: var(--font-weight-medium);
  white-space: nowrap;
}
.tabs button:hover { color: var(--color-ink); }
.tabs button.active {
  color: var(--color-accent-ink);
  border-bottom-color: var(--color-accent);
  font-weight: var(--font-weight-semibold);
}
.workspace {
  width: 100%;
  min-width: var(--page-min-width);
  padding: var(--space-4) var(--space-5) var(--space-8);
}
.page-heading {
  display: flex;
  align-items: start;
  justify-content: space-between;
  gap: var(--space-3);
  margin-bottom: var(--space-3);
}
.page-heading > .button { flex-shrink: 0; }
h1, h2, p { margin-top: 0; }
h1 {
  margin-bottom: 0;
  font-size: var(--font-size-page);
  line-height: 1.25;
  letter-spacing: var(--tracking-tight);
  font-weight: var(--font-weight-semibold);
}
h2 {
  margin-bottom: 0;
  font-size: var(--font-size-title);
  letter-spacing: -.01em;
  font-weight: var(--font-weight-semibold);
}
.lede { margin: var(--space-1) 0 0; color: var(--color-muted); font-size: var(--font-size-ui); }
.card {
  background: var(--color-paper);
  border: 1px solid var(--color-line);
  border-radius: var(--radius-md);
}
.button {
  min-height: var(--control-height);
  padding: var(--space-1) var(--space-2);
  border: 1px solid var(--color-line);
  border-radius: var(--radius-md);
  color: var(--color-control-ink);
  background: var(--color-control-fill);
  font-size: var(--font-size-ui);
  font-weight: var(--font-weight-semibold);
}
.button.primary { border-color: var(--color-accent); color: var(--color-on-accent); background: var(--color-accent); }
.button.danger { border-color: var(--color-danger-line); color: var(--color-danger); background: var(--color-danger-fill); }
.button.ghost { background: transparent; }
.button.sign-out { align-self: center; border-color: transparent; }
.center-card {
  min-height: calc(100vh - var(--masthead-height));
  display: grid;
  place-content: center;
  justify-items: center;
  color: var(--color-muted);
}
.spinner {
  width: var(--mark-size);
  height: var(--mark-size);
  border: 2px solid var(--color-line);
  border-top-color: var(--color-accent);
  border-radius: 50%;
  animation: spin .8s linear infinite;
}
@keyframes spin { to { transform: rotate(360deg); } }
.login-layout {
  display: grid;
  place-items: center;
  min-height: calc(100vh - var(--masthead-height));
  padding: var(--space-5);
}
.login-card { width: min(var(--login-width), 100%); padding: var(--space-4) var(--space-5); }
.login-card h2 { margin-bottom: var(--space-1); }
.login-note { margin: 0 0 var(--space-3); color: var(--color-muted); font-size: var(--font-size-ui); }
label {
  display: grid;
  gap: var(--space-1);
  color: var(--color-muted);
  font-size: var(--font-size-meta);
  font-weight: var(--font-weight-semibold);
}
label span { font-weight: var(--font-weight-medium); }
input, select {
  width: 100%;
  min-height: var(--control-height);
  padding: var(--space-1) var(--space-2);
  border: 1px solid var(--color-line);
  border-radius: var(--radius-md);
  color: var(--color-ink);
  background: var(--color-paper);
  outline: none;
}
input:focus, select:focus {
  border-color: var(--color-accent);
  box-shadow: 0 0 0 2px var(--color-focus);
}
.login-card label { margin-bottom: var(--space-3); }
.login-card .button { width: 100%; min-height: var(--control-height-lg); }
.alert {
  margin: 0 0 var(--space-2);
  padding: var(--space-compact) var(--space-2);
  border-radius: var(--radius-md);
  font-size: var(--font-size-ui);
}
.alert.error { color: var(--color-danger); background: var(--color-danger-wash); border: 1px solid var(--color-danger-line); }
.alert.success { color: var(--color-success); background: var(--color-success-fill); border: 1px solid var(--color-success-line); }
.credential-card {
  display: grid;
  grid-template-columns: 1fr auto;
  gap: var(--space-2) var(--space-3);
  margin-bottom: var(--space-2);
  padding: var(--space-3);
  color: var(--color-accent-ink);
  background: var(--color-credential-fill);
  border: 1px solid var(--color-credential-line);
  border-radius: var(--radius-md);
}
.credential-card p { margin: var(--space-1) 0 0; color: var(--color-muted); font-size: var(--font-size-ui); }
.credential-card code {
  grid-column: 1 / -1;
  padding: var(--space-compact) var(--space-2);
  color: var(--color-on-inverse);
  background: var(--color-inverse);
  border-radius: var(--radius-sm);
  font-size: var(--font-size-ui);
}
.actions { display: flex; flex-wrap: wrap; gap: var(--space-compact); }
.credential-card .actions { grid-column: 1 / -1; }
.create-card, .filters-card { width: 100%; margin-bottom: var(--space-2); padding: var(--space-3); }
.section-title {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: var(--space-3);
  margin-bottom: var(--space-2);
}
.section-note { color: var(--color-muted); font-size: var(--font-size-ui); }
.provider-form { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: var(--space-2) var(--space-3); }
.provider-form .wide { grid-column: 1 / -1; }
.bindings {
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-2) var(--space-4);
  margin: 0;
  padding: var(--space-2) var(--space-3);
  border: 1px solid var(--color-line);
  border-radius: var(--radius-md);
}
.bindings legend { padding: 0 var(--space-1); color: var(--color-muted); font-size: var(--font-size-meta); }
.bounds { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: var(--space-2) var(--space-3); }
.bounds .section-note { grid-column: 1 / -1; margin: 0; }
.row-bounds { display: grid; gap: var(--space-1); }
.row-probe { display: grid; gap: var(--space-1); min-width: 10rem; }
.binding { display: inline-flex; align-items: center; gap: var(--space-1); margin: 0; }
.binding input { width: auto; min-width: 0; }
.badge {
  display: inline-flex;
  padding: 1px var(--space-compact);
  border-radius: var(--radius-sm);
  font-size: var(--font-size-meta);
  font-weight: var(--font-weight-bold);
  letter-spacing: var(--tracking-meta);
  text-transform: uppercase;
}
.badge.enabled { color: var(--color-enabled); background: var(--color-enabled-fill); }
.badge.disabled { color: var(--color-danger); background: var(--color-danger-fill); }
.badge.healthy { color: var(--color-success); background: var(--color-success-fill); }
.badge.isolated, .badge.maintenance { color: var(--color-warning); background: var(--color-warning-fill); }
.badge.neutral { color: var(--color-neutral); background: var(--color-neutral-fill); }
.badge.incomplete { color: var(--color-warning); background: var(--color-warning-fill); }
.filters { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)) auto; gap: var(--space-2) var(--space-3); align-items: end; }
.filter-actions { padding-bottom: 1px; }
.table-card { overflow: hidden; width: 100%; }
.table-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; font-size: var(--font-size-body); }
th, td {
  padding: var(--space-compact) var(--space-3);
  border-bottom: 1px solid var(--color-line);
  text-align: left;
  vertical-align: middle;
  white-space: nowrap;
}
th {
  color: var(--color-muted);
  background: var(--color-control-fill);
  font-size: var(--font-size-meta);
  font-weight: var(--font-weight-bold);
  letter-spacing: var(--tracking-meta);
  text-transform: uppercase;
}
td input, td select { min-width: 8rem; width: 100%; }
th.fill, td.fill { width: 100%; }
.row-actions { width: 1%; }
.row-actions .actions { flex-wrap: nowrap; }
.row-error { display: block; margin-top: var(--space-1); color: var(--color-danger); }
.empty-state { padding: var(--space-6) var(--space-4); color: var(--color-muted); text-align: center; font-size: var(--font-size-ui); }
.load-more { display: block; margin: var(--space-2) auto; }
.filters-pending { margin: var(--space-2) 0 0; color: var(--color-muted); font-size: var(--font-size-ui); }
.settings-actions { padding: var(--space-2) var(--space-3) var(--space-3); }
td small { display: block; margin-top: var(--space-1); color: var(--color-muted); font-weight: var(--font-weight-medium); letter-spacing: 0; text-transform: none; }

@media (max-width: 780px) {
  .masthead {
    grid-template-columns: 1fr auto auto;
    grid-template-areas: "brand ident out" "tabs tabs tabs";
    min-height: 0;
    padding: 0 var(--space-3);
  }
  .brand { grid-area: brand; height: 40px; }
  .identity { grid-area: ident; }
  .sign-out { grid-area: out; }
  .tabs { grid-area: tabs; }
  .tabs button { flex: 1; height: var(--control-height-lg); }
  .workspace { padding-top: var(--space-3); }
  .page-heading { margin-bottom: var(--space-2); }
  .provider-form, .filters { grid-template-columns: 1fr; }
  .provider-form .wide, .filter-actions { grid-column: auto; }
  .bounds { grid-template-columns: 1fr; }
  .credential-card { grid-template-columns: 1fr; }
  .credential-card code, .credential-card .actions { grid-column: auto; }
}
</style>
