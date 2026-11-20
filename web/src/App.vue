<script setup lang="ts">
import { computed, onMounted, reactive, ref, watch } from 'vue'

import { AdminApi, type ProviderHealthWrite, type ProviderStatus, type ProtocolType } from './api/client.ts'
import { emptyAccountPage, loadAccounts, type AccountPage } from './accounts/list.ts'
import { ENDPOINTS, PROTOCOL_LABELS, TROUBLESHOOTING, curlExamples, type TroubleshootingId } from './docs/endpoints.ts'
import { locale, setLocale, settingLabel, t, type MessagePath, type MessageVars } from './locale/state.ts'
import {
  changeSetFor,
  editDraftFor,
  moveProvider,
  readExpiry,
  removeProvider,
  toggleProvider as toggleBoundProvider,
  type CredentialEditDraft,
} from './keys/edit.ts'
import { emptyApiKeyPage, loadApiKeys, type ApiKeyPage } from './keys/list.ts'
import { boundDraft, boundSummary, emptyBoundDrafts, readBounds, type BoundDrafts } from './limits/bounds.ts'
import { emptyLogFilters, logFiltersChanged, type LogFilterValues } from './logs/filters.ts'
import { loadLogs, type LogPage } from './logs/list.ts'
import { emptyProviderPage, loadProviders, type ProviderPage } from './providers/list.ts'
import { loadSettings } from './settings/list.ts'
import { useAdminSession, type ActionFailure } from './session/useAdminSession.ts'

const api = new AdminApi()
const session = useAdminSession(api)

const accountName = ref('')
const password = ref('')
const busy = ref(false)
type PageCopy =
  | { source: 'page'; key: MessagePath; vars?: MessageVars }
  | { source: 'server'; text: string }

const notice = ref<PageCopy | null>(null)
const errorMessage = ref<PageCopy | null>(null)
type View = 'providers' | 'keys' | 'accounts' | 'logs' | 'settings' | 'docs'
const activeView = ref<View>('keys')

// The Docs view is static copy, so it is computed once rather than per render.
const docsExamples = curlExamples()

const settingsPage = ref({ items: [] as import('./api/client.ts').Setting[] })
const settingDrafts = ref<Record<string, string>>({})

const providerPage = ref<ProviderPage>({ ...emptyProviderPage })
const keyPage = ref<ApiKeyPage>({ ...emptyApiKeyPage })
const accountPage = ref<AccountPage>({ ...emptyAccountPage })
const editingProviderId = ref<number | null>(null)
const creatingProvider = ref(false)
const oneTimeSecret = ref<string | null>(null)
const oneTimeAction = ref<PageCopy | null>(null)
const oneTimePassword = ref<string | null>(null)

function page(key: MessagePath, vars?: MessageVars): PageCopy {
  return { source: 'page', key, vars }
}

function show(copy: PageCopy | null): string {
  if (!copy) return ''
  return copy.source === 'server' ? copy.text : t(copy.key, copy.vars)
}

function failureCopy(failure: ActionFailure): PageCopy {
  switch (failure.reason) {
    case 'session-ended':
      return page('session.ended')
    case 'transport':
      return page('request.failed', { status: failure.status })
    case 'server':
      return { source: 'server', text: failure.message }
    case 'unknown':
      return page('request.incomplete')
  }
}

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

// The credential row the page is editing, and its draft. The draft is separate
// from the list so abandoning an edit leaves the listed credential untouched.
const editingKeyId = ref<number | null>(null)
const keyEditDraft = reactive<CredentialEditDraft>(emptyCredentialEditDraft())
const keyEditBounds = reactive({ ...emptyBoundDrafts() })

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
  notice.value = null
  errorMessage.value = null
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
    errorMessage.value = failureCopy(session.handleFailure(error))
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
    cancelKeyEdit()
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
    errorMessage.value = page(bounds.error)
    return
  }
  const health = readHealth(createForm.health)
  if ('error' in health) {
    errorMessage.value = page(health.error)
    return
  }
  await runAction(async () => {
    const { bounds: _drafts, ...fields } = createForm
    const { health: _health, ...providerFields } = fields
    await api.createProvider({ ...providerFields, ...bounds.values, ...(health.value ? { health: health.value } : {}) })
    Object.assign(createForm, emptyCreateForm())
    creatingProvider.value = false
    notice.value = page('provider.created')
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
    errorMessage.value = page(bounds.error)
    return
  }
  const health = readHealth(editForm.health, true)
  if ('error' in health) {
    errorMessage.value = page(health.error)
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
    notice.value = page('provider.updated')
    providerPage.value = await loadProviders(api, providerPage.value, true)
  })
}

function readHealth(
  fields: { probe_path: string; failure_threshold: string; probe_interval_ms: string; probe_timeout_ms: string },
  includeDisabled = false,
): { value: ProviderHealthWrite | null } | { error: MessagePath } {
  const probePath = fields.probe_path.trim()
  if (!probePath) {
    return includeDisabled
      ? { value: { probe_path: null, failure_threshold: null, probe_interval_ms: null, probe_timeout_ms: null } }
      : { value: null }
  }
  const values = [fields.failure_threshold, fields.probe_interval_ms, fields.probe_timeout_ms].map((value) => Number(value))
  if (values.some((value) => !Number.isSafeInteger(value) || value <= 0)) {
    return { error: 'healthProbe.positive' }
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
    notice.value = page(maintenance ? 'provider.enteredMaintenance' : 'provider.leftMaintenance')
    providerPage.value = await loadProviders(api, providerPage.value, true)
  })
}

async function toggleProvider(id: number, current: ProviderStatus) {
  await runAction(async () => {
    const status: ProviderStatus = current === 'enabled' ? 'disabled' : 'enabled'
    await api.updateProvider(id, { status })
    notice.value = page(status === 'disabled' ? 'provider.disabled' : 'provider.enabled')
    providerPage.value = await loadProviders(api, providerPage.value, true)
  })
}

async function deleteProvider(id: number, name: string) {
  if (!window.confirm(t('confirm.providerDelete', { name }))) {
    return
  }
  await runAction(async () => {
    await api.deleteProvider(id)
    notice.value = page('provider.deleted')
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
    notice.value = page('account.created', { name: created.account.name })
    accountPage.value = await loadAccounts(api, accountPage.value, true)
  })
}

async function toggleAccount(id: number, current: string, name: string) {
  const status = current === 'enabled' ? 'disabled' : 'enabled'
  if (status === 'disabled' && !window.confirm(t('confirm.accountDisable', { name }))) {
    return
  }
  await runAction(async () => {
    await api.updateAccount(id, { status })
    notice.value = page(status === 'disabled' ? 'account.disabled' : 'account.enabled')
    accountPage.value = await loadAccounts(api, accountPage.value, true)
  })
}

async function deleteAccount(id: number, name: string) {
  if (!window.confirm(t('confirm.accountDelete', { name }))) return
  await runAction(async () => {
    await api.deleteAccount(id)
    notice.value = page('account.deleted')
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
    errorMessage.value = page(bounds.error)
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
    showSecret(issued.api_key_secret, page('credential.forName', { name: issued.api_key.name }))
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

/** A blank credential edit, used before any credential is chosen. */
function emptyCredentialEditDraft(): CredentialEditDraft {
  return {
    name: '',
    status: 'enabled',
    expires_at: '',
    provider_ids: [],
    default_provider_id: null,
    bounds: emptyBoundDrafts(),
  }
}

/**
 * Opens the inline edit for one credential.
 *
 * The stored bounds and provider order come back as drafts, so the operator
 * starts from what is actually stored and a cancelled edit changes nothing.
 */
function beginKeyEdit(key: typeof keyPage.value.items[number]) {
  editingKeyId.value = key.id
  const draft = editDraftFor(key)
  Object.assign(keyEditDraft, draft)
  Object.assign(keyEditBounds, {
    max_concurrent_requests: draft.bounds.max_concurrent_requests,
    max_requests_per_second: draft.bounds.max_requests_per_second,
    max_websockets: draft.bounds.max_websockets,
  })
  clearFeedback()
}

function cancelKeyEdit() {
  editingKeyId.value = null
  clearFeedback()
}

/** Adds or removes a provider from the edited set, keeping the default valid. */
function toggleKeyProvider(providerId: number) {
  const next = toggleBoundProvider(
    keyEditDraft.provider_ids,
    keyEditDraft.default_provider_id,
    providerId,
  )
  keyEditDraft.provider_ids = next.provider_ids
  keyEditDraft.default_provider_id = next.default_provider_id
}

/** Reorders the edited set, which is the credential's routing preference. */
function moveKeyProvider(providerId: number, offset: number) {
  keyEditDraft.provider_ids = moveProvider(keyEditDraft.provider_ids, providerId, offset)
}

/**
 * Saves the edited credential in place.
 *
 * Bounds and the expiration are read before the request, so a zero or a past
 * instant is reported here instead of costing a round trip. A failure keeps the
 * edit open with its drafts intact so the operator can correct it.
 */
async function saveKey(id: number) {
  const bounds = readBounds(keyEditBounds, CREDENTIAL_BOUND_FIELDS)
  if ('error' in bounds) {
    errorMessage.value = page(bounds.error)
    return
  }
  const expiry = readExpiry(keyEditDraft.expires_at)
  if ('error' in expiry) {
    errorMessage.value = page(expiry.error)
    return
  }
  if (keyEditDraft.provider_ids.length === 0) {
    errorMessage.value = page('credential.bind')
    return
  }
  if (keyEditDraft.name.trim() === '') {
    errorMessage.value = page('credential.nameRequired')
    return
  }
  await runAction(async () => {
    await api.updateApiKey(id, changeSetFor(keyEditDraft, expiry.value, bounds.values))
    editingKeyId.value = null
    notice.value = page('credential.updated')
    // Reloading with the applied conditions keeps the list on one result set.
    keyPage.value = await loadApiKeys(api, keyPage.value, true)
  })
}

async function rotateKey(id: number, name: string) {
  if (!window.confirm(t('confirm.credentialRotate', { name }))) {
    return
  }
  await runAction(async () => {
    const rotated = await api.rotateApiKey(id)
    showSecret(rotated.api_key_secret, page('credential.newForName', { name: rotated.api_key.name }))
    keyPage.value = await loadApiKeys(api, keyPage.value, true)
  })
}

async function deleteKey(id: number, name: string) {
  if (!window.confirm(t('confirm.credentialDelete', { name }))) {
    return
  }
  await runAction(async () => {
    await api.deleteApiKey(id)
    notice.value = page('credential.deleted')
    keyPage.value = await loadApiKeys(api, keyPage.value, true)
  })
}

function showSecret(value: string, action: PageCopy) {
  oneTimeSecret.value = value
  oneTimeAction.value = action
}

function dismissSecret() {
  oneTimeSecret.value = null
  oneTimeAction.value = null
  oneTimePassword.value = null
}

async function copyPassword() {
  if (!oneTimePassword.value) return
  await navigator.clipboard.writeText(oneTimePassword.value)
  notice.value = page('password.copied')
}

async function copySecret() {
  if (!oneTimeSecret.value) return
  await navigator.clipboard.writeText(oneTimeSecret.value)
  notice.value = page('credential.copied')
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
      notice.value = page('settings.unchangedNotice')
      return
    }
    settingsPage.value = await api.updateSettings(patch)
    resetSettingDrafts()
    const pending = settingsPage.value.items.some((item) => item.pending_restart)
    notice.value = page(pending ? 'settings.savedPending' : 'settings.saved')
  })
}

function formatDate(value: string | null) {
  if (!value) return '—'
  return new Intl.DateTimeFormat(locale.value, {
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

const viewTitleKey = {
  keys: 'view.keys.title',
  providers: 'view.providers.title',
  accounts: 'view.accounts.title',
  logs: 'view.logs.title',
  settings: 'view.settings.title',
  docs: 'view.docs.title',
} as const satisfies Record<View, MessagePath>

const viewLedeKey = {
  keys: 'view.keys.lede',
  providers: 'view.providers.lede',
  accounts: 'view.accounts.lede',
  logs: 'view.logs.lede',
  settings: 'view.settings.lede',
  docs: 'view.docs.lede',
} as const satisfies Record<View, MessagePath>

function viewTitle(view: View) {
  return t(viewTitleKey[view])
}

function viewLede(view: View) {
  return t(viewLedeKey[view])
}

function statusLabel(status: 'enabled' | 'disabled') {
  return status === 'enabled' ? t('status.enabled') : t('status.disabled')
}

function roleLabel(role: 'admin' | 'user') {
  return role === 'admin' ? t('role.admin') : t('role.user')
}

function healthLabel(state: 'healthy' | 'isolated' | 'maintenance') {
  if (state === 'healthy') return t('health.healthy')
  if (state === 'isolated') return t('health.isolated')
  return t('health.maintenance')
}

function exampleTitle(id: string) {
  if (id === 'chat-completions' || id === 'responses' || id === 'messages') return t(`docs.example.${id}`)
  return id
}

function troubleSymptom(id: TroubleshootingId) {
  if (id === 'unauthorized') return t('docs.symptom.unauthorized')
  if (id === 'mismatch') return t('docs.symptom.mismatch')
  return t('docs.symptom.unavailable')
}

function troubleCause(id: TroubleshootingId) {
  if (id === 'unauthorized') return t('docs.cause.unauthorized')
  if (id === 'mismatch') return t('docs.cause.mismatch')
  return t('docs.cause.unavailable')
}

onMounted(restoreSession)
</script>

<template>
  <div class="shell">
    <header class="masthead">
      <a class="brand" href="/" :aria-label="t('documentTitle')">
        <span class="brand-mark">T</span>
        <span>Tokenstream</span>
      </a>
      <nav v-if="session.signedIn.value" class="tabs" :aria-label="t('nav.label')">
        <button
          :class="{ active: activeView === 'keys' }"
          :aria-current="activeView === 'keys' ? 'page' : undefined"
          @click="activeView = 'keys'"
        >{{ t('nav.credentials') }}</button>
        <button
          v-if="isAdmin"
          :class="{ active: activeView === 'providers' }"
          :aria-current="activeView === 'providers' ? 'page' : undefined"
          @click="activeView = 'providers'"
        >{{ t('nav.providers') }}</button>
        <button
          v-if="isAdmin"
          :class="{ active: activeView === 'accounts' }"
          :aria-current="activeView === 'accounts' ? 'page' : undefined"
          @click="activeView = 'accounts'"
        >{{ t('nav.accounts') }}</button>
        <button
          :class="{ active: activeView === 'logs' }"
          :aria-current="activeView === 'logs' ? 'page' : undefined"
          @click="activeView = 'logs'"
        >{{ t('nav.logs') }}</button>
        <button
          v-if="isAdmin"
          :class="{ active: activeView === 'settings' }"
          :aria-current="activeView === 'settings' ? 'page' : undefined"
          @click="activeView = 'settings'"
        >{{ t('nav.settings') }}</button>
        <button
          :class="{ active: activeView === 'docs' }"
          :aria-current="activeView === 'docs' ? 'page' : undefined"
          @click="activeView = 'docs'"
        >{{ t('nav.docs') }}</button>
      </nav>
      <div class="masthead-end">
        <div class="locale" role="group" :aria-label="t('locale.switch')">
          <button type="button" :aria-pressed="locale === 'en'" @click="setLocale('en')">EN</button>
          <button type="button" :aria-pressed="locale === 'zh-CN'" @click="setLocale('zh-CN')">中文</button>
        </div>
        <span v-if="session.signedIn.value" class="identity">
          {{ session.accountName.value }}
          <span class="badge neutral">{{ roleLabel(session.role.value) }}</span>
        </span>
        <button v-if="session.signedIn.value" class="button ghost sign-out" :disabled="busy" @click="signOut">{{ t('session.signOut') }}</button>
      </div>
    </header>

    <main v-if="session.checking.value" class="center-card" aria-live="polite">
      <div class="spinner"></div>
      <p>{{ t('session.checking') }}</p>
    </main>

    <main v-else-if="!session.signedIn.value" class="login-layout">
      <form class="card login-card" @submit.prevent="signIn">
        <h2>{{ t('signIn.title') }}</h2>
        <p class="login-note">{{ t('signIn.note') }}</p>
        <label>
          {{ t('signIn.account') }}
          <input v-model="accountName" autocomplete="username" required autofocus placeholder="admin" />
        </label>
        <label>
          {{ t('signIn.password') }}
          <input v-model="password" type="password" autocomplete="current-password" required />
        </label>
        <p v-if="errorMessage" class="alert error" role="alert">{{ show(errorMessage) }}</p>
        <button class="button primary" :disabled="busy">{{ busy ? t('signIn.busy') : t('signIn.submit') }}</button>
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
        >{{ t('action.newProvider') }}</button>
        <button
          v-if="isAdmin && activeView === 'accounts' && !creatingAccount"
          class="button primary"
          type="button"
          :disabled="busy"
          @click="beginAccount"
        >{{ t('action.newAccount') }}</button>
      </section>

      <p v-if="errorMessage" class="alert error" role="alert">{{ show(errorMessage) }}</p>
      <p v-if="notice" class="alert success" role="status">{{ show(notice) }}</p>

      <section v-if="oneTimeSecret" class="credential-card" aria-live="assertive">
        <div>
          <h2>{{ show(oneTimeAction) }}</h2>
          <p>{{ t('secret.once') }}</p>
        </div>
        <code>{{ oneTimeSecret }}</code>
        <div class="actions">
          <button class="button primary" @click="copySecret">{{ t('secret.copy') }}</button>
          <button class="button ghost" @click="dismissSecret">{{ t('secret.stored') }}</button>
        </div>
      </section>

      <section v-if="oneTimePassword" class="credential-card" aria-live="assertive">
        <div>
          <h2>{{ t('password.title') }}</h2>
          <p>{{ t('password.once') }}</p>
        </div>
        <code>{{ oneTimePassword }}</code>
        <div class="actions">
          <button class="button primary" @click="copyPassword">{{ t('password.copy') }}</button>
          <button class="button ghost" @click="dismissSecret">{{ t('secret.stored') }}</button>
        </div>
      </section>

      <template v-if="activeView === 'keys'">
        <section class="card create-card">
          <div class="section-title">
            <h2>{{ t('credential.issueTitle') }}</h2>
            <span class="section-note">{{ t('credential.issueNote') }}</span>
          </div>
          <form class="provider-form" @submit.prevent="issueKey">
            <label>{{ t('credential.name') }}<input v-model="keyForm.name" maxlength="128" required placeholder="ci" /></label>
            <label v-if="isAdmin">
              {{ t('credential.owningAccount') }}
              <select v-model.number="keyForm.account_id" required>
                <option v-for="account in accountPage.items" :key="account.id" :value="account.id">{{ account.name }}</option>
              </select>
            </label>
            <fieldset class="wide bindings">
              <legend>{{ t('credential.providersLegend') }}</legend>
              <label v-for="provider in providers" :key="provider.id" class="binding">
                <input
                  type="checkbox"
                  :value="provider.id"
                  :checked="keyForm.provider_ids.includes(provider.id)"
                  @change="toggleProviderBinding(provider.id)"
                />
                {{ provider.name }}
              </label>
              <p v-if="providers.length === 0" class="section-note">{{ t('credential.noProviders') }}</p>
            </fieldset>
            <label v-if="isAdmin" class="wide">
              {{ t('credential.defaultProvider') }}
              <select v-model="keyForm.default_provider_id">
                <option :value="null">{{ t('credential.firstBound') }}</option>
                <option v-for="id in keyForm.provider_ids" :key="id" :value="id">{{ providerName(id) }}</option>
              </select>
            </label>
            <fieldset class="wide bounds">
              <legend>{{ t('bounds.legendCredential') }}</legend>
              <label>{{ t('bounds.maxConcurrent') }}
                <input v-model="keyForm.bounds.max_concurrent_requests" inputmode="numeric" :placeholder="t('bounds.placeholder')" :aria-label="t('bounds.ariaConcurrent')" />
              </label>
              <label>{{ t('bounds.maxRate') }}
                <input v-model="keyForm.bounds.max_requests_per_second" inputmode="numeric" :placeholder="t('bounds.placeholder')" :aria-label="t('bounds.ariaRate')" />
              </label>
              <label>{{ t('bounds.maxWebsockets') }}
                <input v-model="keyForm.bounds.max_websockets" inputmode="numeric" :placeholder="t('bounds.placeholder')" :aria-label="t('bounds.ariaWebsockets')" />
              </label>
              <p class="section-note">{{ t('bounds.note') }}</p>
            </fieldset>
            <div class="actions wide">
              <button class="button primary" :disabled="busy" :title="keyForm.provider_ids.length === 0 ? t('credential.bindTitle') : undefined">{{ t('action.createCredential') }}</button>
            </div>
          </form>
        </section>

        <section class="card table-card" :aria-label="t('credential.tableLabel')">
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>{{ t('column.id') }}</th>
                  <th>{{ t('column.name') }}</th>
                  <th v-if="isAdmin">{{ t('column.account') }}</th>
                  <th>{{ t('column.status') }}</th>
                  <th class="fill">{{ t('column.providers') }}</th>
                  <th>{{ t('column.bounds') }}</th>
                  <th>{{ t('column.keyId') }}</th>
                  <th>{{ t('column.expires') }}</th>
                  <th>{{ t('column.created') }}</th>
                  <th>{{ t('column.actions') }}</th>
                </tr>
              </thead>
              <tbody>
                <template v-for="key in keyPage.items" :key="key.id">
                  <tr v-if="editingKeyId === key.id">
                    <td>{{ key.id }}</td>
                    <td><input v-model="keyEditDraft.name" maxlength="128" required :aria-label="t('credential.ariaName')" /></td>
                    <td v-if="isAdmin">{{ accountLabel(key.account_id) }}</td>
                    <td>
                      <select v-model="keyEditDraft.status" :aria-label="t('credential.ariaStatus')">
                        <option value="enabled">{{ t('status.enabledOption') }}</option>
                        <option value="disabled">{{ t('status.disabledOption') }}</option>
                      </select>
                    </td>
                    <td class="fill">
                      <div class="row-bindings">
                        <div v-for="(id, index) in keyEditDraft.provider_ids" :key="id" class="binding-row">
                          <span class="binding-name">
                            {{ providerName(id) }}<span v-if="id === keyEditDraft.default_provider_id">{{ t('credential.defaultSuffix') }}</span>
                          </span>
                          <button
                            class="button ghost"
                            type="button"
                            :disabled="index === 0"
                            :aria-label="t('credential.moveEarlier', { name: providerName(id) })"
                            @click="moveKeyProvider(id, -1)"
                          >↑</button>
                          <button
                            class="button ghost"
                            type="button"
                            :disabled="index === keyEditDraft.provider_ids.length - 1"
                            :aria-label="t('credential.moveLater', { name: providerName(id) })"
                            @click="moveKeyProvider(id, 1)"
                          >↓</button>
                          <button
                            class="button ghost"
                            type="button"
                            :aria-label="t('credential.remove', { name: providerName(id) })"
                            @click="toggleKeyProvider(id)"
                          >{{ t('action.remove') }}</button>
                        </div>
                        <label v-for="provider in providers" :key="provider.id" v-show="!keyEditDraft.provider_ids.includes(provider.id)" class="binding">
                          <input type="checkbox" :value="provider.id" @change="toggleKeyProvider(provider.id)" />
                          {{ t('credential.add', { name: provider.name }) }}
                        </label>
                        <label class="binding">
                          {{ t('credential.defaultLabel') }}
                          <select v-model.number="keyEditDraft.default_provider_id">
                            <option :value="null">{{ t('credential.noDefault') }}</option>
                            <option v-for="id in keyEditDraft.provider_ids" :key="id" :value="id">{{ providerName(id) }}</option>
                          </select>
                        </label>
                      </div>
                    </td>
                    <td>
                      <div class="row-bounds">
                        <input
                          v-model="keyEditBounds.max_concurrent_requests"
                          inputmode="numeric"
                          :placeholder="t('bounds.placeholder')"
                          :aria-label="t('bounds.ariaConcurrent')"
                        />
                        <input
                          v-model="keyEditBounds.max_requests_per_second"
                          inputmode="numeric"
                          :placeholder="t('bounds.placeholder')"
                          :aria-label="t('bounds.ariaRate')"
                        />
                        <input
                          v-model="keyEditBounds.max_websockets"
                          inputmode="numeric"
                          :placeholder="t('bounds.placeholder')"
                          :aria-label="t('bounds.ariaWebsockets')"
                        />
                      </div>
                    </td>
                    <td><code>{{ key.key_id }}</code></td>
                    <td>
                      <input v-model="keyEditDraft.expires_at" type="datetime-local" :aria-label="t('expiry.aria')" />
                    </td>
                    <td>{{ formatDate(key.created_at) }}</td>
                    <td class="row-actions">
                      <div class="actions">
                        <button class="button primary" :disabled="busy" @click="saveKey(key.id)">{{ t('action.save') }}</button>
                        <button class="button ghost" type="button" @click="cancelKeyEdit">{{ t('action.cancel') }}</button>
                      </div>
                    </td>
                  </tr>
                  <tr v-else>
                    <td>{{ key.id }}</td>
                    <td>{{ key.name }}</td>
                    <td v-if="isAdmin">{{ accountLabel(key.account_id) }}</td>
                    <td><span class="badge" :class="key.status">{{ statusLabel(key.status) }}</span></td>
                    <td class="fill">
                      <span v-for="(id, index) in key.provider_ids" :key="id">
                        {{ providerName(id) }}<span v-if="id === key.default_provider_id">{{ t('credential.defaultSuffix') }}</span>{{ index < key.provider_ids.length - 1 ? ', ' : '' }}
                      </span>
                    </td>
                    <td>{{ boundSummary([[t('bounds.conc'), key.max_concurrent_requests], [t('bounds.rate'), key.max_requests_per_second], [t('bounds.ws'), key.max_websockets]], t('bounds.unbounded')) }}</td>
                    <td><code>{{ key.key_id }}</code></td>
                    <td>{{ formatDate(key.expires_at) }}</td>
                    <td>{{ formatDate(key.created_at) }}</td>
                    <td class="row-actions">
                      <div class="actions">
                        <button class="button ghost" @click="beginKeyEdit(key)">{{ t('action.edit') }}</button>
                        <button class="button ghost" :disabled="busy" @click="rotateKey(key.id, key.name)">{{ t('action.rotate') }}</button>
                        <button class="button danger" :disabled="busy" @click="deleteKey(key.id, key.name)">{{ t('action.delete') }}</button>
                      </div>
                    </td>
                  </tr>
                </template>
              </tbody>
            </table>
          </div>
          <div v-if="keyPage.items.length === 0" class="empty-state">{{ t('credential.empty') }}</div>
          <button v-if="!keyPage.exhausted" class="button load-more" :disabled="busy" @click="loadMoreKeys">{{ t('action.loadMore') }}</button>
        </section>
      </template>

      <template v-else-if="activeView === 'providers'">
        <section v-if="creatingProvider" class="card create-card">
          <div class="section-title">
            <h2>{{ t('provider.addTitle') }}</h2>
            <span class="section-note">{{ t('provider.addNote') }}</span>
          </div>
          <form class="provider-form" @submit.prevent="createProvider">
            <label>{{ t('provider.name') }}<input v-model="createForm.name" maxlength="128" required placeholder="primary-openai" /></label>
            <label>{{ t('provider.protocol') }}<select v-model="createForm.protocol_type"><option value="openai">OpenAI</option><option value="anthropic">Anthropic</option></select></label>
            <label>{{ t('column.status') }}<select v-model="createForm.status"><option value="enabled">{{ t('status.enabledOption') }}</option><option value="disabled">{{ t('status.disabledOption') }}</option></select></label>
            <label class="wide">{{ t('provider.endpoint') }}<input v-model="createForm.endpoint" type="url" required placeholder="https://api.example.com" /></label>
            <label class="wide">{{ t('provider.upstreamKey') }}<input v-model="createForm.upstream_api_key" type="password" autocomplete="new-password" required /></label>
            <fieldset class="wide bounds">
              <legend>{{ t('bounds.legendProvider') }}</legend>
              <label>{{ t('bounds.maxConcurrent') }}
                <input v-model="createForm.bounds.max_concurrent_requests" inputmode="numeric" :placeholder="t('bounds.placeholder')" :aria-label="t('bounds.ariaConcurrent')" />
              </label>
              <label>{{ t('bounds.maxRate') }}
                <input v-model="createForm.bounds.max_requests_per_second" inputmode="numeric" :placeholder="t('bounds.placeholder')" :aria-label="t('bounds.ariaRate')" />
              </label>
              <p class="section-note">{{ t('bounds.note') }}</p>
            </fieldset>
            <fieldset class="wide bounds">
              <legend>{{ t('healthProbe.legend') }}</legend>
              <label>{{ t('healthProbe.path') }}<input v-model="createForm.health.probe_path" :placeholder="t('healthProbe.pathPlaceholder')" :aria-label="t('healthProbe.ariaPath')" /></label>
              <label>{{ t('healthProbe.threshold') }}<input v-model="createForm.health.failure_threshold" inputmode="numeric" :aria-label="t('healthProbe.ariaThreshold')" /></label>
              <label>{{ t('healthProbe.interval') }}<input v-model="createForm.health.probe_interval_ms" inputmode="numeric" :aria-label="t('healthProbe.ariaInterval')" /></label>
              <label>{{ t('healthProbe.timeout') }}<input v-model="createForm.health.probe_timeout_ms" inputmode="numeric" :aria-label="t('healthProbe.ariaTimeout')" /></label>
              <p class="section-note">{{ t('healthProbe.note') }}</p>
            </fieldset>
            <div class="actions wide">
              <button class="button primary" :disabled="busy">{{ t('action.createProvider') }}</button>
              <button class="button ghost" type="button" @click="cancelCreate">{{ t('action.cancel') }}</button>
            </div>
          </form>
        </section>

        <section class="card table-card" :aria-label="t('provider.tableLabel')">
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>{{ t('column.id') }}</th>
                  <th>{{ t('column.name') }}</th>
                  <th>{{ t('column.protocol') }}</th>
                  <th>{{ t('column.status') }}</th>
                  <th>{{ t('column.health') }}</th>
                  <th class="fill">{{ t('column.endpoint') }}</th>
                  <th>{{ t('column.upstreamKey') }}</th>
                  <th>{{ t('column.bounds') }}</th>
                  <th>{{ t('column.created') }}</th>
                  <th>{{ t('column.actions') }}</th>
                </tr>
              </thead>
              <tbody>
                <template v-for="provider in providers" :key="provider.id">
                  <tr v-if="editingProviderId === provider.id">
                    <td>{{ provider.id }}</td>
                    <td><input v-model="editForm.name" maxlength="128" required :aria-label="t('credential.ariaName')" /></td>
                    <td><span class="badge neutral">{{ PROTOCOL_LABELS[provider.protocol_type] }}</span></td>
                    <td>
                      <select v-model="editForm.status" :aria-label="t('credential.ariaStatus')">
                        <option value="enabled">{{ t('status.enabledOption') }}</option>
                        <option value="disabled">{{ t('status.disabledOption') }}</option>
                      </select>
                    </td>
                    <td>
                      <div class="row-probe">
                        <span class="badge" :class="provider.health">{{ healthLabel(provider.health) }}</span>
                        <input v-model="editForm.health.probe_path" :placeholder="t('healthProbe.editPlaceholder')" :aria-label="t('healthProbe.ariaPath')" />
                        <input v-model="editForm.health.failure_threshold" inputmode="numeric" :aria-label="t('healthProbe.ariaThreshold')" />
                        <input v-model="editForm.health.probe_interval_ms" inputmode="numeric" :aria-label="t('healthProbe.ariaInterval')" />
                        <input v-model="editForm.health.probe_timeout_ms" inputmode="numeric" :aria-label="t('healthProbe.ariaTimeout')" />
                      </div>
                    </td>
                    <td class="fill"><input v-model="editForm.endpoint" type="url" required :aria-label="t('provider.ariaEndpoint')" /></td>
                    <td>
                      <input
                        v-model="editForm.upstream_api_key"
                        type="password"
                        autocomplete="new-password"
                        :placeholder="t('provider.unchanged')"
                        :aria-label="t('provider.ariaReplaceKey')"
                      />
                    </td>
                    <td>
                      <div class="row-bounds">
                        <input
                          v-model="editForm.bounds.max_concurrent_requests"
                          inputmode="numeric"
                          :placeholder="t('bounds.placeholder')"
                          :aria-label="t('bounds.ariaConcurrent')"
                        />
                        <input
                          v-model="editForm.bounds.max_requests_per_second"
                          inputmode="numeric"
                          :placeholder="t('bounds.placeholder')"
                          :aria-label="t('bounds.ariaRate')"
                        />
                      </div>
                    </td>
                    <td>{{ formatDate(provider.created_at) }}</td>
                    <td class="row-actions">
                      <div class="actions">
                        <button class="button primary" :disabled="busy" @click="saveProvider(provider.id)">{{ t('action.save') }}</button>
                        <button class="button ghost" type="button" @click="editingProviderId = null">{{ t('action.cancel') }}</button>
                      </div>
                    </td>
                  </tr>
                  <tr v-else>
                    <td>{{ provider.id }}</td>
                    <td>{{ provider.name }}</td>
                    <td><span class="badge neutral">{{ PROTOCOL_LABELS[provider.protocol_type] }}</span></td>
                    <td><span class="badge" :class="provider.status">{{ statusLabel(provider.status) }}</span></td>
                    <td>
                      <span class="badge" :class="provider.health">{{ healthLabel(provider.health) }}</span>
                      <small v-if="provider.health_probe">{{ t('healthProbe.summary', { path: provider.health_probe.probe_path, count: provider.health_probe.failure_threshold, interval: provider.health_probe.probe_interval_ms }) }}</small>
                      <small v-else>{{ t('healthProbe.disabled') }}</small>
                    </td>
                    <td class="fill">{{ provider.endpoint }}</td>
                    <td>{{ provider.has_upstream_api_key ? t('status.configured') : t('status.notConfigured') }}</td>
                    <td>{{ boundSummary([[t('bounds.conc'), provider.max_concurrent_requests], [t('bounds.rate'), provider.max_requests_per_second]], t('bounds.unbounded')) }}</td>
                    <td>{{ formatDate(provider.created_at) }}</td>
                    <td class="row-actions">
                      <div class="actions">
                        <button class="button ghost" @click="beginEdit(provider.id, provider)">{{ t('action.edit') }}</button>
                        <button
                          class="button ghost"
                          :disabled="busy"
                          @click="toggleMaintenance(provider.id, provider.health !== 'maintenance')"
                        >{{ provider.health === 'maintenance' ? t('action.leaveMaintenance') : t('action.maintenance') }}</button>
                        <button class="button ghost" :disabled="busy" @click="toggleProvider(provider.id, provider.status)">{{ provider.status === 'enabled' ? t('action.disable') : t('action.enable') }}</button>
                        <button class="button danger" :disabled="busy" @click="deleteProvider(provider.id, provider.name)">{{ t('action.delete') }}</button>
                      </div>
                    </td>
                  </tr>
                </template>
              </tbody>
            </table>
          </div>
          <div v-if="providers.length === 0" class="empty-state">{{ t('provider.empty') }}</div>
          <button v-if="!providerPage.exhausted" class="button load-more" :disabled="busy" @click="loadMoreProviders">{{ t('action.loadMore') }}</button>
        </section>
      </template>

      <template v-else-if="activeView === 'accounts'">
        <section v-if="creatingAccount" class="card create-card">
          <div class="section-title">
            <h2>{{ t('account.addTitle') }}</h2>
            <span class="section-note">{{ t('account.addNote') }}</span>
          </div>
          <form class="provider-form" @submit.prevent="createAccount">
            <label>{{ t('account.name') }}<input v-model="accountForm.name" maxlength="128" required placeholder="analyst" /></label>
            <label>{{ t('account.role') }}<select v-model="accountForm.role"><option value="user">{{ t('role.userOption') }}</option><option value="admin">{{ t('role.adminOption') }}</option></select></label>
            <div class="actions wide">
              <button class="button primary" :disabled="busy">{{ t('action.createAccount') }}</button>
              <button class="button ghost" type="button" @click="cancelAccount">{{ t('action.cancel') }}</button>
            </div>
          </form>
        </section>

        <section class="card table-card" :aria-label="t('account.tableLabel')">
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>{{ t('column.id') }}</th>
                  <th>{{ t('column.name') }}</th>
                  <th>{{ t('column.role') }}</th>
                  <th>{{ t('column.status') }}</th>
                  <th>{{ t('column.created') }}</th>
                  <th>{{ t('column.actions') }}</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="account in accountPage.items" :key="account.id">
                  <td>{{ account.id }}</td>
                  <td>
                    {{ account.name }}
                    <span v-if="account.is_bootstrap" class="badge neutral">{{ t('status.bootstrap') }}</span>
                  </td>
                  <td><span class="badge neutral">{{ roleLabel(account.role) }}</span></td>
                  <td><span class="badge" :class="account.status">{{ statusLabel(account.status) }}</span></td>
                  <td>{{ formatDate(account.created_at) }}</td>
                  <td class="row-actions">
                    <div class="actions">
                      <button
                        class="button ghost"
                        :disabled="busy || account.is_bootstrap"
                        :title="account.is_bootstrap ? t('account.cannotDisable') : undefined"
                        @click="toggleAccount(account.id, account.status, account.name)"
                      >{{ account.status === 'enabled' ? t('action.disable') : t('action.enable') }}</button>
                      <button
                        class="button danger"
                        :disabled="busy || account.is_bootstrap"
                        :title="account.is_bootstrap ? t('account.cannotDelete') : undefined"
                        @click="deleteAccount(account.id, account.name)"
                      >{{ t('action.delete') }}</button>
                    </div>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
          <div v-if="accountPage.items.length === 0" class="empty-state">{{ t('account.empty') }}</div>
          <button v-if="!accountPage.exhausted" class="button load-more" :disabled="busy" @click="loadMoreAccounts">{{ t('action.loadMore') }}</button>
        </section>
      </template>

      <template v-else-if="activeView === 'logs'">
        <section class="card filters-card">
          <form class="filters" @submit.prevent="applyLogFilters">
            <label>{{ t('logs.provider') }}<select v-model="logFilters.provider_id"><option value="">{{ t('logs.allProviders') }}</option><option v-for="provider in providers" :key="provider.id" :value="String(provider.id)">{{ provider.name }}</option></select></label>
            <label>{{ t('logs.transport') }}<select v-model="logFilters.transport_type"><option value="">{{ t('logs.allTransports') }}</option><option value="http">{{ t('logs.http') }}</option><option value="websocket">{{ t('logs.websocket') }}</option></select></label>
            <label>{{ t('logs.startedAfter') }}<input v-model="logFilters.start_time_gte" type="datetime-local" /></label>
            <label>{{ t('logs.startedBefore') }}<input v-model="logFilters.start_time_lt" type="datetime-local" /></label>
            <div class="actions filter-actions"><button class="button primary" :disabled="busy">{{ t('action.applyFilters') }}</button><button class="button ghost" type="button" @click="resetLogFilters">{{ t('action.reset') }}</button></div>
          </form>
          <p v-if="logFiltersDirty" class="filters-pending" role="status">
            {{ t('logs.pending') }}
          </p>
        </section>

        <section class="card table-card">
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>{{ t('column.request') }}</th>
                  <th>{{ t('column.account') }}</th>
                  <th>{{ t('logs.provider') }}</th>
                  <th>{{ t('column.transport') }}</th>
                  <th class="fill">{{ t('column.route') }}</th>
                  <th>{{ t('column.status') }}</th>
                  <th>{{ t('column.started') }}</th>
                  <th>{{ t('column.completed') }}</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="log in logPage.items" :key="log.id">
                  <td><code>{{ log.request_id }}</code></td>
                  <td>{{ isAdmin ? accountLabel(log.account_id) : session.accountName.value }}</td>
                  <td>{{ providerName(log.provider_id) }}</td>
                  <td>{{ log.transport_type }}</td>
                  <td class="fill"><code>{{ log.path }}</code></td>
                  <td><span v-if="log.incomplete" class="badge incomplete">{{ t('status.incomplete') }}</span><span v-else>{{ log.status_code ?? '—' }}</span><small v-if="log.error_msg" class="row-error">{{ log.error_msg }}</small></td>
                  <td>{{ formatDate(log.start_time) }}</td>
                  <td>{{ formatDate(log.end_time) }}</td>
                </tr>
              </tbody>
            </table>
          </div>
          <div v-if="logPage.items.length === 0" class="empty-state">{{ t('logs.empty') }}</div>
          <button v-if="!logPage.exhausted" class="button load-more" :disabled="busy" @click="loadMoreLogs">{{ t('action.loadMore') }}</button>
        </section>
      </template>

      <template v-else-if="activeView === 'settings'">
        <section class="card table-card">
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>{{ t('column.setting') }}</th>
                  <th class="fill">{{ t('column.value') }}</th>
                  <th>{{ t('column.applies') }}</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="item in settingsPage.items" :key="item.name">
                  <td>
                    <strong>{{ settingLabel(item.name, item.label) }}</strong>
                    <small>{{ item.name }}</small>
                  </td>
                  <td class="fill">
                    <input
                      v-model="settingDrafts[item.name]"
                      :type="item.secret ? 'password' : 'text'"
                      :placeholder="item.secret ? t('settings.unchanged') : ''"
                      :autocomplete="item.secret ? 'new-password' : 'off'"
                    />
                  </td>
                  <td>
                    <span v-if="item.pending_restart" class="badge incomplete">{{ t('status.restartPending') }}</span>
                    <span v-else-if="item.restart_required" class="badge neutral">{{ t('status.nextStart') }}</span>
                    <span v-else class="badge enabled">{{ t('status.live') }}</span>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
          <div class="actions settings-actions">
            <button class="button primary" :disabled="busy" @click="saveSettings">{{ t('action.saveSettings') }}</button>
          </div>
        </section>
      </template>

      <template v-else-if="activeView === 'docs'">
        <section class="card docs-card">
          <div class="section-title">
            <h2>{{ t('docs.endpoints') }}</h2>
            <span class="section-note">{{ t('docs.staticNote') }}</span>
          </div>
          <p class="docs-note">{{ t('docs.baseUrl') }}</p>
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>{{ t('column.protocol') }}</th>
                  <th>{{ t('column.method') }}</th>
                  <th class="fill">{{ t('column.path') }}</th>
                  <th>{{ t('column.authentication') }}</th>
                  <th>{{ t('column.transport') }}</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="row in ENDPOINTS" :key="`${row.protocol}-${row.method}-${row.path}-${row.transport}`">
                  <td>{{ PROTOCOL_LABELS[row.protocol] }}</td>
                  <td><code>{{ row.method }}</code></td>
                  <td class="fill"><code>{{ row.path }}</code></td>
                  <td><code>{{ row.auth }}</code></td>
                  <td>{{ row.transport }}</td>
                </tr>
              </tbody>
            </table>
          </div>
          <p class="section-note">{{ t('docs.websocket') }}</p>
        </section>

        <section class="card docs-card" :aria-label="t('docs.examplesLabel')">
          <div class="section-title">
            <h2>{{ t('docs.examples') }}</h2>
            <span class="section-note">{{ t('docs.examplesNote') }}</span>
          </div>
          <div class="docs-examples">
            <article v-for="example in docsExamples" :key="example.id" class="docs-example">
              <h3>{{ exampleTitle(example.id) }}</h3>
              <pre><code>{{ example.command }}</code></pre>
            </article>
          </div>
        </section>

        <section class="card docs-card" :aria-label="t('docs.troubleshootingLabel')">
          <div class="section-title">
            <h2>{{ t('docs.troubleshooting') }}</h2>
            <span class="section-note">{{ t('docs.troubleshootingNote') }}</span>
          </div>
          <div class="table-wrap">
            <table>
              <thead><tr><th>{{ t('column.symptom') }}</th><th class="fill">{{ t('column.meaning') }}</th></tr></thead>
              <tbody>
                <tr v-for="note in TROUBLESHOOTING" :key="note.id">
                  <td><span class="badge neutral">{{ troubleSymptom(note.id) }}</span></td>
                  <td class="fill">{{ troubleCause(note.id) }}</td>
                </tr>
              </tbody>
            </table>
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
  grid-template-columns: auto 1fr auto;
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
  grid-column: 1;
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
.tabs { grid-column: 2; display: flex; align-items: stretch; min-width: 0; }
.masthead-end {
  grid-column: 3;
  display: flex;
  align-items: center;
  gap: var(--space-3);
}
.locale {
  display: inline-flex;
  align-self: center;
  overflow: hidden;
  border: 1px solid var(--color-line);
  border-radius: var(--radius-md);
}
.locale button {
  min-height: var(--control-height);
  padding: 0 var(--space-2);
  border: 0;
  color: var(--color-muted);
  background: transparent;
  font-size: var(--font-size-ui);
  font-weight: var(--font-weight-semibold);
}
.locale button + button { border-left: 1px solid var(--color-line); }
.locale button[aria-pressed='true'] {
  color: var(--color-accent-ink);
  background: var(--color-control-fill);
}
:lang(zh-CN) th,
:lang(zh-CN) .badge {
  letter-spacing: 0;
  text-transform: none;
}
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
.row-bindings { display: grid; gap: var(--space-1); min-width: 14rem; }
.binding-row {
  display: flex;
  align-items: center;
  gap: var(--space-compact);
}
.binding-name { flex: 1; min-width: 0; }
.binding-row .button { padding: 2px var(--space-compact); }
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

.docs-card { width: 100%; margin-bottom: var(--space-2); padding: var(--space-3); }
.docs-note { margin: 0 0 var(--space-2); color: var(--color-muted); font-size: var(--font-size-ui); }
.docs-examples { display: grid; gap: var(--space-2); }
.docs-example h3 { margin-bottom: var(--space-1); font-size: var(--font-size-title); font-weight: var(--font-weight-semibold); }
.docs-example pre {
  margin: 0;
  padding: var(--space-2) var(--space-3);
  overflow-x: auto;
  background: var(--color-control-fill);
  border: 1px solid var(--color-line);
  border-radius: var(--radius-md);
}
.docs-example code { font-family: var(--font-mono); font-size: var(--font-size-body); white-space: pre; }

@media (max-width: 780px) {
  .masthead {
    grid-template-columns: 1fr auto;
    min-height: 0;
    padding: 0 var(--space-3);
  }
  .brand { grid-column: 1; grid-row: 1; height: 40px; }
  .masthead-end { grid-column: 2; grid-row: 1; }
  .tabs { grid-column: 1 / -1; grid-row: 2; }
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
