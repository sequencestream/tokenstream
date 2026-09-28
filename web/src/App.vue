<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'

import { AdminApi, type ProviderStatus, type ProtocolType } from './api/client.ts'
import { emptyLogFilters, logFiltersChanged, type LogFilterValues } from './logs/filters.ts'
import { loadLogs, type LogPage } from './logs/list.ts'
import { emptyProviderPage, loadProviders, type ProviderPage } from './providers/list.ts'
import { useAdminSession } from './session/useAdminSession.ts'

const api = new AdminApi()
const session = useAdminSession(api)

const password = ref('')
const busy = ref(false)
const notice = ref('')
const errorMessage = ref('')
const activeView = ref<'providers' | 'logs'>('providers')

const providerPage = ref<ProviderPage>({ ...emptyProviderPage })
const editingProviderId = ref<number | null>(null)
const oneTimeCredential = ref<string | null>(null)
const credentialAction = ref('')

const createForm = reactive({
  name: '',
  protocol_type: 'openai' as ProtocolType,
  endpoint: 'https://',
  upstream_api_key: '',
  status: 'enabled' as ProviderStatus,
})
const editForm = reactive({
  name: '',
  endpoint: '',
  upstream_api_key: '',
  status: 'enabled' as ProviderStatus,
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
      dismissCredential()
    }
  } finally {
    busy.value = false
  }
}

async function restoreSession() {
  if (await session.restore()) {
    await runAction(async () => {
      const [nextProviders, nextLogs] = await Promise.all([
        loadProviders(api, providerPage.value, true),
        loadLogs(api, logPage.value, appliedLogFilters, true),
      ])
      providerPage.value = nextProviders
      logPage.value = nextLogs
    })
  }
}

async function signIn() {
  await runAction(async () => {
    await session.signIn(password.value)
    password.value = ''
    const [nextProviders, nextLogs] = await Promise.all([
      loadProviders(api, providerPage.value, true),
      loadLogs(api, logPage.value, appliedLogFilters, true),
    ])
    providerPage.value = nextProviders
    logPage.value = nextLogs
  })
}

async function signOut() {
  await runAction(async () => {
    await session.signOut()
    providerPage.value = { ...emptyProviderPage }
    logPage.value = { items: [], cursor: null, exhausted: true }
    dismissCredential()
  })
}

async function loadMoreProviders() {
  await runAction(async () => {
    providerPage.value = await loadProviders(api, providerPage.value, false)
  })
}

async function createProvider() {
  await runAction(async () => {
    const created = await api.createProvider({ ...createForm })
    showCredential(created.gateway_api_key, `Credential for ${created.provider.name}`)
    Object.assign(createForm, {
      name: '',
      protocol_type: 'openai' as ProtocolType,
      endpoint: 'https://',
      upstream_api_key: '',
      status: 'enabled' as ProviderStatus,
    })
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
  })
  clearFeedback()
}

async function saveProvider(id: number) {
  await runAction(async () => {
    await api.updateProvider(id, {
      name: editForm.name,
      endpoint: editForm.endpoint,
      status: editForm.status,
      ...(editForm.upstream_api_key ? { upstream_api_key: editForm.upstream_api_key } : {}),
    })
    editingProviderId.value = null
    notice.value = 'Provider updated.'
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

async function rotateCredential(id: number, name: string) {
  if (
    !window.confirm(
      `Rotate the gateway credential for ${name}? The old credential will stop working for new requests.`,
    )
  ) {
    return
  }
  await runAction(async () => {
    const rotated = await api.rotateCredential(id)
    showCredential(rotated.gateway_api_key, `New credential for ${rotated.provider.name}`)
    providerPage.value = await loadProviders(api, providerPage.value, true)
  })
}

async function deleteProvider(id: number, name: string) {
  if (
    !window.confirm(
      `Delete ${name}? Providers referenced by request logs cannot be deleted.`,
    )
  ) {
    return
  }
  await runAction(async () => {
    await api.deleteProvider(id)
    notice.value = 'Provider deleted.'
    providerPage.value = await loadProviders(api, providerPage.value, true)
  })
}

function showCredential(value: string, action: string) {
  oneTimeCredential.value = value
  credentialAction.value = action
}

function dismissCredential() {
  oneTimeCredential.value = null
  credentialAction.value = ''
}

async function copyCredential() {
  if (!oneTimeCredential.value) return
  await navigator.clipboard.writeText(oneTimeCredential.value)
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

function formatDate(value: string | null) {
  if (!value) return '—'
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: 'medium',
    timeStyle: 'medium',
  }).format(new Date(value))
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
      <button v-if="session.signedIn.value" class="button ghost" :disabled="busy" @click="signOut">Sign out</button>
    </header>

    <main v-if="session.checking.value" class="center-card" aria-live="polite">
      <div class="spinner"></div>
      <p>Checking your session…</p>
    </main>

    <main v-else-if="!session.signedIn.value" class="login-layout">
      <section class="login-copy">
        <p class="eyebrow">Transparent AI gateway</p>
        <h1>Operate every upstream from one quiet control plane.</h1>
        <p>Manage providers and inspect transport metadata without exposing request payloads or upstream secrets.</p>
      </section>
      <form class="card login-card" @submit.prevent="signIn">
        <p class="eyebrow">Administration</p>
        <h2>Sign in</h2>
        <label>
          Password
          <input v-model="password" type="password" autocomplete="current-password" required autofocus />
        </label>
        <p v-if="errorMessage" class="alert error" role="alert">{{ errorMessage }}</p>
        <button class="button primary" :disabled="busy">{{ busy ? 'Signing in…' : 'Sign in' }}</button>
      </form>
    </main>

    <main v-else class="workspace">
      <section class="page-heading">
        <div>
          <p class="eyebrow">Administration</p>
          <h1>{{ activeView === 'providers' ? 'Providers' : 'Request logs' }}</h1>
        </div>
        <nav class="tabs" aria-label="Administration views">
          <button :class="{ active: activeView === 'providers' }" @click="activeView = 'providers'">Providers</button>
          <button :class="{ active: activeView === 'logs' }" @click="activeView = 'logs'">Request logs</button>
        </nav>
      </section>

      <p v-if="errorMessage" class="alert error" role="alert">{{ errorMessage }}</p>
      <p v-if="notice" class="alert success" role="status">{{ notice }}</p>

      <section v-if="oneTimeCredential" class="credential-card" aria-live="assertive">
        <div>
          <p class="eyebrow">Shown once</p>
          <h2>{{ credentialAction }}</h2>
          <p>Copy this credential now. It will disappear when dismissed or when the page is refreshed.</p>
        </div>
        <code>{{ oneTimeCredential }}</code>
        <div class="actions">
          <button class="button primary" @click="copyCredential">Copy credential</button>
          <button class="button ghost" @click="dismissCredential">I have stored it</button>
        </div>
      </section>

      <template v-if="activeView === 'providers'">
        <section class="card create-card">
          <div class="section-title">
            <div>
              <p class="eyebrow">New upstream</p>
              <h2>Add provider</h2>
            </div>
            <span class="section-note">The upstream key is write-only.</span>
          </div>
          <form class="provider-form" @submit.prevent="createProvider">
            <label>Name<input v-model="createForm.name" maxlength="128" required placeholder="primary-openai" /></label>
            <label>Protocol<select v-model="createForm.protocol_type"><option value="openai">OpenAI</option><option value="anthropic">Anthropic</option></select></label>
            <label class="wide">Endpoint<input v-model="createForm.endpoint" type="url" required placeholder="https://api.example.com" /></label>
            <label class="wide">Upstream API key<input v-model="createForm.upstream_api_key" type="password" autocomplete="new-password" required /></label>
            <label>Status<select v-model="createForm.status"><option value="enabled">Enabled</option><option value="disabled">Disabled</option></select></label>
            <button class="button primary align-end" :disabled="busy">Create provider</button>
          </form>
        </section>

        <section class="provider-list" aria-label="Providers">
          <article v-for="provider in providers" :key="provider.id" class="card provider-card">
            <template v-if="editingProviderId === provider.id">
              <form class="provider-form" @submit.prevent="saveProvider(provider.id)">
                <label>Name<input v-model="editForm.name" maxlength="128" required /></label>
                <label>Status<select v-model="editForm.status"><option value="enabled">Enabled</option><option value="disabled">Disabled</option></select></label>
                <label class="wide">Endpoint<input v-model="editForm.endpoint" type="url" required /></label>
                <label class="wide">Replace upstream API key <span>(optional)</span><input v-model="editForm.upstream_api_key" type="password" autocomplete="new-password" /></label>
                <div class="actions wide">
                  <button class="button primary" :disabled="busy">Save changes</button>
                  <button class="button ghost" type="button" @click="editingProviderId = null">Cancel</button>
                </div>
              </form>
            </template>
            <template v-else>
              <div class="provider-summary">
                <div>
                  <div class="title-row">
                    <h2>{{ provider.name }}</h2>
                    <span class="badge" :class="provider.status">{{ provider.status }}</span>
                    <span class="badge neutral">{{ provider.protocol_type }}</span>
                  </div>
                  <p class="endpoint">{{ provider.endpoint }}</p>
                </div>
                <div class="provider-id">#{{ provider.id }}</div>
              </div>
              <dl class="metadata">
                <div><dt>Gateway key ID</dt><dd><code>{{ provider.gateway_key_id }}</code></dd></div>
                <div><dt>Upstream key</dt><dd>{{ provider.has_upstream_api_key ? 'Configured' : 'Not configured' }}</dd></div>
                <div><dt>Created</dt><dd>{{ formatDate(provider.created_at) }}</dd></div>
              </dl>
              <div class="actions">
                <button class="button ghost" @click="beginEdit(provider.id, provider)">Edit</button>
                <button class="button ghost" :disabled="busy" @click="toggleProvider(provider.id, provider.status)">{{ provider.status === 'enabled' ? 'Disable' : 'Enable' }}</button>
                <button class="button ghost" :disabled="busy" @click="rotateCredential(provider.id, provider.name)">Rotate credential</button>
                <button class="button danger" :disabled="busy" @click="deleteProvider(provider.id, provider.name)">Delete</button>
              </div>
            </template>
          </article>
          <div v-if="providers.length === 0" class="empty-state">No providers configured.</div>
          <button v-if="!providerPage.exhausted" class="button load-more" :disabled="busy" @click="loadMoreProviders">Load more</button>
        </section>
      </template>

      <template v-else>
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
              <thead><tr><th>Request</th><th>Provider</th><th>Transport</th><th>Route</th><th>Status</th><th>Started</th><th>Completed</th></tr></thead>
              <tbody>
                <tr v-for="log in logPage.items" :key="log.id">
                  <td><code>{{ log.request_id }}</code></td>
                  <td>{{ providerById.get(log.provider_id)?.name ?? `#${log.provider_id}` }}</td>
                  <td>{{ log.transport_type }}</td>
                  <td><code>{{ log.path }}</code></td>
                  <td><span v-if="log.incomplete" class="badge incomplete">Incomplete</span><span v-else>{{ log.status_code ?? '—' }}</span><small v-if="log.error_msg">{{ log.error_msg }}</small></td>
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
    </main>
  </div>
</template>

<style>
:root {
  color: #17211c;
  background: #f1f3ed;
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  font-synthesis: none;
}

* { box-sizing: border-box; }
body { margin: 0; min-width: 320px; min-height: 100vh; }
button, input, select { font: inherit; }
button { cursor: pointer; }
button:disabled { cursor: wait; opacity: .58; }
code { font-family: "SFMono-Regular", Consolas, monospace; overflow-wrap: anywhere; }

.shell { min-height: 100vh; background: radial-gradient(circle at 10% 0%, #dce8d7 0, transparent 26rem), #f1f3ed; }
.masthead { height: 72px; padding: 0 clamp(1.25rem, 4vw, 4rem); display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid #d9ddd4; background: rgba(248, 249, 245, .82); backdrop-filter: blur(14px); }
.brand { display: inline-flex; align-items: center; gap: .7rem; color: inherit; text-decoration: none; font-weight: 760; letter-spacing: -.02em; }
.brand-mark { display: grid; place-items: center; width: 2rem; height: 2rem; color: #f8fff8; background: #1e6a48; border-radius: .55rem; }
.workspace { width: min(1180px, calc(100% - 2rem)); margin: 0 auto; padding: 3.5rem 0 5rem; }
.page-heading { display: flex; align-items: end; justify-content: space-between; gap: 2rem; margin-bottom: 2rem; }
h1, h2, p { margin-top: 0; }
h1 { margin-bottom: .25rem; font-size: clamp(2.2rem, 6vw, 4.6rem); line-height: .95; letter-spacing: -.055em; }
h2 { margin-bottom: .35rem; font-size: 1.15rem; letter-spacing: -.02em; }
.eyebrow { margin-bottom: .7rem; color: #347052; font-size: .72rem; font-weight: 800; letter-spacing: .14em; text-transform: uppercase; }
.card { background: rgba(255, 255, 252, .92); border: 1px solid #d6dbd1; border-radius: 1rem; box-shadow: 0 16px 40px rgba(34, 51, 40, .06); }
.tabs { display: flex; padding: .25rem; background: #e3e7df; border-radius: .75rem; }
.tabs button { padding: .65rem 1rem; border: 0; border-radius: .55rem; color: #536058; background: transparent; }
.tabs button.active { color: #173d2a; background: #fff; box-shadow: 0 2px 8px rgba(20, 45, 30, .1); }
.button { min-height: 2.55rem; padding: .65rem 1rem; border: 1px solid #c9d0c7; border-radius: .65rem; color: #24352b; background: #f9faf7; font-weight: 680; }
.button.primary { border-color: #1e6a48; color: white; background: #1e6a48; }
.button.danger { border-color: #ebc8c3; color: #9a3028; background: #fff7f6; }
.button.ghost { background: transparent; }
.center-card { min-height: calc(100vh - 72px); display: grid; place-content: center; justify-items: center; color: #536058; }
.spinner { width: 2rem; height: 2rem; border: 3px solid #cbd5cc; border-top-color: #1e6a48; border-radius: 50%; animation: spin .8s linear infinite; }
@keyframes spin { to { transform: rotate(360deg); } }
.login-layout { width: min(1080px, calc(100% - 2rem)); min-height: calc(100vh - 72px); margin: auto; display: grid; grid-template-columns: 1.3fr .7fr; align-items: center; gap: clamp(3rem, 8vw, 8rem); }
.login-copy h1 { max-width: 13ch; }
.login-copy > p:last-child { max-width: 55ch; color: #59665e; font-size: 1.05rem; line-height: 1.7; }
.login-card { padding: 2rem; }
label { display: grid; gap: .45rem; color: #48554d; font-size: .76rem; font-weight: 760; letter-spacing: .025em; }
label span { font-weight: 500; }
input, select { width: 100%; min-height: 2.75rem; padding: .7rem .8rem; border: 1px solid #cbd2c9; border-radius: .55rem; color: #17211c; background: #fff; outline: none; }
input:focus, select:focus { border-color: #287653; box-shadow: 0 0 0 3px rgba(40, 118, 83, .12); }
.login-card label { margin: 1.5rem 0 1rem; }
.login-card .button { width: 100%; }
.alert { padding: .85rem 1rem; border-radius: .65rem; font-size: .9rem; }
.alert.error { color: #85251f; background: #fce8e5; border: 1px solid #efcbc6; }
.alert.success { color: #24593c; background: #e3f1e7; border: 1px solid #c2dfca; }
.credential-card { display: grid; grid-template-columns: 1fr auto; gap: 1rem 2rem; margin-bottom: 1.5rem; padding: 1.5rem; color: #153825; background: #ddefd9; border: 1px solid #b9d7b7; border-radius: 1rem; }
.credential-card code { grid-column: 1 / -1; padding: 1rem; color: #effff4; background: #173d2a; border-radius: .6rem; }
.actions { display: flex; flex-wrap: wrap; gap: .55rem; }
.credential-card .actions { grid-column: 1 / -1; }
.create-card, .filters-card { margin-bottom: 1.25rem; padding: 1.5rem; }
.section-title { display: flex; align-items: start; justify-content: space-between; gap: 1rem; margin-bottom: 1.25rem; }
.section-note { color: #6a756e; font-size: .82rem; }
.provider-form { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 1rem; }
.provider-form .wide { grid-column: 1 / -1; }
.align-end { align-self: end; }
.provider-list { display: grid; gap: 1rem; }
.provider-card { padding: 1.5rem; }
.provider-summary, .title-row { display: flex; align-items: start; gap: .7rem; }
.provider-summary { justify-content: space-between; }
.provider-summary h2 { font-size: 1.35rem; }
.provider-id { color: #7b857e; font: .8rem "SFMono-Regular", Consolas, monospace; }
.endpoint { margin: .35rem 0 0; color: #627068; }
.badge { display: inline-flex; padding: .25rem .5rem; border-radius: 999px; font-size: .68rem; font-weight: 800; letter-spacing: .04em; text-transform: uppercase; }
.badge.enabled { color: #20613f; background: #d9efdf; }
.badge.disabled { color: #8a4337; background: #f6e2de; }
.badge.neutral { color: #47584d; background: #e8ece6; }
.badge.incomplete { color: #7c570e; background: #f7e9bc; }
.metadata { display: grid; grid-template-columns: 1.3fr .7fr 1fr; gap: 1rem; margin: 1.4rem 0; padding: 1rem 0; border-top: 1px solid #e3e7e0; border-bottom: 1px solid #e3e7e0; }
.metadata div { min-width: 0; }
.metadata dt { margin-bottom: .35rem; color: #7a857d; font-size: .7rem; font-weight: 760; text-transform: uppercase; }
.metadata dd { margin: 0; font-size: .9rem; }
.filters { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 1rem; }
.filter-actions { grid-column: 1 / -1; }
.table-card { overflow: hidden; }
.table-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; font-size: .82rem; }
th, td { padding: .9rem 1rem; border-bottom: 1px solid #e4e7e2; text-align: left; vertical-align: top; white-space: nowrap; }
th { color: #6c7870; background: #f8f9f6; font-size: .68rem; letter-spacing: .06em; text-transform: uppercase; }
td small { display: block; margin-top: .35rem; color: #9a3d33; }
.empty-state { padding: 3rem 1rem; color: #738078; text-align: center; }
.load-more { display: block; margin: 1rem auto; }
.filters-pending { margin-top: 1rem; color: #6a756e; font-size: .82rem; }

@media (max-width: 780px) {
  .login-layout { grid-template-columns: 1fr; align-content: center; gap: 2rem; padding: 3rem 0; }
  .login-copy h1 { font-size: 2.8rem; }
  .page-heading { align-items: stretch; flex-direction: column; }
  .tabs button { flex: 1; }
  .provider-form, .filters { grid-template-columns: 1fr; }
  .provider-form .wide, .filter-actions { grid-column: auto; }
  .metadata { grid-template-columns: 1fr; }
  .credential-card { grid-template-columns: 1fr; }
  .credential-card code, .credential-card .actions { grid-column: auto; }
}
</style>

<style>
:root {
  color: #17211c;
  background: #f1f3ed;
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  font-synthesis: none;
}

* { box-sizing: border-box; }
body { margin: 0; min-width: 320px; min-height: 100vh; }
button, input, select { font: inherit; }
button { cursor: pointer; }
button:disabled { cursor: wait; opacity: .58; }
code { font-family: "SFMono-Regular", Consolas, monospace; overflow-wrap: anywhere; }

.shell { min-height: 100vh; background: radial-gradient(circle at 10% 0%, #dce8d7 0, transparent 26rem), #f1f3ed; }
.masthead { height: 72px; padding: 0 clamp(1.25rem, 4vw, 4rem); display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid #d9ddd4; background: rgba(248, 249, 245, .82); backdrop-filter: blur(14px); }
.brand { display: inline-flex; align-items: center; gap: .7rem; color: inherit; text-decoration: none; font-weight: 760; letter-spacing: -.02em; }
.brand-mark { display: grid; place-items: center; width: 2rem; height: 2rem; color: #f8fff8; background: #1e6a48; border-radius: .55rem; }
.workspace { width: min(1180px, calc(100% - 2rem)); margin: 0 auto; padding: 3.5rem 0 5rem; }
.page-heading { display: flex; align-items: end; justify-content: space-between; gap: 2rem; margin-bottom: 2rem; }
h1, h2, p { margin-top: 0; }
h1 { margin-bottom: .25rem; font-size: clamp(2.2rem, 6vw, 4.6rem); line-height: .95; letter-spacing: -.055em; }
h2 { margin-bottom: .35rem; font-size: 1.15rem; letter-spacing: -.02em; }
.eyebrow { margin-bottom: .7rem; color: #347052; font-size: .72rem; font-weight: 800; letter-spacing: .14em; text-transform: uppercase; }
.card { background: rgba(255, 255, 252, .92); border: 1px solid #d6dbd1; border-radius: 1rem; box-shadow: 0 16px 40px rgba(34, 51, 40, .06); }
.tabs { display: flex; padding: .25rem; background: #e3e7df; border-radius: .75rem; }
.tabs button { padding: .65rem 1rem; border: 0; border-radius: .55rem; color: #536058; background: transparent; }
.tabs button.active { color: #173d2a; background: #fff; box-shadow: 0 2px 8px rgba(20, 45, 30, .1); }
.button { min-height: 2.55rem; padding: .65rem 1rem; border: 1px solid #c9d0c7; border-radius: .65rem; color: #24352b; background: #f9faf7; font-weight: 680; }
.button.primary { border-color: #1e6a48; color: white; background: #1e6a48; }
.button.danger { border-color: #ebc8c3; color: #9a3028; background: #fff7f6; }
.button.ghost { background: transparent; }
.center-card { min-height: calc(100vh - 72px); display: grid; place-content: center; justify-items: center; color: #536058; }
.spinner { width: 2rem; height: 2rem; border: 3px solid #cbd5cc; border-top-color: #1e6a48; border-radius: 50%; animation: spin .8s linear infinite; }
@keyframes spin { to { transform: rotate(360deg); } }
.login-layout { width: min(1080px, calc(100% - 2rem)); min-height: calc(100vh - 72px); margin: auto; display: grid; grid-template-columns: 1.3fr .7fr; align-items: center; gap: clamp(3rem, 8vw, 8rem); }
.login-copy h1 { max-width: 13ch; }
.login-copy > p:last-child { max-width: 55ch; color: #59665e; font-size: 1.05rem; line-height: 1.7; }
.login-card { padding: 2rem; }
label { display: grid; gap: .45rem; color: #48554d; font-size: .76rem; font-weight: 760; letter-spacing: .025em; }
label span { font-weight: 500; }
input, select { width: 100%; min-height: 2.75rem; padding: .7rem .8rem; border: 1px solid #cbd2c9; border-radius: .55rem; color: #17211c; background: #fff; outline: none; }
input:focus, select:focus { border-color: #287653; box-shadow: 0 0 0 3px rgba(40, 118, 83, .12); }
.login-card label { margin: 1.5rem 0 1rem; }
.login-card .button { width: 100%; }
.alert { padding: .85rem 1rem; border-radius: .65rem; font-size: .9rem; }
.alert.error { color: #85251f; background: #fce8e5; border: 1px solid #efcbc6; }
.alert.success { color: #24593c; background: #e3f1e7; border: 1px solid #c2dfca; }
.credential-card { display: grid; grid-template-columns: 1fr auto; gap: 1rem 2rem; margin-bottom: 1.5rem; padding: 1.5rem; color: #153825; background: #ddefd9; border: 1px solid #b9d7b7; border-radius: 1rem; }
.credential-card code { grid-column: 1 / -1; padding: 1rem; color: #effff4; background: #173d2a; border-radius: .6rem; }
.actions { display: flex; flex-wrap: wrap; gap: .55rem; }
.credential-card .actions { grid-column: 1 / -1; }
.create-card, .filters-card { margin-bottom: 1.25rem; padding: 1.5rem; }
.section-title { display: flex; align-items: start; justify-content: space-between; gap: 1rem; margin-bottom: 1.25rem; }
.section-note { color: #6a756e; font-size: .82rem; }
.provider-form { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 1rem; }
.provider-form .wide { grid-column: 1 / -1; }
.align-end { align-self: end; }
.provider-list { display: grid; gap: 1rem; }
.provider-card { padding: 1.5rem; }
.provider-summary, .title-row { display: flex; align-items: start; gap: .7rem; }
.provider-summary { justify-content: space-between; }
.provider-summary h2 { font-size: 1.35rem; }
.provider-id { color: #7b857e; font: .8rem "SFMono-Regular", Consolas, monospace; }
.endpoint { margin: .35rem 0 0; color: #627068; }
.badge { display: inline-flex; padding: .25rem .5rem; border-radius: 999px; font-size: .68rem; font-weight: 800; letter-spacing: .04em; text-transform: uppercase; }
.badge.enabled { color: #20613f; background: #d9efdf; }
.badge.disabled { color: #8a4337; background: #f6e2de; }
.badge.neutral { color: #47584d; background: #e8ece6; }
.badge.incomplete { color: #7c570e; background: #f7e9bc; }
.metadata { display: grid; grid-template-columns: 1.3fr .7fr 1fr; gap: 1rem; margin: 1.4rem 0; padding: 1rem 0; border-top: 1px solid #e3e7e0; border-bottom: 1px solid #e3e7e0; }
.metadata div { min-width: 0; }
.metadata dt { margin-bottom: .35rem; color: #7a857d; font-size: .7rem; font-weight: 760; text-transform: uppercase; }
.metadata dd { margin: 0; font-size: .9rem; }
.filters { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 1rem; }
.filter-actions { grid-column: 1 / -1; }
.table-card { overflow: hidden; }
.table-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; font-size: .82rem; }
th, td { padding: .9rem 1rem; border-bottom: 1px solid #e4e7e2; text-align: left; vertical-align: top; white-space: nowrap; }
th { color: #6c7870; background: #f8f9f6; font-size: .68rem; letter-spacing: .06em; text-transform: uppercase; }
td small { display: block; margin-top: .35rem; color: #9a3d33; }
.empty-state { padding: 3rem 1rem; color: #738078; text-align: center; }
.load-more { display: block; margin: 1rem auto; }
.filters-pending { margin-top: 1rem; color: #6a756e; font-size: .82rem; }

@media (max-width: 780px) {
  .login-layout { grid-template-columns: 1fr; align-content: center; gap: 2rem; padding: 3rem 0; }
  .login-copy h1 { font-size: 2.8rem; }
  .page-heading { align-items: stretch; flex-direction: column; }
  .tabs button { flex: 1; }
  .provider-form, .filters { grid-template-columns: 1fr; }
  .provider-form .wide, .filter-actions { grid-column: auto; }
  .metadata { grid-template-columns: 1fr; }
  .credential-card { grid-template-columns: 1fr; }
  .credential-card code, .credential-card .actions { grid-column: auto; }
}
</style>
