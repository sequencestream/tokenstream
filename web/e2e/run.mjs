/**
 * Real-browser acceptance of the administration page.
 *
 * The suite runs twice: once against the control plane that hosts the compiled
 * page, and once against the development server that proxies the API. A failed
 * interaction fails the process; a successful frontend build is not enough.
 */
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createServer } from 'node:net'
import { fileURLToPath } from 'node:url'
import { setTimeout as delay } from 'node:timers/promises'
import { chromium } from 'playwright'

const repositoryRoot = fileURLToPath(new URL('../..', import.meta.url))
const webRoot = fileURLToPath(new URL('..', import.meta.url))
const accountName = process.env.TEST_ADMIN_ACCOUNT ?? 'admin'
const password = process.env.TEST_ADMIN_PASSWORD
const gatewayBinary = process.env.GATEWAY_BINARY
const mainSessionTtlMs = 60_000
const expirySessionTtlMs = 2_000

if (!password || !gatewayBinary) {
  throw new Error('GATEWAY_BINARY and TEST_ADMIN_PASSWORD are required')
}

async function freePort() {
  const server = createServer()
  await new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', resolve)
  })
  const { port } = server.address()
  await new Promise((resolve) => server.close(resolve))
  return port
}

function spawnLogged(command, args, options) {
  const child = spawn(command, args, { ...options, stdio: ['ignore', 'pipe', 'pipe'] })
  child.stdout.setEncoding('utf8')
  child.stderr.setEncoding('utf8')
  child.output = ''
  const collect = (chunk) => {
    child.output += chunk
  }
  child.stdout.on('data', collect)
  child.stderr.on('data', collect)
  return child
}

async function waitFor(predicate, description, timeoutMs = 20_000) {
  const deadline = Date.now() + timeoutMs
  let lastError
  while (Date.now() < deadline) {
    try {
      if (await predicate()) return
    } catch (error) {
      lastError = error
    }
    await delay(50)
  }
  throw new Error(`${description}${lastError ? `: ${lastError}` : ''}`)
}

async function startGateway({ name, directory, sessionTtlMs }) {
  const dataPort = await freePort()
  const adminPort = await freePort()
  const env = {
    ...process.env,
    TOKENSTREAM_DATA_LISTEN_ADDR: `127.0.0.1:${dataPort}`,
    TOKENSTREAM_ADMIN_LISTEN_ADDR: `127.0.0.1:${adminPort}`,
    TOKENSTREAM_DATABASE_URL: `sqlite://${join(directory, `${name}.db`)}`,
    TOKENSTREAM_MASTER_KEY: '11'.repeat(32),
    TOKENSTREAM_ADMIN_PASSWORD_HASH: process.env.TEST_ADMIN_HASH,
    TOKENSTREAM_ADMIN_PASSWORD: password,
    TOKENSTREAM_DEVELOPMENT_MODE: 'true',
    TOKENSTREAM_ADMIN_SESSION_TTL_MS: String(sessionTtlMs),
    TOKENSTREAM_UPSTREAM_CONNECT_TIMEOUT_MS: '5000',
    TOKENSTREAM_UPSTREAM_HEADER_TIMEOUT_MS: '30000',
    TOKENSTREAM_STREAM_IDLE_TIMEOUT_MS: '60000',
    TOKENSTREAM_SHUTDOWN_DRAIN_TIMEOUT_MS: '150',
    TOKENSTREAM_LOG_FLUSH_TIMEOUT_MS: '1000',
    TOKENSTREAM_DATABASE_MAX_CONNECTIONS: '4',
    TOKENSTREAM_MAX_PROXY_CONNECTIONS: '8',
    TOKENSTREAM_HTTP_BUFFER_BYTES: '65536',
    TOKENSTREAM_WEBSOCKET_MAX_FRAME_BYTES: '65536',
    TOKENSTREAM_WEBSOCKET_MAX_MESSAGE_BYTES: '65536',
    TOKENSTREAM_WEBSOCKET_QUEUE_CAPACITY: '4',
    TOKENSTREAM_LOG_QUEUE_CAPACITY: '128',
    TOKENSTREAM_LOG_BATCH_SIZE: '16',
    TOKENSTREAM_LOG_BATCH_INTERVAL_MS: '10',
  }
  const processHandle = spawnLogged(gatewayBinary, [], { env, cwd: repositoryRoot })
  const deadline = Date.now() + 20_000
  while (Date.now() < deadline) {
    if (processHandle.exitCode !== null) {
      throw new Error(`gateway ${name} exited:\n${processHandle.output}`)
    }
    try {
      if ((await fetch(`http://127.0.0.1:${adminPort}/healthz`)).ok) {
        return { processHandle, dataPort, adminPort }
      }
    } catch {
      // The listener is not bound yet.
    }
    await delay(50)
  }
  throw new Error(`gateway ${name} did not listen\n${processHandle.output}`)
}

async function startVite(adminPort) {
  const port = await freePort()
  const child = spawnLogged(join(webRoot, 'node_modules', '.bin', 'vite'), [
    '--host',
    '127.0.0.1',
    '--port',
    String(port),
    '--strictPort',
  ], {
    cwd: webRoot,
    env: {
      ...process.env,
      TOKENSTREAM_ADMIN_PROXY_TARGET: `http://127.0.0.1:${adminPort}`,
    },
  })
  const deadline = Date.now() + 20_000
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error(`development server exited:\n${child.output}`)
    try {
      if ((await fetch(`http://127.0.0.1:${port}/`)).ok) return { child, port }
    } catch {
      // The development server is not bound yet.
    }
    await delay(50)
  }
  throw new Error(`development server did not listen\n${child.output}`)
}

function stop(child) {
  if (!child || child.exitCode !== null) return Promise.resolve()
  child.kill('SIGTERM')
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      child.kill('SIGKILL')
      resolve()
    }, 3_000)
    child.once('exit', () => {
      clearTimeout(timer)
      resolve()
    })
  })
}

function attachAdminCacheGuard(page) {
  const failures = []
  page.on('response', (response) => {
    const path = new URL(response.url()).pathname
    if (!path.startsWith('/admin/api/')) return
    const policy = response.headers()['cache-control']
    if (policy !== 'no-store') {
      failures.push(`${path} cache-control=${policy ?? '<missing>'}`)
    }
  })
  return () => {
    assert.deepEqual(failures, [], 'administration API responses must forbid storage')
  }
}

async function storedCredentialTraces(page, credential) {
  return page.evaluate((value) => {
    const local = JSON.stringify({ ...localStorage })
    const session = JSON.stringify({ ...sessionStorage })
    return {
      local: local.includes(value),
      session: session.includes(value),
    }
  }, credential)
}

async function signIn(page, origin) {
  await page.goto(origin, { waitUntil: 'networkidle' })
  await assert.equal(await page.getByRole('heading', { name: 'Sign in' }).count(), 1)
  await page.getByLabel('Account').fill(accountName)
  await page.getByLabel('Password').fill(password)
  await page.getByRole('button', { name: 'Sign in' }).click()
  await page.getByRole('heading', { name: 'Credentials' }).waitFor()
}

/** Creates a provider through the page, returning its name. */
async function createProvider(page, name) {
  await page.getByRole('button', { name: 'Providers' }).click()
  await page.getByRole('button', { name: 'New provider' }).click()
  await page.getByPlaceholder('primary-openai').waitFor()
  await page.getByPlaceholder('primary-openai').fill(name)
  await page.getByPlaceholder('https://api.example.com').fill('https://api.example.com')
  await page.getByLabel('Upstream API key').fill('upstream-secret')
  await page.getByRole('button', { name: 'Create provider' }).click()
  await page.getByRole('row').filter({ hasText: name }).waitFor()
}

/** Issues a credential bound to one provider, returning its one-time plaintext. */
/** The admission bounds the suite issues every credential with. */
const CREDENTIAL_BOUNDS = { maxConcurrent: 4, maxRate: 20, maxWebsockets: 2 }

async function issueCredential(page, providerName, keyName) {
  await page.getByRole('button', { name: 'Credentials' }).click()
  await page.getByPlaceholder('ci').fill(keyName)
  await page.locator('.binding').filter({ hasText: providerName }).locator('input').check()
  await page.getByLabel('Max concurrent requests').fill(String(CREDENTIAL_BOUNDS.maxConcurrent))
  await page.getByLabel('Max requests per second').fill(String(CREDENTIAL_BOUNDS.maxRate))
  await page.getByLabel('Max WebSocket connections').fill(String(CREDENTIAL_BOUNDS.maxWebsockets))
  await page.getByRole('button', { name: 'Create credential' }).click()
  await page.locator('.credential-card code').waitFor()
  const secret = (await page.locator('.credential-card code').innerText()).trim()
  await page.getByRole('button', { name: 'I have stored it' }).click()
  return secret
}

/** Creates a regular account and returns its name with its one-time password. */
async function createAccount(page, name) {
  await page.getByRole('button', { name: 'Accounts' }).click()
  await page.getByRole('button', { name: 'New account' }).click()
  await page.getByPlaceholder('analyst').fill(name)
  await page.getByRole('button', { name: 'Create account' }).click()
  await page.getByRole('heading', { name: 'Password for the new account' }).waitFor()
  const generated = (await page.locator('.credential-card code').innerText()).trim()
  await page.getByRole('button', { name: 'I have stored it' }).click()
  return generated
}

async function runSuite(browser, origin, label) {
  const context = await browser.newContext()
  const page = await context.newPage()
  const checkCache = attachAdminCacheGuard(page)
  try {
    await page.goto(origin, { waitUntil: 'networkidle' })
    await page.getByRole('heading', { name: 'Sign in' }).waitFor()
    if (label === 'hosted') {
      const document = await page.evaluate(async () => {
        const response = await fetch('/', { credentials: 'same-origin' })
        return {
          type: response.headers.get('content-type'),
          cache: response.headers.get('cache-control'),
        }
      })
      assert.match(document.type ?? '', /text\/html/)
      assert.equal(document.cache, 'no-store')
    }

    const unauthenticated = await page.evaluate(async () => {
      const response = await fetch('/admin/api/accounts', { credentials: 'same-origin' })
      return { status: response.status, cache: response.headers.get('cache-control') }
    })
    assert.equal(unauthenticated.status, 401)
    assert.equal(unauthenticated.cache, 'no-store')

    // A wrong password and a wrong account name fail identically, so neither
    // reveals whether the named account exists.
    await page.getByLabel('Account').fill(accountName)
    await page.getByLabel('Password').fill('not-the-password')
    await page.getByRole('button', { name: 'Sign in' }).click()
    await page.getByRole('alert').filter({ hasText: 'Invalid credentials' }).waitFor()

    await page.getByLabel('Account').fill(accountName)
    await page.getByLabel('Password').fill(password)
    await page.getByRole('button', { name: 'Sign in' }).click()
    await page.getByRole('heading', { name: 'Credentials' }).waitFor()

    await page.reload({ waitUntil: 'networkidle' })
    await page.getByRole('heading', { name: 'Credentials' }).waitFor()

    const csrf = await page.evaluate(async () => {
      const response = await fetch('/admin/api/accounts', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ name: 'csrf-rejected', role: 'user', status: 'enabled' }),
      })
      return { status: response.status, cache: response.headers.get('cache-control') }
    })
    assert.equal(csrf.status, 403)
    assert.equal(csrf.cache, 'no-store')

    // A provider issues no credential of its own, so nothing is shown when one
    // is created.
    const providerName = `browser-${label}`
    assert.equal(await page.getByPlaceholder('primary-openai').count(), 0)
    await page.getByRole('button', { name: 'Providers' }).click()
    await page.getByRole('button', { name: 'New provider' }).click()
    await page.getByPlaceholder('primary-openai').waitFor()
    await page.getByRole('button', { name: 'Cancel' }).click()
    assert.equal(await page.getByPlaceholder('primary-openai').count(), 0)
    await createProvider(page, providerName)
    assert.equal(await page.locator('.credential-card').count(), 0)

    const keyName = `ci-${label}`
    const createdCredential = await issueCredential(page, providerName, keyName)
    assert.match(createdCredential, /^.+\..+$/)
    assert.deepEqual(await storedCredentialTraces(page, createdCredential), {
      local: false,
      session: false,
    })

    // A bound the operator set is shown on the row, so the page never hides the
    // limit that is shaping the credential's own traffic.
    const boundSummary = `conc ${CREDENTIAL_BOUNDS.maxConcurrent}, rate ${CREDENTIAL_BOUNDS.maxRate}, WS ${CREDENTIAL_BOUNDS.maxWebsockets}`
    await page
      .getByRole('row')
      .filter({ has: page.getByRole('cell', { name: keyName, exact: true }) })
      .getByRole('cell', { name: boundSummary })
      .waitFor()

    // A bound of zero would forbid all traffic rather than bound it, so the page
    // refuses it and issues nothing instead of sending a form the server rejects.
    await page.getByRole('button', { name: 'Credentials' }).click()
    await page.getByPlaceholder('ci').fill(`${keyName}-rejected`)
    await page.locator('.binding').filter({ hasText: providerName }).locator('input').check()
    await page.getByLabel('Max concurrent requests').fill('0')
    await page.getByRole('button', { name: 'Create credential' }).click()
    await page.getByText('A bound must be at least 1.').waitFor()
    assert.equal(await page.getByRole('row').filter({ hasText: `${keyName}-rejected` }).count(), 0)

    await page.reload({ waitUntil: 'networkidle' })
    await page.getByRole('heading', { name: 'Credentials' }).waitFor()
    assert.equal(await page.locator('.credential-card').count(), 0)
    assert.equal(await page.getByText(createdCredential).count(), 0)

    page.once('dialog', (dialog) => dialog.accept())
    await page
      .getByRole('row')
      .filter({ has: page.getByRole('cell', { name: keyName, exact: true }) })
      .getByRole('button', { name: 'Rotate credential' })
      .click()
    await page.getByRole('heading', { name: `New credential for ${keyName}` }).waitFor()
    const rotatedCredential = (await page.locator('.credential-card code').innerText()).trim()
    assert.notEqual(rotatedCredential, createdCredential)
    assert.deepEqual(await storedCredentialTraces(page, rotatedCredential), {
      local: false,
      session: false,
    })
    await page.getByRole('button', { name: 'I have stored it' }).click()

    // A regular user manages only its own credentials, so it never sees the
    // administrator-only views.
    const userName = `analyst-${label}`
    const userPassword = await createAccount(page, userName)
    await signOut(page)
    await page.getByLabel('Account').fill(userName)
    await page.getByLabel('Password').fill(userPassword)
    await page.getByRole('button', { name: 'Sign in' }).click()
    await page.getByRole('heading', { name: 'Credentials' }).waitFor()
    assert.equal(await page.getByRole('button', { name: 'Accounts' }).count(), 0)
    assert.equal(await page.getByRole('button', { name: 'Settings' }).count(), 0)
    const userScope = await page.evaluate(async () => {
      const response = await fetch('/admin/api/accounts', { credentials: 'same-origin' })
      return response.status
    })
    assert.equal(userScope, 403)
    assert.equal(
      await page.getByRole('cell', { name: keyName, exact: true }).count(),
      0,
      'a regular user must not see another account\'s credentials',
    )

    await signOut(page)
    await page.getByLabel('Account').fill(accountName)
    await page.getByLabel('Password').fill(password)
    await page.getByRole('button', { name: 'Sign in' }).click()
    await page.getByRole('heading', { name: 'Credentials' }).waitFor()

    const logQueries = []
    const onLogRequest = (request) => {
      const url = new URL(request.url())
      if (url.pathname === '/admin/api/request-logs') logQueries.push(url.searchParams)
    }
    page.on('request', onLogRequest)
    await page.getByRole('button', { name: 'Request logs' }).click()
    await page.getByRole('button', { name: 'Apply filters' }).waitFor()
    await page.locator('label').filter({ hasText: 'Transport' }).locator('select').selectOption('http')
    await page.getByRole('status').filter({ hasText: 'Filters are edited but not applied' }).waitFor()
    await page.getByRole('button', { name: 'Apply filters' }).click()
    await waitFor(() => logQueries.some((query) => query.get('transport_type') === 'http'), 'applied log filter was not sent')
    const applied = logQueries.filter((query) => query.get('transport_type') === 'http')
    assert.equal(applied.at(-1).has('after_id'), false)
    await waitFor(
      () => page.getByRole('button', { name: 'Apply filters' }).isEnabled(),
      'applying filters left the page busy',
    )
    await page.locator('label').filter({ hasText: 'Transport' }).locator('select').selectOption('websocket')
    await page.getByRole('status').filter({ hasText: 'Filters are edited but not applied' }).waitFor()
    const beforeDraft = logQueries.length
    await delay(200)
    assert.equal(logQueries.length, beforeDraft, 'editing filters must not page with a draft cursor')
    await page.getByRole('button', { name: 'Apply filters' }).click()
    await waitFor(
      () => logQueries.some((query) => query.get('transport_type') === 'websocket' && !query.has('after_id')),
      'changing filters must restart without the previous cursor',
    )
    page.off('request', onLogRequest)

    const signOutButton = page.getByRole('button', { name: 'Sign out' })
    await waitFor(() => signOutButton.isEnabled(), 'the page stayed busy after applying filters')
    await signOutButton.click()
    await page.getByRole('heading', { name: 'Sign in' }).waitFor()
    await page.reload({ waitUntil: 'networkidle' })
    await page.getByRole('heading', { name: 'Sign in' }).waitFor()
    checkCache()
  } finally {
    await context.close()
  }
}

async function signOut(page) {
  const button = page.getByRole('button', { name: 'Sign out' })
  await waitFor(() => button.isEnabled(), 'the page stayed busy')
  await button.click()
  await page.getByRole('heading', { name: 'Sign in' }).waitFor()
}

async function runExpiry(browser, origin) {
  const context = await browser.newContext()
  const page = await context.newPage()
  try {
    await signIn(page, origin)
    await delay(expirySessionTtlMs + 1_200)
    await page.reload({ waitUntil: 'networkidle' })
    await page.getByRole('heading', { name: 'Sign in' }).waitFor()
  } finally {
    await context.close()
  }
}

const directory = mkdtempSync(join(tmpdir(), 'tokenstream-admin-browser-'))
let main
let mainVite
let expiry
let expiryVite
let browser
try {
  main = await startGateway({
    name: 'admin-browser-main',
    directory,
    sessionTtlMs: mainSessionTtlMs,
  })
  mainVite = await startVite(main.adminPort)
  expiry = await startGateway({
    name: 'admin-browser-expiry',
    directory,
    sessionTtlMs: expirySessionTtlMs,
  })
  expiryVite = await startVite(expiry.adminPort)
  browser = await chromium.launch({ headless: true })
  await runSuite(browser, `http://127.0.0.1:${main.adminPort}`, 'hosted')
  console.log('passed control-plane hosted administration page')
  await runSuite(browser, `http://127.0.0.1:${mainVite.port}`, 'proxied')
  console.log('passed development-server proxied administration page')
  await runExpiry(browser, `http://127.0.0.1:${expiry.adminPort}`)
  console.log('passed hosted session expiry')
  await runExpiry(browser, `http://127.0.0.1:${expiryVite.port}`)
  console.log('passed proxied session expiry')
} finally {
  if (browser) await browser.close()
  await stop(mainVite?.child)
  await stop(expiryVite?.child)
  await stop(main?.processHandle)
  await stop(expiry?.processHandle)
}
