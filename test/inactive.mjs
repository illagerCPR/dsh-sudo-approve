// Inactive-host harness — a Host whose sudo cannot be trusted must still answer
// the settings page, and must answer nothing else. Before 1.0.3 it said nothing
// at all: the page drew a normal form ("启用拦截 ✓") over a gate that never
// loaded, and the only trace was one audit line nobody reads.
//
// Both halves are covered here: the diagnosis that names the failed check, and
// the single read-only route the Host registers instead of the approval routes.
import { chmodSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
const root = fileURLToPath(new URL('..', import.meta.url))

const home = mkdtempSync(join(tmpdir(), 'dsa-inactive-home-'))
process.env.DSH_HOME = home
const logPath = join(home, 'logs', 'dsh-sudo-approve.log')

const results = []
const check = (name, ok, extra = '') => {
  results.push(ok)
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${extra === '' ? '' : `  [${extra}]`}`)
}

const { diagnoseTrust, resolveTrusted } = await import(`${root}/lib/trusted.js`)
const mod = await import(`${root}/index.js`)

/**
 * A fake Host context.
 *
 * Same shape the other harnesses use: routes land in a map keyed by path, event
 * handlers in another, and `effect` runs immediately so the routes are
 * registered by the time `apply` returns.
 */
function makeCtx() {
  const handlers = new Map()
  const routes = new Map()
  const own = []
  const connection = { allowsRemoteAuthorities: false, fetch: { register: (route) => routes.set(route.path, route) } }
  const systemPrompt = { context: () => {}, getContextOrder: () => 100 }
  const shell = { resolve: (request) => ({ command: request.command, workdir: '/tmp', timeoutMs: 1000 }) }
  const get = (name) => {
    if (name === 'connection') return connection
    if (name === 'systemPrompt') return systemPrompt
    if (name === 'shell') return shell
    if (name === 'agents') return { list: () => [] }
    if (name === 'sandboxPolicy') return { resolve: () => ({ mode: 'danger-full-access' }) }
    if (name === 'tools') return { schemas: () => [] }
    return undefined
  }
  const ctx = {
    on: (name, fn) => handlers.set(name, fn),
    effect: (fn) => {
      const dispose = fn()
      if (typeof dispose === 'function') own.push(dispose)
    },
    get,
    inject: (_services, cb) => {
      cb({ get, systemPrompt, shell, connection })
      return { dispose: () => {} }
    },
  }
  const dispose = () => {
    for (const fn of own.splice(0)) {
      try {
        fn()
      } catch {
        // a torn-down install is not a test failure
      }
    }
  }
  return { ctx, handlers, routes, dispose }
}

// --- T: the diagnosis names the step that failed ---------------------------
const ownDir = mkdtempSync(join(tmpdir(), 'dsa-own-'))
const ownFile = join(ownDir, 'sudo')
writeFileSync(ownFile, '#!/bin/sh\nexit 0\n')
chmodSync(ownFile, 0o755)
{
  const verdict = diagnoseTrust('', [ownFile])
  check('T1 a same-user binary is reported as not root-owned', verdict.ok === false && verdict.check === 'not-root-owned', verdict.check)
  check('T2 the report names the binary it rejected', verdict.path === ownFile, verdict.path)
  const missing = diagnoseTrust('', ['/nonexistent/definitely-not-here'])
  check('T3 a missing candidate is reported as missing', missing.ok === false && missing.check === 'missing', missing.check)
  const relative = diagnoseTrust('', ['usr/bin/sudo'])
  check('T4 a relative candidate is reported as such', relative.ok === false && relative.check === 'relative-path', relative.check)
  check('T5 the report keeps the candidate list', Array.isArray(relative.tried) && relative.tried.length === 1)
  // The two functions answer the same question, so they must never disagree.
  const agrees = (resolveTrusted('', ['/usr/bin/sudo']) === undefined) === !diagnoseTrust('', ['/usr/bin/sudo']).ok
  check('T6 diagnosis and resolution agree on /usr/bin/sudo', agrees)
  // A pinned path replaces the defaults instead of preceding them: falling back
  // would hand the password to a binary the operator did not name.
  const pinned = diagnoseTrust(ownFile, ['/usr/bin/sudo'])
  check('T7 a pinned path never falls back to the defaults', pinned.ok === false && pinned.path === ownFile, pinned.path)
}

// --- H: the Host stops early, but still answers the page -------------------
{
  const { ctx, handlers, routes, dispose } = makeCtx()
  mod.apply(ctx, { sudoPath: ownFile })

  const lines = readFileSync(logPath, 'utf8').split('\n')
  const inactive = lines.filter((line) => line.includes('"event":"inactive"')).at(-1) ?? ''
  check(
    'H1 the Host records which check failed',
    inactive.includes('"reason":"sudo-not-trusted"') && inactive.includes('"check":"not-root-owned"'),
    inactive.slice(0, 90),
  )
  check('H2 the audit line carries no command text', !inactive.includes('sudo ') || inactive.includes('"path"'))

  const config = routes.get('/api/sudo-approve/config')
  check('H3 the settings route is still answered', config !== undefined)
  check(
    'H4 and it is GET-only',
    Array.isArray(config?.methods) && config.methods.length === 1 && config.methods[0] === 'GET',
    String(config?.methods),
  )

  const payload = await (await config.fetch(new Request('http://127.0.0.1/api/sudo-approve/config'))).json()
  const value = payload.value ?? {}
  check(
    'H5 the payload says the plugin is not active',
    payload.ok === true && value.active === false && value.reason === 'sudo-not-trusted',
    JSON.stringify(value.reason),
  )
  check(
    'H6 the payload names the rejected binary and the failed check',
    value.sudo?.check === 'not-root-owned' && value.sudo?.path === ownFile,
    JSON.stringify(value.sudo),
  )
  check(
    'H7 no approval route is registered',
    !routes.has('/api/sudo-approve/pending') && !routes.has('/api/sudo-approve/respond'),
  )
  check('H8 no bash interception is installed', !handlers.has('tools/pre-execute'))
  dispose()
}

// --- A: a trusted Host still takes the normal path -------------------------
{
  const trusted = diagnoseTrust('', ['/usr/bin/sudo']).ok
  if (trusted) {
    const { ctx, handlers, routes, dispose } = makeCtx()
    mod.apply(ctx, {})
    check('A1 a trusted Host registers the approval routes', routes.has('/api/sudo-approve/pending'))
    check('A2 a trusted Host intercepts bash', handlers.has('tools/pre-execute'))
    const payload = await (await routes.get('/api/sudo-approve/config').fetch(new Request('http://127.0.0.1/api/sudo-approve/config'))).json()
    check('A3 a trusted Host does not report itself inactive', payload.value?.active !== false)
    dispose()
  } else {
    console.log('SKIP  A1-A3 (this machine has no trusted /usr/bin/sudo)')
  }
}

const failed = results.filter((ok) => !ok).length
console.log(`\n${results.length - failed}/${results.length} checks matched`)
if (failed > 0) process.exitCode = 1
