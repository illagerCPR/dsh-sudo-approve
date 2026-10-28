// Scratch harness for build 13 — P1/P2 fixes. Drives the real module, never the live Host.
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
const root = fileURLToPath(new URL('..', import.meta.url))

const home = mkdtempSync(join(tmpdir(), 'dsa-b13-home-'))
process.env.DSH_HOME = home
process.env.XDG_RUNTIME_DIR = mkdtempSync(join(tmpdir(), 'dsa-b13-run-'))

const results = []
const check = (name, ok, extra = '') => {
  results.push({ name, ok })
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${extra === '' ? '' : `  [${extra}]`}`)
}

const mod = await import(`${root}/index.js`)

function makeCtx() {
  const handlers = new Map()
  const effects = []
  const routes = new Map()
  const connection = {
    allowsRemoteAuthorities: false,
    fetch: { register: (route) => routes.set(route.path, route) },
  }
  const get = (name) => {
    if (name === 'shell') return { resolve: (request) => ({ command: request.command, workdir: '/tmp', timeoutMs: 1000 }) }
    if (name === 'agents') return { roots: () => [{ id: 'session-x' }] }
    if (name === 'sandboxPolicy') return { resolve: () => ({ mode: 'danger-full-access' }) }
    if (name === 'connection') return connection
    return undefined
  }
  const ctx = {
    on: (name, fn) => handlers.set(name, fn),
    effect: (fn) => effects.push(fn() ?? (() => {})),
    get,
    inject: (_services, cb) => {
      cb({ get })
      return { dispose: () => {} }
    },
  }
  return { ctx, handlers, effects, routes }
}

const ex = (command, callId = 'call-1') => ({
  name: 'bash',
  callId,
  args: { command },
  arguments: { command },
  agent: { id: 'session-x', session: { cwd: '/tmp' } },
  signal: undefined,
  parent: undefined,
})
const next = async () => 'dispatched'
const auditLines = () => readFileSync(join(home, 'logs', 'dsh-sudo-approve.log'), 'utf8').trim().split('\n').map((line) => JSON.parse(line))

// ------------------------------------------------------- A. N4 + regressions
{
  const { ctx, handlers } = makeCtx()
  mod.apply(ctx, { passwordDialog: 'browser' })
  const pre = handlers.get('tools/pre-execute')

  const literal = await pre(ex('sudo -n true'), next)
  check('A1 literal sudo still gated', literal?.kind === 'deny', JSON.stringify(literal?.kind))

  const spliced = await pre(ex('su\\\ndo -n true'), next)
  check('A2 spliced token is now gated', spliced?.kind === 'deny', JSON.stringify(spliced))

  const spaced = await pre(ex('su\\\r\ndo -n true'), next)
  check('A3 CRLF splice is gated too', spaced?.kind === 'deny', JSON.stringify(spaced))

  const quoted = await pre(ex('s""udo -n true'), next)
  check('A4 quote splicing still bypasses (known M1)', quoted === 'dispatched', JSON.stringify(quoted))

  const sixtyThree = Array.from({ length: 62 }, (_, i) => (i === 61 ? 'sudo id' : `echo line-${i}`)).join('\n')
  const longLines = `echo line-0\n${sixtyThree}`
  const truncated = await pre(ex(longLines), next)
  check('A5 63-line command still refused', truncated?.kind === 'deny' && /超出面板/.test(truncated.reason), JSON.stringify(truncated?.kind))

  const longLine = `sudo id # ${'x'.repeat(500)}`
  const wide = await pre(ex(longLine), next)
  check('A6 over-wide line still refused', wide?.kind === 'deny', JSON.stringify(wide?.kind))

  const plain = await pre(ex('echo hello'), next)
  check('A7 non-sudo command untouched', plain === 'dispatched', String(plain))
}

// --------------------------------------------- B. N1 gesture ordering
{
  const { ctx, handlers, routes } = makeCtx()
  mod.apply(ctx, { passwordDialog: 'browser' })
  const pre = handlers.get('tools/pre-execute')
  const pendingRoute = routes.get('/api/sudo-approve/pending')
  const respondRoute = routes.get('/api/sudo-approve/respond')
  const get = (url) => pendingRoute.fetch(new Request(`http://127.0.0.1:3080${url}`))
  const post = (url, body) =>
    respondRoute.fetch(
      new Request(`http://127.0.0.1:3080${url}`, {
        method: 'POST',
        body: JSON.stringify(body),
        headers: { 'content-type': 'application/json' },
      }),
    )

  await get('/api/sudo-approve/pending?state=visible')
  const running = pre(ex('sudo id'), next)
  await new Promise((resolve) => setImmediate(resolve))
  const snapshot = await (await get('/api/sudo-approve/pending?state=visible')).json()
  const id = snapshot.value.requests[0].id
  check('B1 panel shows the pending request', typeof id === 'string')

  const selfClaim = await (
    await post('/api/sudo-approve/respond?state=visible&interaction=1', {
      id,
      decision: 'approve',
      interaction: true,
      password: 'wrong-password-x',
    })
  ).json()
  check('B2 approval can no longer supply its own gesture', selfClaim.error?.code === 'sudo-approve/no-interaction', selfClaim.error?.code)

  await get('/api/sudo-approve/pending?state=visible&interaction=1')
  const afterGesture = await (
    await post('/api/sudo-approve/respond?state=visible&interaction=1', {
      id,
      decision: 'approve',
      interaction: true,
      password: 'wrong-password-x',
    })
  ).json()
  check('B3 a gesture reported first lets the approval through', afterGesture.error?.code === 'sudo-approve/invalid-password', afterGesture.error?.code)

  await post('/api/sudo-approve/respond', { id, decision: 'reject', reason: 'harness' })
  const verdict = await running
  check('B4 rejection settles the gate', verdict?.kind === 'deny', JSON.stringify(verdict?.kind))

  const denied = auditLines().filter((line) => line.event === 'denied' && line.reason === 'no-interaction')
  check('B5 the refusal is audited', denied.length >= 1, String(denied.length))
}

// --------------------------------------- C. N2 reset keeps security keys
{
  writeFileSync(
    join(home, 'dsh-sudo-approve.json'),
    JSON.stringify({ enabled: false, credential: 'askpass', remember: 'never', timeoutMs: 30_000 }, null, 2),
  )
  const { ctx, routes } = makeCtx()
  mod.apply(ctx, { passwordDialog: 'browser' })
  const configRoute = routes.get('/api/sudo-approve/config')
  const read = async () =>
    (await (await configRoute.fetch(new Request('http://127.0.0.1:3080/api/sudo-approve/config'))).json()).value.values
  const post = (body) =>
    configRoute.fetch(
      new Request('http://127.0.0.1:3080/api/sudo-approve/config', {
        method: 'POST',
        body: JSON.stringify(body),
        headers: { 'content-type': 'application/json' },
      }),
    )

  const before = await read()
  check('C1 file-only values are honoured', before.enabled === false && before.credential === 'askpass', JSON.stringify(before))

  const direct = await (await post({ patch: { enabled: true, credential: 'auto' } })).json()
  check('C2 direct patch of file-only keys is refused', direct.ok === false, direct.error?.code)

  const reset = await (await post({ reset: true })).json()
  const after = reset.ok === true ? reset.value.values : await read()
  check('C3 reset keeps enabled=false', after.enabled === false, String(after.enabled))
  check('C4 reset keeps credential=askpass', after.credential === 'askpass', String(after.credential))
  check('C5 reset clears the page-owned timeout', after.timeoutMs === 120_000, String(after.timeoutMs))

  const stored = JSON.parse(readFileSync(join(home, 'dsh-sudo-approve.json'), 'utf8'))
  check('C6 store file still holds the security keys', stored.enabled === false && stored.credential === 'askpass', JSON.stringify(stored))

  const configured = auditLines().filter((line) => line.event === 'configured' && line.reset === true)
  check('C7 reset is audited with the kept keys', configured.length >= 1 && Array.isArray(configured[0].kept), JSON.stringify(configured[0]?.kept))

  const timing = await (await post({ patch: { timeoutMs: 20_000 } })).json()
  check('C8 the page may still change its own knobs', timing.ok === true && timing.value.values.timeoutMs === 20_000, String(timing.value?.values?.timeoutMs))
}

// ------------------------------------- D. N7: page may only narrow presence
{
  const { ctx, routes } = makeCtx()
  mod.apply(ctx, { passwordDialog: 'browser' })
  const configRoute = routes.get('/api/sudo-approve/config')
  const post = (body) =>
    configRoute.fetch(
      new Request('http://127.0.0.1:3080/api/sudo-approve/config', {
        method: 'POST',
        body: JSON.stringify(body),
        headers: { 'content-type': 'application/json' },
      }),
    )
  const read = async () =>
    (await (await configRoute.fetch(new Request('http://127.0.0.1:3080/api/sudo-approve/config'))).json()).value

  const snapshot = await read()
  check('D1 the page sees the narrow presence range', snapshot.limits.presenceWindowMs[1] === 30_000, JSON.stringify(snapshot.limits))

  const wide = await (await post({ patch: { presenceWindowMs: 300_000 } })).json()
  check('D2 a wide presence window is clamped for the page', wide.value.values.presenceWindowMs === 30_000, String(wide.value?.values?.presenceWindowMs))

  const narrow = await (await post({ patch: { presenceWindowMs: 1_000 } })).json()
  check('D3 a tiny presence window is clamped up', narrow.value.values.presenceWindowMs === 2_000, String(narrow.value?.values?.presenceWindowMs))
}

const failed = results.filter((entry) => !entry.ok)
console.log(`\n${results.length - failed.length}/${results.length} checks matched`)
rmSync(home, { recursive: true, force: true })
process.exit(failed.length === 0 ? 0 : 1)
