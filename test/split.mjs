// split-seam harness — the parts test/audit.mjs never touched:
// the runtime-context paragraph, the armed hand-off, the shim roundtrip and the
// route table. Drives the real modules, never the live Host.
import { existsSync, mkdtempSync, readdirSync, readFileSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
const root = fileURLToPath(new URL('..', import.meta.url))

const home = mkdtempSync(join(tmpdir(), 'dsa-split-home-'))
process.env.DSH_HOME = home
process.env.XDG_RUNTIME_DIR = mkdtempSync(join(tmpdir(), 'dsa-split-run-'))

const results = []
const disposers = []
const check = (name, ok, extra = '') => {
  results.push({ name, ok })
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${extra === '' ? '' : `  [${extra}]`}`)
}

function makeCtx(options = {}) {
  const { roots = [{ id: 'session-x' }], sandboxMode = 'danger-full-access', remote = false, ptc = false } = options
  const handlers = new Map()
  const effects = []
  const routes = new Map()
  const contexts = []
  const connection = { allowsRemoteAuthorities: remote, fetch: { register: (route) => routes.set(route.path, route) } }
  const systemPrompt = { context: (spec) => contexts.push(spec), getContextOrder: () => 100 }
  const shell = { resolve: (request) => ({ command: request.command, workdir: '/tmp', timeoutMs: 1000 }) }
  const tools = { get: (name) => (ptc && name === 'run_code' ? { name } : undefined) }
  const get = (name) => {
    if (name === 'shell') return shell
    if (name === 'agents') return { roots: () => roots }
    if (name === 'sandboxPolicy') return { resolve: () => ({ mode: sandboxMode }) }
    if (name === 'connection') return connection
    if (name === 'systemPrompt') return systemPrompt
    if (name === 'tools') return tools
    return undefined
  }
  const ctx = {
    on: (name, fn) => handlers.set(name, fn),
    effect: (fn) => {
      const dispose = fn()
      const owned = typeof dispose === 'function' ? dispose : () => {}
      effects.push(owned)
      disposers.push(owned)
    },
    get,
    inject: (_services, cb) => {
      cb({ get, systemPrompt, shell, connection })
      return { dispose: () => {} }
    },
  }
  return { ctx, handlers, routes, contexts, effects }
}

const mod = await import(`${root}/index.js`)
const { createGate } = await import(`${root}/lib/gate.js`)
const { createShim } = await import(`${root}/lib/shim.js`)
const { digestOf } = await import(`${root}/lib/analysis.js`)

// --- E: the runtime-context paragraph -------------------------------------
{
  const { ctx, contexts } = makeCtx()
  mod.apply(ctx, { passwordDialog: 'browser' })
  const spec = contexts[0]
  check('E1 the prompt paragraph is registered once', contexts.length === 1)
  const agent = { id: 'session-x', session: {} }
  const native = spec.text({ agent })
  check('E2 the native variant is the plain-bash one', native.includes('a foreground `bash` call') && !native.includes('run_code'), native.slice(0, 40))
  check('E3 the shared rules travel with it', native.includes('Write it plainly') && native.includes('59') === false)
  check('E4 a subagent is told nothing', spec.text({ agent: { id: 'other', session: {} } }) === '')
  check('E5 the paragraph sits right after the approval policy', spec.order === 101 && spec.name === 'dsh-sudo-approve:availability')
}
{
  const { ctx, contexts } = makeCtx({ ptc: true })
  mod.apply(ctx, { passwordDialog: 'browser' })
  const text = contexts[0].text({ agent: { id: 'session-x', session: {} } })
  check('E6 the PTC variant replaces the native opening', text.includes('through `run_code`') && !text.includes('a foreground `bash` call'))
}
{
  const { ctx, contexts } = makeCtx({ sandboxMode: 'workspace-write' })
  mod.apply(ctx, { passwordDialog: 'browser' })
  check('E7 a confined session is told nothing', contexts[0].text({ agent: { id: 'session-x', session: {} } }) === '')
}

// --- F: the route table ----------------------------------------------------
{
  const { ctx, routes } = makeCtx()
  mod.apply(ctx, { passwordDialog: 'browser' })
  const paths = [...routes.keys()].sort()
  check('F1 the three routes are registered', paths.length === 3 && paths[0] === '/api/sudo-approve/config', paths.join(' '))
  check('F2 the answer route is POST-only', routes.get('/api/sudo-approve/respond').methods.join() === 'POST')
  check('F3 the settings route answers GET and POST', routes.get('/api/sudo-approve/config').methods.join() === 'GET,POST')
}

// --- G: armed hand-off (the fail-closed half) -----------------------------
{
  const auditLines = []
  const gate = createGate({
    ctx: makeCtx().ctx,
    config: () => ({ presenceWindowMs: 15_000, remember: 'never', allowRemoteDeployment: false, timeoutMs: 120_000, enabled: true, toolNames: new Set(['bash']) }),
    audit: (event) => auditLines.push(event),
    remembered: new Map(),
    ptc: { nestedPlan: () => ({ waitMs: 1_000 }), budgetMs: () => undefined },
  })
  const exec = { callId: 'c1', agent: { id: 'session-x' }, arguments: { command: 'sudo id -un' } }
  gate.arm(exec, 'pw', digestOf('sudo id -un'))
  const same = { ...exec, arguments: { command: 'sudo id -un' } }
  check('G1 the identical command gets the secret', gate.takeArmed(same)?.secret === 'pw')
  check('G2 the secret is single-use', gate.takeArmed(same) === undefined)

  gate.arm(exec, 'pw', digestOf('sudo id -un'))
  let thrown
  try {
    gate.takeArmed({ ...exec, arguments: { command: 'sudo rm -rf /' } })
  } catch (error) {
    thrown = error.message
  }
  check('G3 a changed command is refused', typeof thrown === 'string' && thrown.includes('不匹配'), thrown ?? 'no throw')
  check('G4 the refusal is audited', auditLines.some((line) => line.event === 'armed-mismatch'))

  gate.arm(exec, 'pw', digestOf('sudo id -un'))
  thrown = undefined
  try {
    gate.takeArmed({ ...exec, arguments: {} })
  } catch (error) {
    thrown = error.message
  }
  const noCommand = auditLines.filter((line) => line.reason === 'no-command')
  check('G5 a command that cannot be read back is refused', typeof thrown === 'string' && noCommand.length === 1)
}

// --- H: the shim roundtrip -------------------------------------------------
{
  const auditLines = []
  const { AsyncLocalStorage } = await import('node:async_hooks')
  const scope = new AsyncLocalStorage()
  const shim = createShim({
    name: 'dsh-sudo-approve',
    scope,
    basePath: '/usr/bin:/bin',
    realSudo: { path: '/usr/bin/sudo' },
    realSudoedit: undefined,
    audit: (event) => auditLines.push(event),
  })
  check('H1 delivery starts unscoped', shim.isScoped() === false)
  const run = await shim.materialize('hunter2')
  const passwordFile = join(run.root, 'askpass.txt')
  const mode = statSync(passwordFile).mode & 0o777
  const shimText = readFileSync(join(run.bin, 'sudo'), 'utf8')
  check('H2 the password file is 0600', mode === 0o600, mode.toString(8))
  check('H3 the shim adds -A and reads the helper', shimText.includes('exec "/usr/bin/sudo" -A "$@"') && shimText.includes(run.askpass))
  check('H4 the scope answers for the same instance', scope.run(run, () => scope.getStore()?.bin) === run.bin)
  await shim.dematerialize(run)
  check('H5 the directory is gone afterwards', !existsSync(run.root))
  await shim.sweepStaleRuns()
  check('H6 nothing stale is left in the runtime dir', readdirSync(process.env.XDG_RUNTIME_DIR).length === 0, readdirSync(process.env.XDG_RUNTIME_DIR).join(','))
}

// The lifecycle effect owns a 30 s timer, so every install is torn down here;
// otherwise this script would print its results and then hang forever.
for (const dispose of disposers) {
  try {
    dispose()
  } catch {
    // a torn-down install is not a test failure
  }
}

const failed = results.filter((result) => !result.ok)
console.log(`\n${results.length - failed.length}/${results.length} checks matched`)
if (failed.length > 0) process.exitCode = 1
