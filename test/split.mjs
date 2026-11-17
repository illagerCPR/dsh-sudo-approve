// split-seam harness — the parts test/audit.mjs never touched:
// the runtime-context paragraph, the armed hand-off, the shim roundtrip and the
// route table. Drives the real modules, never the live Host.
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync, chmodSync } from 'node:fs'
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
  const tools = options.tools ?? { get: (name) => (ptc && name === 'run_code' ? { name } : undefined) }
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
const { programTransportsOf } = await import(`${root}/lib/agents.js`)
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

// --- E8-E11: the DSH 0.2.2 executor-owned transport ------------------------
{
  // 0.2.2 forbids registering `run_code`; only the selected executor's
  // describe() still names it. This is the shape the live Host has now.
  let describedWith
  const executorTools = (schemas) => ({
    get: () => undefined,
    selectExecutor: () => ({
      describe: (tools) => {
        describedWith = tools
        return { schemas }
      },
    }),
  })
  const ptcCtx = makeCtx({ tools: executorTools([{ name: 'run_code' }]) }).ctx
  check(
    'E8 rc.1 PTC is recognised through the selected executor',
    programTransportsOf(ptcCtx, { id: 'session-x' }).includes('run_code') && describedWith?.length === 0,
  )
  const nativeCtx = makeCtx({ tools: executorTools([]) }).ctx
  check('E9 a native executor is not mistaken for PTC', programTransportsOf(nativeCtx, { id: 'session-x' }).length === 0)
  const legacyCtx = makeCtx({ ptc: true }).ctx
  check('E10 the pre-0.2.2 tools.get path still works', programTransportsOf(legacyCtx, { id: 'session-x' }).includes('run_code'))
  const brokenCtx = makeCtx({
    tools: {
      get: () => {
        throw new Error('registry unavailable')
      },
      selectExecutor: () => {
        throw new Error('executor unavailable')
      },
    },
  }).ctx
  check('E11 an unreadable executor is treated as no program channel', programTransportsOf(brokenCtx, { id: 'session-x' }).length === 0)
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

// --- I: the shim only reads sudo's own leading option ----------------------
// Issue #1: `for arg do` scanned the whole argv, so a wrapped program's own `-h`
// (`df -h`, `free -h`, `dumpe2fs -h`) was taken for sudo's and `-A` was dropped.
// sudo then had no askpass helper, PAM saw no password, and the failure counted
// against pam_faillock — three of them reached the default deny=3 and locked the
// account out of sudo. The shim is driven here against a fake sudo that only
// echoes its argv, so no PAM is involved.
{
  const { spawnSync } = await import('node:child_process')
  const { AsyncLocalStorage } = await import('node:async_hooks')
  const scope = new AsyncLocalStorage()
  const fakeDir = mkdtempSync(join(tmpdir(), 'dsa-shim-fake-'))
  const fake = join(fakeDir, 'fake-sudo')
  writeFileSync(fake, '#!/bin/sh\nprintf "%s\\n" "$*"\n')
  chmodSync(fake, 0o755)
  const shim = createShim({
    name: 'dsh-sudo-approve',
    scope,
    basePath: '/usr/bin:/bin',
    realSudo: { path: fake },
    realSudoedit: undefined,
    audit: () => {},
  })
  const run = await shim.materialize('hunter2')
  /** Run the generated shim with these arguments and return its argv echo. */
  const argvOf = (...args) => spawnSync(join(run.bin, 'sudo'), args, { encoding: 'utf8' }).stdout.trim()

  // The regression itself: a bare -h belongs to the wrapped program.
  check('I1 sudo df -h keeps -A', argvOf('df', '-h') === '-A df -h', argvOf('df', '-h'))
  check('I2 sudo dumpe2fs -h keeps -A', argvOf('dumpe2fs', '-h', '/dev/sda') === '-A dumpe2fs -h /dev/sda', argvOf('dumpe2fs', '-h', '/dev/sda'))
  check('I3 sudo free -h keeps -A', argvOf('free', '-h') === '-A free -h', argvOf('free', '-h'))
  check('I4 a trailing -h keeps -A', argvOf('ls', '-l', '-h') === '-A ls -l -h', argvOf('ls', '-l', '-h'))
  check('I5 a combined -lh keeps -A', argvOf('ls', '-lh') === '-A ls -lh', argvOf('ls', '-lh'))
  // sudo's own metadata forms still pass through untouched: sudo-rs refuses
  // --reset-timestamp together with --askpass, so adding -A would break them.
  check('I6 sudo -k passes through', argvOf('-k') === '-k', argvOf('-k'))
  check('I7 sudo -K passes through', argvOf('-K') === '-K', argvOf('-K'))
  check('I8 sudo -V passes through', argvOf('-V') === '-V', argvOf('-V'))
  check('I9 sudo -h passes through', argvOf('-h') === '-h', argvOf('-h'))
  check('I10 sudo --reset-timestamp passes through', argvOf('--reset-timestamp') === '--reset-timestamp', argvOf('--reset-timestamp'))
  // A metadata flag followed by a command does authenticate, so it takes -A.
  check('I11 sudo -k ls keeps -A', argvOf('-k', 'ls') === '-A -k ls', argvOf('-k', 'ls'))
  check('I12 sudo -u root id keeps -A', argvOf('-u', 'root', 'id') === '-A -u root id', argvOf('-u', 'root', 'id'))
  await shim.dematerialize(run)
  rmSync(fakeDir, { recursive: true, force: true })
}

// --- J: a lockout is not reported as a wrong password ---------------------
// Issue #1, secondary: pam_faillock's preauth rejects before the password is
// checked, so every password fails once the tally reaches deny. Reading that as
// "wrong password" sends the operator into a retry loop that keeps the lock
// alive. The probe and the marker are pure, so they are tested directly.
{
  const { denyFrom, lockoutMarker, validFailures, DEFAULT_DENY } = await import(`${root}/lib/lockout.js`)
  check('J1 the default deny is 3', DEFAULT_DENY === 3)
  check('J2 deny is read from faillock.conf', denyFrom('deny = 5\nunlock_time = 600\n') === 5)
  check('J3 a commented deny is ignored', denyFrom('# deny = 9\ndeny = 4\n') === 4)
  check('J4 an unreadable conf falls back to the default', denyFrom(undefined) === DEFAULT_DENY)
  check('J5 a malformed deny falls back to the default', denyFrom('deny = many\n') === DEFAULT_DENY)

  const table = [
    'illager_aris:',
    'When                Type  Source                                           Valid',
    '2026-11-17 18:38:19 V     sudo                                              V',
    '2026-11-17 18:38:21 V     sudo                                              V',
    '2026-11-17 18:38:23 V     sudo                                              I',
  ].join('\n')
  check('J6 only valid rows are counted', validFailures(table) === 2, String(validFailures(table)))
  check('J7 a missing table is unknown, not zero', validFailures('') === undefined)
  check('J8 an empty table counts zero', validFailures('u:\nWhen                Type  Source                                           Valid\n') === 0)

  check('J9 PAM lockout text is recognised', lockoutMarker('sudo: Account validation failure, is your account locked?') !== undefined)
  check('J10 "temporarily locked" is recognised', lockoutMarker('pam_faillock: account temporarily locked') !== undefined)
  check('J11 an ordinary failure is not a lockout', lockoutMarker('sudo: Authentication failed, try again.') === undefined)
  check('J12 empty stderr is not a lockout', lockoutMarker('') === undefined)
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
