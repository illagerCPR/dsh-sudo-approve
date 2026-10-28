// Coverage harness — checks the boot self-check against fake tool registries.
//
// Every block disposes its own install when it finishes: the check schedules
// timers (2 s / 8 s) to re-read the registry, and a leftover timer from an
// earlier block would append an audit line in the middle of a later assertion.
import { mkdtempSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
const root = fileURLToPath(new URL('..', import.meta.url))

const home = mkdtempSync(join(tmpdir(), 'dsa-cov-home-'))
process.env.DSH_HOME = home
const logPath = join(home, 'logs', 'dsh-sudo-approve.log')

const results = []
const check = (name, ok, extra = '') => {
  results.push({ name, ok })
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${extra === '' ? '' : `  [${extra}]`}`)
}

/** Coverage audit lines written so far, oldest first. */
function coverageLines() {
  let text = ''
  try {
    text = readFileSync(logPath, 'utf8')
  } catch {
    return []
  }
  return text.split('\n').filter((line) => line.includes('"event":"coverage"'))
}
const lastCoverage = () => coverageLines().at(-1) ?? ''

function makeCtx(options = {}) {
  const toolsRef = options.toolsRef ?? { value: options.tools }
  const handlers = new Map()
  const routes = new Map()
  const own = []
  const connection = { allowsRemoteAuthorities: false, fetch: { register: (route) => routes.set(route.path, route) } }
  const systemPrompt = { context: () => {}, getContextOrder: () => 100 }
  const shell = { resolve: (request) => ({ command: request.command, workdir: '/tmp', timeoutMs: 1000 }) }
  const get = (name) => {
    if (name === 'shell') return shell
    if (name === 'agents') return { roots: () => [{ id: 'session-x' }], list: () => options.agents ?? [] }
    if (name === 'sandboxPolicy') return { resolve: () => ({ mode: 'danger-full-access' }) }
    if (name === 'connection') return connection
    if (name === 'systemPrompt') return systemPrompt
    if (name === 'tools') return toolsRef.value
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
  return { ctx, handlers, routes, toolsRef, dispose }
}

const mod = await import(`${root}/index.js`)
const { scanCoverage } = await import(`${root}/lib/coverage.js`)

const schema = (name, fields) => ({
  name,
  description: '',
  parameters: { type: 'object', properties: Object.fromEntries(fields.map((field) => [field, { type: 'string' }])) },
})
const registry = (schemas) => ({ schemas: () => schemas })
const names = new Set(['bash'])
const readConfig = async (routes) => {
  const route = routes.get('/api/sudo-approve/config')
  const payload = await (await route.fetch(new Request('http://127.0.0.1/api/sudo-approve/config'))).json()
  return payload.value?.coverage ?? payload.coverage
}

// --- the scan itself ------------------------------------------------------
{
  // The PTC transport is not an "uncovered tool": its payload is code, and the
  // fact worth naming is the processes a program can spawn on its own.
  const ptc = scanCoverage(registry([schema('bash', ['command']), schema('run_code', ['code', 'description'])]), names)
  check('C26 the PTC transport is reported as a program channel', ptc.programs?.includes('run_code') === true, JSON.stringify(ptc.programs))
  check('C27 it is not misfiled as an uncovered tool', !ptc.uncovered.some((entry) => entry.name === 'run_code'))
  check('C28 a native host reports no program channel', scanCoverage(registry([schema('bash', ['command'])]), names).programs?.length === 0)

  const report = scanCoverage(
    registry([
      schema('bash', ['command', 'description']),
      schema('shell_exec', ['command']),
      schema('workflow', ['script', 'meta']),
      schema('write', ['file_path', 'content']),
    ]),
    names,
  )
  const uncovered = report.uncovered.map((entry) => entry.name)
  check('C1 a second command tool is reported', uncovered.includes('shell_exec'), JSON.stringify(report.uncovered))
  check('C2 the covered tool is not reported', !uncovered.includes('bash') && report.covered.includes('bash'))
  check(
    'C3 the read is final and counted',
    report.available === true && report.total === 4 && report.missing.length === 0,
    JSON.stringify({ total: report.total, missing: report.missing }),
  )
  check('C4 a JS workflow is not treated as a shell', !uncovered.includes('workflow'), JSON.stringify(uncovered))
  check('C5 a plain file writer stays quiet', !uncovered.includes('write'))
}

// --- a shell tool under an unexpected field name --------------------------
{
  const report = scanCoverage(registry([schema('bash', ['command']), schema('mcp__x__terminal', ['input'])]), names)
  check(
    'C6 a command-ish tool name is reported by name',
    report.uncovered[0]?.name === 'mcp__x__terminal' && report.uncovered[0]?.why === 'name',
    JSON.stringify(report.uncovered),
  )
}

// --- unknown answers, never "all clear" -----------------------------------
{
  const absent = scanCoverage(undefined, names)
  check('C7 a missing registry is unavailable', absent.available === false && absent.total === 0)
  const broken = scanCoverage(
    {
      schemas: () => {
        throw new Error('boom')
      },
    },
    names,
  )
  check('C8 a throwing registry is not fatal', broken.available === false)
  const empty = scanCoverage(registry([]), names)
  check('C9 an empty registry is not an answer', empty.available === false && empty.total === 0)
  const partial = scanCoverage(registry([schema('shell_exec', ['command'])]), names)
  check(
    'C10 a view missing the covered tool is partial',
    partial.available === false && partial.total === 1 && partial.missing[0] === 'bash',
    JSON.stringify(partial.missing),
  )
}

// --- boot line + settings payload ----------------------------------------
{
  const before = coverageLines().length
  const { ctx, routes, dispose } = makeCtx({
    tools: registry([schema('bash', ['command']), schema('shell_exec', ['command'])]),
  })
  mod.apply(ctx, { passwordDialog: 'browser' })
  check(
    'C11 the audit line is final and names the uncovered tool',
    coverageLines().length === before + 1 &&
      lastCoverage().includes('shell_exec') &&
      lastCoverage().includes('"covered":["bash"]') &&
      lastCoverage().includes('"final":true') &&
      lastCoverage().includes('"tools":2'),
    lastCoverage().slice(0, 96),
  )

  const covered = await readConfig(routes)
  check(
    'C12 the settings payload carries the same answer',
    covered?.available === true && covered.uncovered?.[0]?.name === 'shell_exec' && covered.total === 2,
    JSON.stringify(covered ?? null).slice(0, 80),
  )
  dispose()
}

// --- the boot line and payload name the PTC channel -----------------------
{
  const before = coverageLines().length
  const { ctx, routes, dispose } = makeCtx({
    tools: registry([schema('bash', ['command']), schema('run_code', ['code', 'description'])]),
  })
  mod.apply(ctx, { passwordDialog: 'browser' })
  check(
    'C29 the boot line names the program channel',
    coverageLines().length === before + 1 && lastCoverage().includes('"programs":["run_code"]'),
    lastCoverage().slice(-80),
  )
  const covered = await readConfig(routes)
  check('C30 the settings payload carries it too', Array.isArray(covered?.programs) && covered.programs.includes('run_code'), JSON.stringify(covered?.programs ?? null))
  dispose()
}

// --- a registry that appears only after apply ----------------------------
{
  const before = coverageLines().length
  const { ctx, routes, toolsRef, dispose } = makeCtx({ toolsRef: { value: undefined } })
  mod.apply(ctx, { passwordDialog: 'browser' })
  check('C13 an absent registry writes no audit line', coverageLines().length === before)

  toolsRef.value = registry([schema('bash', ['command']), schema('shell_exec', ['command'])])
  const covered = await readConfig(routes)
  check(
    'C14 a late registry is read on demand and audited once',
    covered?.available === true && coverageLines().length === before + 1,
    `${JSON.stringify(covered ?? null).slice(0, 44)} lines=${coverageLines().length}`,
  )
  dispose()
}

// --- a host without the registry service ---------------------------------
{
  const { ctx, routes, dispose } = makeCtx()
  mod.apply(ctx, { passwordDialog: 'browser' })
  const covered = await readConfig(routes)
  check(
    'C15 no registry is reported as unavailable',
    covered?.available === false,
    JSON.stringify(covered ?? null).slice(0, 50),
  )
  dispose()
}

// --- tools mounted inside an agent composition ----------------------------
{
  // This is the live shape: the global view never contains bash, because the
  // shell tool is mounted inside the agent's own composition.
  const globals = [schema('workflow', ['script']), schema('write', ['file_path'])]
  const perAgent = new Map([
    ['session-a', [schema('bash', ['command']), schema('shell_exec', ['command']), schema('write', ['file_path'])]],
  ])
  const tools = {
    schemas: (scope) => (scope === undefined ? globals : (perAgent.get(scope.id) ?? [])),
  }
  const report = scanCoverage(tools, names, [undefined, { id: 'session-a' }])
  check(
    'C19 an agent-mounted shell tool is found through the union',
    report.available === true && report.covered.includes('bash') && report.total === 4,
    JSON.stringify({ total: report.total, views: report.views, covered: report.covered }),
  )
  check(
    'C20 a command tool found only in an agent view is reported',
    report.uncovered[0]?.name === 'shell_exec',
    JSON.stringify(report.uncovered),
  )
  check('C21 both views are counted', report.views === 2, String(report.views))

  const globalOnly = scanCoverage(tools, names, [undefined])
  check(
    'C22 the global view alone is honestly partial',
    globalOnly.available === false && globalOnly.missing.includes('bash'),
    JSON.stringify(globalOnly.missing),
  )

  const flaky = {
    schemas: (scope) => {
      if (scope !== undefined) throw new Error('scope unavailable')
      return [schema('bash', ['command'])]
    },
  }
  const tolerated = scanCoverage(flaky, names, [undefined, { id: 'broken' }])
  check(
    'C23 a view that throws is skipped, not fatal',
    tolerated.available === true && tolerated.views === 1,
    JSON.stringify({ views: tolerated.views, available: tolerated.available }),
  )
}

// --- a view that fills in progressively ----------------------------------
{
  const before = coverageLines().length
  const { ctx, routes, toolsRef, dispose } = makeCtx({ toolsRef: { value: registry([schema('shell_exec', ['command'])]) } })
  mod.apply(ctx, { passwordDialog: 'browser' })
  check(
    'C16 a partial view is logged as partial, not as an answer',
    coverageLines().length === before + 1 && lastCoverage().includes('"final":false'),
    lastCoverage().slice(0, 90),
  )

  toolsRef.value = registry([schema('bash', ['command']), schema('shell_exec', ['command'])])
  const covered = await readConfig(routes)
  check(
    'C17 the final read replaces the partial one',
    covered?.available === true && coverageLines().length === before + 2 && lastCoverage().includes('"final":true'),
    `${JSON.stringify(covered ?? null).slice(0, 46)} lines=${coverageLines().length}`,
  )

  await readConfig(routes)
  check('C18 a settled view stops writing audit lines', coverageLines().length === before + 2)
  dispose()
}

// --- the boot line itself (it was once deleted by a careless patch) -------
{
  const lines = readFileSync(logPath, 'utf8')
    .split('\n')
    .filter((line) => line.includes('"event":"loaded"'))
  check(
    'C24 every install writes a loaded line with the build and dialog facts',
    lines.length >= 1 &&
      lines.every((line) => line.includes('"build":') && line.includes('"dialog":"') && line.includes('"dialogBinary"')),
    `${lines.length} lines`,
  )
  check('C25 the boot line carries no secret and no command text', !/"(password|command)":/i.test(lines.at(-1) ?? ''))
}

const failed = results.filter((result) => !result.ok)
console.log(`\n${results.length - failed.length}/${results.length} checks matched`)
if (failed.length > 0) process.exitCode = 1
