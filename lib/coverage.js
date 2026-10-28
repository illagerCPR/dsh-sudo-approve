/**
 * Coverage self-check.
 *
 * The gate covers an allowlist of tool names (`toolNames`, default `bash`) and
 * expects the command line in `arguments.command`. Both are fixed in code, so a
 * deployment that composes a second command-running tool — another plugin's
 * `exec`, an MCP server's `shell`, a shell tool under a different name — would
 * not be gated and would leave no audit trace at all. Silent non-coverage reads
 * exactly like safety, which is the worst property an approval gate can have.
 *
 * The boot check uses the Host's own tool registry to name those tools. It
 * changes no decision and denies nothing: it makes an unchecked surface visible.
 *
 * One surface needs separate treatment. Under the PTC presentation the model
 * writes a program (`run_code`) instead of calling tools directly; that program
 * runs in a Node process and, with a permissive sandbox, can spawn processes
 * itself. Nested tool calls still pass the gate, but a direct spawn does not,
 * and no parameter heuristic can see it: the payload is `code`, not a command
 * line. The transport is therefore reported as its own `programs` field rather
 * than being fed to the same filter.
 * @module dsh-sudo-approve/lib/coverage
 */

import { RUN_CODE_NAME } from './agents.js'

/** Parameter names that carry a command line. */
const COMMAND_FIELDS = Object.freeze(['command', 'cmd', 'shell', 'exec', 'executable', 'argv'])

/**
 * Tool names that promise to run commands even when their field is named
 * something else. `script` / `code` are deliberately absent: a JavaScript or
 * Python payload is not a shell command line, and treating it as one would flag
 * orchestration tools that cannot touch a process.
 */
const COMMAND_NAMES = /(^|_)(bash|sh|shell|zsh|fish|terminal|term|exec|execute|cmd|command|subprocess)($|_)/i

/**
 * Why this tool might run a command, or undefined when it shows no sign of it.
 * @param schema - one `ToolSchema` from the Host registry.
 * @returns a short reason, used verbatim in the audit line.
 */
function commandSurface(schema) {
  const properties = schema?.parameters?.properties
  if (typeof properties === 'object' && properties !== null) {
    for (const field of Object.keys(properties)) {
      if (COMMAND_FIELDS.includes(field)) return `parameter:${field}`
    }
  }
  const name = typeof schema?.name === 'string' ? schema.name : ''
  if (COMMAND_NAMES.test(name)) return 'name'
  return undefined
}

/** Every schema one view can offer, or none when that view is unreadable. */
function visibleSchemas(tools, scope) {
  try {
    const schemas = tools.schemas(scope)
    return Array.isArray(schemas) ? schemas : []
  } catch {
    return []
  }
}

/**
 * Compare the tools this Host actually offers with the ones the gate covers.
 *
 * More than one view is read on purpose. Tools are mounted inside agent
 * compositions as well as globally — `bash` itself is one of the agent-mounted
 * ones — so the global view alone can miss the very tool a coverage report is
 * supposed to be about. The Host's own inspect provider reads `schemas(agent)`
 * for the same reason.
 *
 * `available: false` means "not a readable answer yet": the registry service is
 * absent, the views are empty, or the allowlisted tools are still missing from
 * them. The answer is then "unknown", never "all clear".
 * @param tools - the Host `tools` service, or undefined.
 * @param toolNames - the names the gate intercepts.
 * @param scopes - registry views to union: `undefined` for the global one, plus
 *   one entry per live agent.
 * @returns `{ available, total, views, covered, uncovered, missing, programs }`,
 *   listing at most 20 uncovered names and the program transports present.
 */
export function scanCoverage(tools, toolNames, scopes = [undefined]) {
  const names = toolNames ?? new Set()
  const notReady = { available: false, total: 0, views: 0, covered: [], uncovered: [], missing: [...names], programs: [] }
  if (typeof tools?.schemas !== 'function') return notReady
  const byName = new Map()
  let views = 0
  for (const scope of scopes) {
    const schemas = visibleSchemas(tools, scope)
    if (schemas.length > 0) views += 1
    for (const schema of schemas) {
      const name = typeof schema?.name === 'string' ? schema.name : ''
      if (name !== '' && !byName.has(name)) byName.set(name, schema)
    }
  }
  // An empty union means "the tool plugins have not registered yet", not "this
  // Host runs nothing": this plugin is applied before they are.
  if (byName.size === 0) return notReady
  const covered = []
  const uncovered = []
  for (const [name, schema] of byName) {
    if (names.has(name)) {
      covered.push(name)
      continue
    }
    const why = commandSurface(schema)
    if (why !== undefined) uncovered.push({ name, why })
  }
  // The views fill in progressively, so a read only counts as an answer once the
  // tools this gate claims to cover are visible in it. Before that it is a
  // partial view, and saying anything about coverage from it would be guessing.
  const missing = [...names].filter((name) => !byName.has(name))
  return {
    available: missing.length === 0,
    total: byName.size,
    views,
    covered,
    uncovered: uncovered.slice(0, 20),
    missing,
    // Named separately from `uncovered`: the transport itself is legible, but the
    // processes its programs can spawn are not — that is the fact worth naming,
    // and the name/field heuristic above is exactly what cannot see it.
    programs: byName.has(RUN_CODE_NAME) ? [RUN_CODE_NAME] : [],
  }
}
