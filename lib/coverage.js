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
 * @module dsh-sudo-approve/lib/coverage
 */

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

/**
 * Compare the tools this Host actually offers with the ones the gate covers.
 *
 * `available: false` means the registry could not be read (an older Host, or a
 * harness without the service): the answer is then "unknown", never "all
 * clear".
 * @param tools - the Host `tools` service, or undefined.
 * @param toolNames - the names the gate intercepts.
 * @returns `{ available, covered, uncovered }`, with at most 20 names listed.
 */
export function scanCoverage(tools, toolNames) {
  if (typeof tools?.schemas !== 'function') return { available: false, covered: [], uncovered: [] }
  let schemas
  try {
    schemas = tools.schemas()
  } catch {
    return { available: false, covered: [], uncovered: [] }
  }
  const covered = []
  const uncovered = []
  for (const schema of Array.isArray(schemas) ? schemas : []) {
    const name = typeof schema?.name === 'string' ? schema.name : ''
    if (name === '') continue
    if (toolNames?.has?.(name) === true) {
      covered.push(name)
      continue
    }
    const why = commandSurface(schema)
    if (why !== undefined) uncovered.push({ name, why })
  }
  return { available: true, covered, uncovered: uncovered.slice(0, 20) }
}
