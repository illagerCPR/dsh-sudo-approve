/**
 * What an agent is allowed to do here, and how its model reaches tools.
 *
 * Both the gate and the runtime-context paragraph ask these questions, so they
 * live in one place: the paragraph must never promise sudo to an agent the gate
 * would refuse, and the gate must never refuse one the paragraph invited.
 * @module dsh-sudo-approve/lib/agents
 */

/** The PTC presentation transport; a sub-dispatch carries its token as `parent`. */
export const RUN_CODE_NAME = 'run_code'

/** Whether this agent is a top-level agent (not a subagent or teammate). */
export function isRootAgent(ctx, agent) {
  const agents = ctx.get('agents')
  if (agents === undefined || typeof agents.roots !== 'function') return false
  try {
    return agents.roots().some((root) => root.id === agent.id)
  } catch {
    return false
  }
}

/** The sandbox mode this call would run under, when the deployment confines. */
export function sandboxModeOf(ctx, agent) {
  const policy = ctx.get('sandboxPolicy')
  if (policy === undefined || typeof policy.resolve !== 'function') return undefined
  try {
    const session = agent.session
    return policy.resolve(session === undefined ? {} : { session }).mode
  } catch {
    return undefined
  }
}

/**
 * The program transports this agent's selected executor presents.
 *
 * DSH 0.2.2 moved `run_code` out of the tool registry: it is now a reserved
 * transport owned by the PTC executor, deliberately excluded from
 * `tools.get()` and `tools.schemas()`. The executor's `describe()` is the only
 * place that still names it, so both the prompt variant and the coverage report
 * have to ask there. `tools.get()` stays as the first check for older hosts.
 *
 * `describe([])` is enough because only the transport list is being read, not
 * the SDK schemas rendered from the visible tool definitions.
 * @param ctx - the plugin context.
 * @param agent - the Agent whose executor selection is asked; undefined is the
 *   global selection.
 * @returns the program transport names, oldest host shape first.
 */
export function programTransportsOf(ctx, agent) {
  const found = new Set()
  const tools = ctx.get('tools')
  if (tools === undefined) return []

  try {
    if (typeof tools.get === 'function' && tools.get(RUN_CODE_NAME, agent) !== undefined) {
      found.add(RUN_CODE_NAME)
    }
  } catch {
    // A registry that cannot answer is not a program channel.
  }

  try {
    if (typeof tools.selectExecutor !== 'function') return [...found]
    const executor = tools.selectExecutor(agent)
    if (typeof executor?.describe !== 'function') return [...found]
    const description = executor.describe([])
    for (const schema of Array.isArray(description?.schemas) ? description.schemas : []) {
      if (schema?.name === RUN_CODE_NAME) found.add(RUN_CODE_NAME)
    }
  } catch {
    // The executor is optional and may be unavailable mid-hot-reload.
  }

  return [...found]
}

/** Whether this agent's model reaches tools through `run_code` (PTC presentation). */
export function presentsPtc(ctx, agent) {
  return programTransportsOf(ctx, agent).includes(RUN_CODE_NAME)
}
