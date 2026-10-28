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

/** Whether this agent's model reaches tools through `run_code` (PTC presentation). */
export function presentsPtc(ctx, agent) {
  const tools = ctx.get('tools')
  if (tools === undefined || typeof tools.get !== 'function') return false
  try {
    // The transport is visible only to scopes whose mode actually presents it.
    return tools.get(RUN_CODE_NAME, agent) !== undefined
  } catch {
    return false
  }
}
