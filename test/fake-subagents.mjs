/**
 * The DSH 0.2.2 `subagents` service, as the gate and the prompt use it.
 *
 * `rootOf(agent)` answers with the caller for a root and with another tree's
 * root for a child, which is exactly the distinction under test. It is a stub,
 * not a live tree: tests that need a refusal build their own object.
 * @param roots - the agent-shaped roots this tree knows.
 */
export function fakeSubagents(roots = [{ id: 'session-x' }]) {
  const ids = new Set(roots.map((root) => root.id))
  const first = roots[0]?.id
  return {
    rootOf: (agent) => {
      if (ids.has(agent.id)) return agent
      if (first === undefined) throw new Error('no live subagent root')
      return { id: first }
    },
  }
}
