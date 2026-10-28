/**
 * What the model is told about sudo in this deployment.
 *
 * Two presentations exist and they are never shipped together: a model that
 * receives both instructions ("just call bash" and "call bash through
 * run_code") will follow the wrong one half the time.
 * @module dsh-sudo-approve/lib/prompt
 */

import { isRootAgent, presentsPtc, sandboxModeOf } from './agents.js'

/**
 * @param deps - context, plugin name, config accessor and the PTC budget helper.
 */
export function installPrompt(deps) {
  const { ctx, name, config, ptc } = deps

  // The rules are the same whichever way the model reaches bash; only the
  // opening sentence (how to get to sudo at all) depends on the presentation.
  const SUDO_RULES = [
    'Write it plainly (`sudo <command>`) — the approved call authenticates by itself, so never pass a password, pipe one in, or add `-n`/`-S`/askpass flags; `sudo -n` always fails here.',
    'Keep the whole command short: the panel shows at most 60 lines and 400 characters per line, and a command that would not fit is refused outright instead of being approved blind — split it into several shorter commands. Do not move part of it into a script file and call that instead: a file the panel cannot show is a file the user never approved.',
    'One approval covers the whole command string, so keep sudo lines few and short. A rejection may quote the user\u2019s reason: do not retry the same command unchanged.',
    'Approvals are handled one at a time in arrival order: a parallel sudo call waits in line instead of failing, but each wait delays the command behind it, so keep sudo calls sequential and few. `sudo -k`, `-K`, `-V` and `-h` alone need no approval; sudo is unavailable in subagents and background jobs.',
  ].join(' ')

  /**
   * The runtime-context paragraph for a native presentation: sudo exists here,
   * the asking happens in the GUI, so the model should write plain sudo instead
   * of trying to authenticate by itself.
   */
  const SUDO_CONTEXT = [
    '`sudo` is available here: a foreground `bash` call that invokes `sudo` or `sudoedit` shows the user the command in the GUI and asks for their password before it runs.',
    SUDO_RULES,
  ].join(' ')

  /**
   * The paragraph for a PTC presentation, where reaching `bash` costs a nested
   * sub-dispatch and the approval wait is charged to the program budget.
   * @returns the paragraph for this deployment.
   */
  function ptcContext() {
    const budget = ptc.budgetMs()
    const span = budget === undefined ? 'fixed elapsed budget' : `${Math.round(budget / 1000)} second elapsed budget`
    return [
      '`sudo` is available here through `run_code`: a `tools.bash` call whose command invokes `sudo` or `sudoedit` shows the user the command in the GUI and asks for their password while the program waits.',
      `That wait, and the command itself, are charged to the program\u2019s ${span}, so put the sudo call near the start of a short program; a request whose program has too little time left is refused before any panel opens, or gives up while still waiting in line, and the answer is to rerun that sudo call in its own small program.`,
      SUDO_RULES,
    ].join(' ')
  }

  ctx.effect(() => {
    const scope = ctx.inject(['systemPrompt'], (child) => {
      const prompt = child.systemPrompt
      if (prompt === undefined || typeof prompt.context !== 'function') return
      const anchor = typeof prompt.getContextOrder === 'function' ? prompt.getContextOrder('APPROVAL_POLICY') : undefined
      prompt.context({
        name: `${name}:availability`,
        // Right after the approval-policy line it qualifies.
        order: Number.isFinite(anchor) ? anchor + 1 : 116,
        text: (context) => {
          const agent = context?.agent
          if (agent === undefined || !config().enabled) return ''
          // The gate only runs for the root agent in a full-access session.
          if (!isRootAgent(ctx, agent)) return ''
          const mode = sandboxModeOf(ctx, agent)
          if (mode !== undefined && mode !== 'danger-full-access') return ''
          // Both variants carry the shared rules; only the opening differs.
          return presentsPtc(ctx, agent) ? ptcContext() : SUDO_CONTEXT
        },
      })
    })
    return () => {
      scope?.dispose?.()
    }
  }, `${name}: context`)
}
