/**
 * Program-budget accounting for the `run_code` (PTC) presentation.
 *
 * A `run_code` program's elapsed budget is fixed when its dispatch starts and
 * covers everything inside it, including an approval wait. This module remembers
 * when each program started so a nested sudo request can size its panel inside
 * the time that is actually left.
 * @module dsh-sudo-approve/lib/ptc
 */

import { MESSAGES } from './messages.js'

/**
 * Time a nested request leaves untouched at the end of its program budget, so
 * validation and the command itself still fit after the panel closes.
 */
export const PTC_RESERVE_MS = 10_000

/**
 * Shortest wait any request will open a panel for. Both the queue and the budget
 * guard respect it: below this there is no point showing anything.
 */
export const MIN_PANEL_MS = 5_000

/**
 * @param deps - the plugin context and the config accessor.
 */
export function createPtc(deps) {
  const { ctx, config } = deps

  /**
   * `run_code` token → the moment its dispatch started. A program's elapsed
   * budget is fixed at that point, so this is what lets a nested request size
   * its panel inside the time that is actually left.
   */
  const parents = new Map()

  /** The elapsed budget a `run_code` program runs with, when one is mounted. */
  function budgetMs() {
    try {
      const timeout = ctx.get('ptcRuntime')?.timeout
      return typeof timeout?.defaultMs === 'number' && timeout.defaultMs > 0 ? timeout.defaultMs : undefined
    } catch {
      return undefined
    }
  }

  /**
   * Size the wait of a nested (PTC) request inside what is left of its program.
   *
   * Waiting longer than the budget would kill the program while the user is
   * still typing, so the panel closes before that, and a request with too little
   * left is refused up front instead of opening a panel nobody can finish.
   * @param exec - the nested call.
   * @returns `{ waitMs, deadlineAt }`, or `{ deny }` when no panel would fit.
   */
  function nestedPlan(exec) {
    const budget = budgetMs()
    if (budget === undefined) return { waitMs: config().timeoutMs }
    const startedAt = parents.get(exec.parent)
    const deadlineAt = (startedAt === undefined ? Date.now() : startedAt) + budget - PTC_RESERVE_MS
    const left = deadlineAt - Date.now()
    if (left < MIN_PANEL_MS) return { deny: MESSAGES.budget(Math.round(budget / 1000)) }
    return { waitMs: Math.min(config().timeoutMs, Math.floor(left)), deadlineAt }
  }

  return {
    budgetMs,
    nestedPlan,
    /** Fix the moment a program's budget started. */
    startProgram: (token) => parents.set(token, Date.now()),
    /** Forget a program that finished or was cancelled. */
    endProgram: (token) => parents.delete(token),
    /** Whether this token is a program currently being timed. */
    isProgram: (token) => parents.has(token),
    /** Drop every program record on unload. */
    clear: () => parents.clear(),
  }
}
