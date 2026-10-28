/**
 * The panel, the queue behind it, and the decision for one call.
 *
 * One request is on screen at a time; a second waits in line instead of failing,
 * because refusing it outright looked like a random error. Everything here is
 * also where the security-relevant refusals happen: no page, no gesture, wrong
 * session, remote deployment, a command the panel cannot show in full.
 * @module dsh-sudo-approve/lib/gate
 */

import { randomUUID } from 'node:crypto'
import { analyzeCommand, digestOf, MAX_DISPLAY_LINES, MAX_DISPLAY_WIDTH } from './analysis.js'
import { isRootAgent, sandboxModeOf } from './agents.js'
import { MESSAGES } from './messages.js'
import { MIN_PANEL_MS } from './ptc.js'
import { isPlainObject } from './util.js'

/**
 * How many requests may wait behind the one on screen. The page shows a single
 * panel, so extra requests queue: refusing them outright made a parallel sudo
 * call fail for no reason the user could see.
 */
const QUEUE_LIMIT = 4

/**
 * @param deps - context, config accessor, audit sink, remembered secrets and the
 *   PTC budget helper.
 */
export function createGate(deps) {
  const { ctx, config, audit, remembered, ptc } = deps

  /** The one request currently waiting for the page, if any. */
  let inflight
  /** Requests waiting for their turn, oldest first; `inflight` is not in here. */
  const queue = []
  /** `${sessionId}:${callId}` → validated secret for one dispatch. */
  const armed = new Map()
  /** Timestamp of the last page poll; 0 means no page has ever polled. */
  let lastPollAt = 0
  /** Timestamp of the last poll from a *visible* page. */
  let lastVisibleAt = 0
  /** Timestamp of the last real user gesture reported by the page. */
  let lastInteractionAt = 0

  /** Whether a visible page has polled recently enough to show a panel. */
  function pagePresent() {
    const now = Date.now()
    const window = config().presenceWindowMs
    if (lastPollAt === 0 || now - lastPollAt > window) return false
    // A hidden tab keeps polling exactly like a visible one, so the page has to
    // report that it is on screen before it can be treated as somebody watching.
    return lastVisibleAt !== 0 && now - lastVisibleAt <= window
  }

  /** Whether the page reported a real user gesture (click, key, focus) lately. */
  function interactionPresent() {
    return lastInteractionAt !== 0 && Date.now() - lastInteractionAt <= config().presenceWindowMs
  }

  /**
   * Record how the page presented itself on this request.
   *
   * `state=visible` and `interaction=1` are claims made by the page, so they are
   * a speed bump rather than a proof: they stop a hidden tab from counting as
   * somebody watching, and they let a gesture be reported before the approval
   * that leans on it. A script that holds a session cookie can assert both; that
   * is why the security-relevant switches are file-only.
   */
  function notePresence(request) {
    const now = Date.now()
    lastPollAt = now
    let url
    try {
      url = new URL(request.url)
    } catch {
      return
    }
    if (url.searchParams.get('state') === 'visible') lastVisibleAt = now
    if (url.searchParams.get('interaction') === '1') lastInteractionAt = now
  }

  /**
   * Approval key for one dispatch. A provider's `callId` is only unique within
   * its own conversation, so the session has to be part of the key: otherwise a
   * collision in another session would inherit this approval.
   */
  function armKey(exec) {
    return `${exec.agent === undefined ? '?' : exec.agent.id}:${exec.callId}`
  }

  /** Remember the secret the page approved, bound to one command digest. */
  function arm(exec, secret, digest) {
    armed.set(armKey(exec), {
      secret,
      at: Date.now(),
      sessionId: exec.agent.id,
      // The secret is released only to a dispatch whose command still hashes to
      // what the user was shown.
      digest,
    })
  }

  /**
   * Take the secret armed for this dispatch, if any.
   *
   * The secret may only be released to the exact command the user saw. When the
   * command cannot even be read back, that cannot be shown, so it is refused
   * rather than dispatched on the strength of the call id alone.
   * @param exec - the call about to be dispatched.
   * @returns the armed entry, or undefined when nothing was approved for it.
   */
  function takeArmed(exec) {
    const key = armKey(exec)
    const entry = armed.get(key)
    if (entry === undefined) return undefined
    armed.delete(key)
    const command = isPlainObject(exec.arguments) && typeof exec.arguments.command === 'string' ? exec.arguments.command : undefined
    if (command === undefined) {
      audit({ event: 'armed-mismatch', callId: exec.callId, sessionId: entry.sessionId, reason: 'no-command' })
      throw new Error(MESSAGES.mismatch)
    }
    if (digestOf(command) !== entry.digest) {
      audit({ event: 'armed-mismatch', callId: exec.callId, sessionId: entry.sessionId })
      throw new Error(MESSAGES.mismatch)
    }
    return entry
  }

  /** Put one request on screen: fix its deadline, log it, start its timer. */
  function admit(request) {
    request.state = 'visible'
    request.startedAt = Date.now()
    if (request.deadlineAt !== undefined) {
      // It may have queued for a while, so re-measure instead of trusting the
      // wait computed when it arrived.
      request.waitMs = Math.max(MIN_PANEL_MS, Math.min(request.waitMs, Math.floor(request.deadlineAt - request.startedAt)))
    }
    request.expiresAt = request.startedAt + request.waitMs
    inflight = request
    audit({
      event: 'request',
      id: request.id,
      sessionId: request.sessionId,
      callId: request.callId,
      lines: request.items.length,
      waitMs: request.waitMs,
      ...(request.nested ? { channel: 'ptc' } : {}),
      ...(request.position > 1 ? { position: request.position } : {}),
      cwd: request.cwd,
    })
    request.start?.()
  }

  /**
   * Show the next queued request, skipping any that can no longer be answered:
   * the page has gone away, or a nested request's program budget no longer has
   * room for a panel at all. Skipping rather than opening a doomed panel keeps
   * the queue moving.
   */
  function pump() {
    if (inflight !== undefined) return
    while (queue.length > 0) {
      const next = queue[0]
      if (!pagePresent()) {
        queue.shift()
        next.settle?.({ kind: 'noClient' })
        continue
      }
      if (next.deadlineAt !== undefined && next.deadlineAt - Date.now() < MIN_PANEL_MS) {
        queue.shift()
        next.settle?.({ kind: 'budget' })
        continue
      }
      queue.shift()
      admit(next)
      return
    }
  }

  /**
   * Ask the page and resolve the whole gate for one sudo command.
   * @param exec - the tool call being gated.
   * @param analysis - the command analysis (lines to show).
   * @param plan - `{ waitMs, deadlineAt? }` from the PTC planner.
   */
  async function askForApproval(exec, analysis, plan) {
    let session
    let cwd
    try {
      session = exec.agent.session
      cwd = typeof session?.cwd === 'string' ? session.cwd : undefined
    } catch {
      cwd = undefined
    }
    const request = {
      id: randomUUID(),
      callId: exec.callId,
      sessionId: exec.agent.id,
      createdAt: Date.now(),
      cwd,
      items: analysis.items,
      nested: exec.parent !== undefined,
      waitMs: plan.waitMs,
      deadlineAt: plan.deadlineAt,
      expiresAt: undefined,
      state: 'queued',
      position: 1,
      settle: undefined,
      start: undefined,
      resolving: false,
    }
    const decided = new Promise((resolve) => {
      let finished = false
      let panelTimer
      let deadlineTimer
      const finish = (value) => {
        if (finished) return
        finished = true
        clearTimeout(panelTimer)
        clearTimeout(deadlineTimer)
        exec.signal?.removeEventListener('abort', onAbort)
        resolve(value)
      }
      const onAbort = () => finish({ kind: 'cancelled' })
      request.settle = finish
      request.start = () => {
        // On screen now: the panel's own wait (already clamped to the budget)
        // owns the deadline, so the queue guard must not fire first.
        clearTimeout(deadlineTimer)
        deadlineTimer = undefined
        panelTimer = setTimeout(() => finish({ kind: 'timeout' }), request.waitMs)
      }
      // A nested request that runs out of program budget while still queued must
      // give up here: by the time it reached the screen nothing could be typed.
      if (request.deadlineAt !== undefined) {
        const leave = Math.max(0, request.deadlineAt - MIN_PANEL_MS - Date.now())
        deadlineTimer = setTimeout(() => finish({ kind: 'budget' }), leave)
      }
      if (exec.signal?.aborted === true) {
        finish({ kind: 'cancelled' })
        return
      }
      exec.signal?.addEventListener('abort', onAbort, { once: true })
    }).finally(() => {
      const index = queue.indexOf(request)
      if (index >= 0) queue.splice(index, 1)
      if (inflight === request) inflight = undefined
      pump()
    })
    queue.push(request)
    pump()
    if (request.state === 'queued') {
      request.position = queue.indexOf(request) + 1
      audit({
        event: 'queued',
        id: request.id,
        sessionId: request.sessionId,
        callId: request.callId,
        lines: request.items.length,
        position: request.position,
      })
    }
    return { request, decision: await decided }
  }

  /** Decide one sudo-bearing bash call. */
  async function decide(exec, analysis) {
    if (exec.agent === undefined) return { kind: 'deny', reason: MESSAGES.noAgent }
    if (isPlainObject(exec.arguments) && exec.arguments.run_in_background === true) {
      return { kind: 'deny', reason: MESSAGES.background }
    }
    if (!isRootAgent(ctx, exec.agent)) return { kind: 'deny', reason: MESSAGES.subagent }
    const mode = sandboxModeOf(ctx, exec.agent)
    if (mode !== undefined && mode !== 'danger-full-access') {
      audit({ event: 'denied', reason: 'sandbox', mode, sessionId: exec.agent.id })
      return { kind: 'deny', reason: MESSAGES.sandbox(mode) }
    }
    if (!config().allowRemoteDeployment) {
      const connection = ctx.get('connection')
      if (connection?.allowsRemoteAuthorities === true) {
        audit({ event: 'denied', reason: 'remote-deployment', sessionId: exec.agent.id })
        return { kind: 'deny', reason: MESSAGES.remote }
      }
    }
    // The panel is one at a time, so parallel calls line up behind it. Only a
    // queue that is already full is refused, and it says so.
    if (queue.length >= QUEUE_LIMIT) {
      audit({ event: 'denied', reason: 'queue-full', sessionId: exec.agent.id, callId: exec.callId })
      return { kind: 'deny', reason: MESSAGES.queueFull(QUEUE_LIMIT) }
    }
    if (!pagePresent()) {
      audit({ event: 'denied', reason: 'no-client', sessionId: exec.agent.id })
      return { kind: 'deny', reason: MESSAGES.noClient }
    }
    // A PTC sub-dispatch is how that presentation reaches any tool, so it is a
    // normal path rather than a nested bypass: the password is still required.
    // What differs is the wait, which has to fit inside the program's budget.
    let plan = { waitMs: config().timeoutMs }
    if (exec.parent !== undefined) {
      plan = ptc.nestedPlan(exec)
      if (plan.deny !== undefined) {
        audit({ event: 'denied', reason: 'ptc-budget', sessionId: exec.agent.id, callId: exec.callId })
        return { kind: 'deny', reason: plan.deny }
      }
    }

    const { request, decision } = await askForApproval(exec, analysis, plan)
    if (decision.kind === 'approved' && typeof decision.secret === 'string' && decision.secret !== '') {
      // The secret is released only to a dispatch whose command still hashes to
      // what the user was shown.
      arm(exec, decision.secret, digestOf(typeof exec.arguments.command === 'string' ? exec.arguments.command : ''))
      audit({
        event: 'approved',
        id: request.id,
        sessionId: request.sessionId,
        callId: request.callId,
        digest: analysis.digest,
        // A remembered secret was reused: no password was typed for this one.
        ...(decision.memo === true ? { memo: true } : {}),
      })
      return undefined
    }
    if (decision.kind === 'rejected') {
      audit({ event: 'rejected', id: request.id, sessionId: request.sessionId, reason: decision.reason })
      return { kind: 'deny', reason: MESSAGES.rejected(decision.reason) }
    }
    if (decision.kind === 'cancelled') {
      audit({ event: 'cancelled', id: request.id, sessionId: request.sessionId })
      return { kind: 'cancel' }
    }
    if (decision.kind === 'budget') {
      audit({ event: 'denied', reason: 'ptc-budget', id: request.id, sessionId: request.sessionId, callId: request.callId, queued: true })
      return { kind: 'deny', reason: MESSAGES.budgetQueued(Math.round((ptc.budgetMs() ?? config().timeoutMs) / 1000)) }
    }
    if (decision.kind === 'noClient') {
      audit({ event: 'denied', reason: 'no-client', id: request.id, sessionId: request.sessionId, queued: true })
      return { kind: 'deny', reason: MESSAGES.noClient }
    }
    audit({ event: 'timeout', id: request.id, sessionId: request.sessionId })
    return { kind: 'deny', reason: MESSAGES.timeout(Math.round(request.waitMs / 1000)) }
  }

  /** Gate one tool call; returns a decision or undefined to dispatch. */
  async function check(exec) {
    if (!config().enabled) return undefined
    if (typeof exec.name !== 'string' || !config().toolNames.has(exec.name)) return undefined
    const args = exec.arguments
    if (!isPlainObject(args) || typeof args.command !== 'string' || args.command === '') return undefined
    const analysis = analyzeCommand(args.command)
    // A sudo call can sit past the display cap, where the per-line scan cannot
    // see it, so the folded whole string is scanned before this command is
    // written off as needing no gate at all.
    if (!analysis.hasSudo && !analysis.mentionsSudo) return undefined
    // An approval covers the whole command string, so a command the panel could
    // not show in full is refused rather than approved blind.
    if (analysis.truncated) {
      audit({ event: 'denied', reason: 'truncated', sessionId: exec.agent?.id, callId: exec.callId, digest: analysis.digest })
      return { kind: 'deny', reason: MESSAGES.truncated(MAX_DISPLAY_LINES, MAX_DISPLAY_WIDTH) }
    }
    // The token only appeared in comments or in a form that never authenticates.
    if (!analysis.hasSudo) return undefined
    return decide(exec, analysis)
  }

  /**
   * Value the page polls for: the one request on screen plus how many are
   * waiting behind it, so the panel can say that a parallel call is in line.
   */
  function snapshot() {
    const waiting = queue.length
    if (inflight === undefined) return { requests: [], waiting }
    const { id, sessionId, createdAt, expiresAt, cwd, items } = inflight
    const memo = config().remember === 'session' ? remembered.get(sessionId) : undefined
    return { requests: [{ id, sessionId, createdAt, expiresAt, cwd, items, passwordRequired: memo === undefined }], waiting }
  }

  /** Drop arming records nobody claimed; called on a timer. */
  function pruneArmed(now) {
    for (const [key, entry] of armed) {
      if (now - entry.at > 60_000) armed.delete(key)
    }
  }

  /** Settle every waiter so an unloaded plugin cannot leave models hanging. */
  function settleAll() {
    for (const request of queue.splice(0, queue.length)) request.settle?.({ kind: 'cancelled' })
    inflight?.settle?.({ kind: 'cancelled' })
    inflight = undefined
  }

  return {
    check,
    snapshot,
    /** The request currently on screen, for the answer route. */
    current: () => inflight,
    notePresence,
    interactionPresent,
    pagePresent,
    arm,
    takeArmed,
    pruneArmed,
    settleAll,
    /** Forget every armed secret on unload. */
    disarmAll: () => armed.clear(),
  }
}
