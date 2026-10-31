/**
 * The three Fetch routes the page talks to.
 *
 * All three sit behind the Harness Host/Origin fence and a signed cookie. None
 * of them can change a switch that decides what the gate does: the settings
 * route accepts the two timing knobs and nothing else, and a reset keeps every
 * file-only value in place.
 *
 * A Host that never got as far as a gate answers exactly one read-only route
 * ({@link installInactiveRoute}): the same `/config` path, carrying why it is
 * not working. It is registered instead of the three above, never alongside
 * them, so an inactive Host cannot answer an approval through any route.
 * @module dsh-sudo-approve/lib/routes
 */

import { sanitizeRuntimePatch } from './config.js'
import { MESSAGES } from './messages.js'
import { errorText, normalizeReason } from './util.js'

/** Exact Fetch routes the browser half calls. */
const ROUTE_PREFIX = '/api/sudo-approve'

/**
 * @param deps - context, config accessor, audit sink, settings store, the gate
 *   (panel + presence), remembered secrets and the password validator.
 */
export function installRoutes(deps) {
  const { ctx, name, config, audit, settings, gate, remembered, validatePassword, surfaceOf, coverageOf } = deps

  /**
   * The settings payload, plus which approval surface is actually in use and
   * which tools the gate does *not* cover. The coverage answer is read-only: it
   * exists so the page can say "this Host has a command-running tool that is not
   * gated" instead of implying a completeness the allowlist never had.
   */
  const settingsValue = () => ({
    ...settings.snapshot(),
    dialog: surfaceOf(),
    coverage: typeof coverageOf === 'function' ? coverageOf() : undefined,
  })

  const respondJson = (payload, status = 200) =>
    Response.json(payload, { status, headers: { 'cache-control': 'no-store' } })

  /**
   * Answer the page's approve/reject click.
   * @param body - the JSON body.
   * @param gestured - whether a gesture was reported *before* this request was
   *   seen. It is read by the route before `notePresence` records the current
   *   request, because an approval that supplied its own evidence would be
   *   judged against a fact it had just written.
   */
  async function respond(body, gestured) {
    const id = typeof body?.id === 'string' ? body.id : undefined
    const decision = body?.decision === 'approve' || body?.decision === 'reject' ? body.decision : undefined
    if (id === undefined || decision === undefined) {
      return respondJson({ ok: false, error: { code: 'sudo-approve/bad-request', message: 'id and decision are required' } }, 400)
    }
    const request = current()
    if (request === undefined || request.id !== id) {
      return respondJson({ ok: false, error: { code: 'sudo-approve/stale', message: 'this request is no longer pending' } }, 409)
    }
    if (request.resolving) {
      return respondJson({ ok: false, error: { code: 'sudo-approve/busy', message: 'this request is being resolved' } }, 409)
    }
    // In native mode the page is not an approval surface at all: the button on
    // the host's screen is. Any POST here is refused, so no script holding a
    // session cookie can stand in for the person at the display.
    if (request.dialog === 'native') {
      audit({ event: 'denied', reason: 'native-surface', id: request.id, sessionId: request.sessionId })
      return respondJson(
        { ok: false, error: { code: 'sudo-approve/native-dialog', message: 'this approval is answered in the system dialog' } },
        409,
      )
    }
    if (decision === 'reject') {
      request.settle?.({ kind: 'rejected', reason: normalizeReason(body?.reason) })
      return respondJson({ ok: true, value: { state: 'rejected' } })
    }
    // An approval leans on a gesture reported before it, never on its own claim.
    if (body?.interaction !== true || gestured !== true) {
      audit({ event: 'denied', reason: 'no-interaction', id: request.id, sessionId: request.sessionId })
      return respondJson(
        { ok: false, error: { code: 'sudo-approve/no-interaction', message: 'approval requires a user gesture reported before it' } },
        403,
      )
    }
    request.resolving = true
    try {
      let secret = typeof body?.password === 'string' && body.password !== '' ? body.password : undefined
      let memo = false
      if (secret === undefined && config().remember === 'session') {
        const stored = remembered.get(request.sessionId)
        if (stored !== undefined) {
          secret = stored.secret
          memo = true
        }
      }
      if (secret === undefined) {
        return respondJson({ ok: false, error: { code: 'sudo-approve/password-required', message: 'password is required' } }, 400)
      }
      if (!(await validatePassword(secret))) {
        audit({ event: 'invalid-password', id: request.id, sessionId: request.sessionId })
        return respondJson({ ok: false, error: { code: 'sudo-approve/invalid-password', message: MESSAGES.invalidPassword } }, 403)
      }
      if (config().remember === 'session') remembered.set(request.sessionId, { secret, usedAt: Date.now() })
      request.settle?.({ kind: 'approved', secret, memo })
      return respondJson({ ok: true, value: { state: 'approved' } })
    } finally {
      request.resolving = false
    }
  }

  /**
   * The request currently on screen.
   *
   * `respond` and the `armed` handoff both need it, and going through the gate
   * keeps the panel state in one place instead of copying a reference around.
   */
  function current() {
    return gate.current()
  }

  ctx.effect(() => {
    const scope = ctx.inject(['connection'], (child) => {
      const connection = child.get('connection')
      if (connection === undefined) return
      connection.fetch.register({
        path: `${ROUTE_PREFIX}/pending`,
        methods: ['GET'],
        requestBody: 'buffered',
        fetch: async (request) => {
          gate.notePresence(request)
          return respondJson({ ok: true, value: gate.snapshot() })
        },
      })
      connection.fetch.register({
        path: `${ROUTE_PREFIX}/respond`,
        methods: ['POST'],
        requestBody: 'buffered',
        fetch: async (request) => {
          // Read the gesture *before* this request records its own claim: an
          // approval must rest on evidence that existed when it arrived.
          const gestured = gate.interactionPresent()
          gate.notePresence(request)
          let body
          try {
            body = await request.json()
          } catch {
            return respondJson({ ok: false, error: { code: 'sudo-approve/bad-request', message: 'body is not JSON' } }, 400)
          }
          return respond(body, gestured)
        },
      })
      connection.fetch.register({
        path: `${ROUTE_PREFIX}/config`,
        methods: ['GET', 'POST'],
        requestBody: 'buffered',
        fetch: async (request) => {
          // Deliberately does not refresh the presence window: a settings page
          // is not an approval surface.
          if (request.method !== 'POST') return respondJson({ ok: true, value: settingsValue() })
          let body
          try {
            body = await request.json()
          } catch {
            return respondJson({ ok: false, error: { code: 'sudo-approve/bad-request', message: 'body is not JSON' } }, 400)
          }
          if (body?.reset === true) {
            const kept = settings.reset()
            audit({ event: 'configured', reset: true, ...(kept.length === 0 ? {} : { kept }) })
            return respondJson({ ok: true, value: settingsValue() })
          }
          // Only the two timing knobs are page-editable; everything that
          // decides what the gate does is file-only by design.
          const patch = sanitizeRuntimePatch(body?.patch)
          if (Object.keys(patch).length === 0) {
            return respondJson({ ok: false, error: { code: 'sudo-approve/bad-request', message: 'no editable setting' } }, 400)
          }
          try {
            settings.save(patch)
          } catch (error) {
            return respondJson({ ok: false, error: { code: 'sudo-approve/store-failed', message: errorText(error) } }, 500)
          }
          audit({ event: 'configured', ...patch })
          return respondJson({ ok: true, value: settingsValue() })
        },
      })
    })
    return () => {
      scope?.dispose?.()
    }
  }, `${name}: routes`)
}

/**
 * The one route a Host answers when it has no trusted sudo.
 *
 * Silence was the defect: the page could not tell "this Host is not gating
 * anything" from "the settings request failed", so it drew a normal form with
 * "启用拦截 ✓" over a gate that did not exist. This route says so on the path the
 * page already reads, read-only and GET-only — an inactive Host must not accept
 * a settings change, a pending query, or an approval from anyone.
 *
 * @param deps - context, plugin name, and a payload accessor returning
 *   `{ build, active: false, reason, sudo, store, auditLog }`.
 */
export function installInactiveRoute({ ctx, name, value }) {
  ctx.effect(() => {
    const scope = ctx.inject(['connection'], (child) => {
      const connection = child.get('connection')
      if (connection === undefined) return
      connection.fetch.register({
        path: `${ROUTE_PREFIX}/config`,
        methods: ['GET'],
        requestBody: 'buffered',
        fetch: async () =>
          Response.json({ ok: true, value: value() }, { status: 200, headers: { 'cache-control': 'no-store' } }),
      })
    })
    return () => {
      scope?.dispose?.()
    }
  }, `${name}: inactive status`)
}
