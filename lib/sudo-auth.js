/**
 * Talking to the real sudo: validating a password, reading the timestamp cache,
 * and releasing a secret to exactly one dispatch.
 * @module dsh-sudo-approve/lib/sudo-auth
 */

import { spawn } from 'node:child_process'
import { lockoutMarker } from './lockout.js'
import { MESSAGES } from './messages.js'
import { errorText } from './util.js'

/**
 * @param deps - the trusted sudo, the Host PATH, the approval scope, config
 *   accessor, the shim installer, the lockout probe and the audit sink.
 */
export function createSudoAuth(deps) {
  const { realSudo, basePath, scope, config, audit, shim, lockout } = deps

  /** The restricted environment `sudo` itself is invoked with. */
  function sudoEnv() {
    return {
      PATH: basePath,
      HOME: process.env.HOME ?? '',
      USER: process.env.USER ?? '',
      LOGNAME: process.env.LOGNAME ?? process.env.USER ?? '',
      SHELL: process.env.SHELL ?? '/bin/sh',
      TERM: 'dumb',
      LANG: 'C',
      LC_ALL: 'C',
    }
  }

  /**
   * Validate a password with one non-interactive `sudo -S -v` attempt.
   *
   * `-k` matters: `sudo -v` honours the timestamp cache, so within 15 minutes of
   * any earlier successful sudo it exits 0 without ever looking at the password.
   * Invalidating first forces a real PAM authentication, so a wrong password can
   * never be accepted just because a timestamp happened to be warm.
   *
   * The answer distinguishes a lockout from a wrong password. `pam_faillock`'s
   * `preauth` line rejects *before* the password is checked, so once the tally
   * reaches `deny` every password fails — including the correct one. Reporting
   * that as "wrong password" sends the operator into a retry loop that keeps the
   * lock alive, and each retry also counts against the tally. The tally is
   * therefore consulted before the attempt (a locked account is not asked at all,
   * so no further failure is recorded) and again after a failure, and sudo's own
   * stderr is read for PAM's lockout text.
   * @param secret - the candidate password.
   * @returns `{ ok: true }`, or `{ ok: false, reason }` where `reason` is
   *   `'locked'`, `'wrong-password'` or `'unknown'` (sudo could not be run).
   */
  async function authenticate(secret) {
    if (lockout !== undefined) {
      const before = await lockout.read()
      if (before.locked === true) {
        audit({ event: 'locked-out', stage: 'pre-check', source: before.source, detail: before.detail })
        return { ok: false, reason: 'locked', detail: before.detail }
      }
    }
    const attempt = await runValidation(secret)
    if (attempt.ok) return { ok: true }
    // PAM's own words are the most direct signal, but only when the `preauth`
    // line is not `silent`; the tally is the fallback that works either way.
    if (attempt.marker !== undefined) {
      audit({ event: 'locked-out', stage: 'stderr', marker: attempt.marker })
      return { ok: false, reason: 'locked', detail: attempt.marker }
    }
    if (lockout !== undefined) {
      const after = await lockout.read()
      if (after.locked === true) {
        audit({ event: 'locked-out', stage: 'post-check', source: after.source, detail: after.detail })
        return { ok: false, reason: 'locked', detail: after.detail }
      }
    }
    return { ok: false, reason: attempt.spawned ? 'wrong-password' : 'unknown' }
  }

  /**
   * One `sudo -k -S -v` attempt, with its stderr kept for the lockout marker.
   * @param secret - the candidate password.
   * @returns `{ ok, spawned, marker? }`.
   */
  function runValidation(secret) {
    return new Promise((resolve) => {
      let settled = false
      const finish = (value) => {
        if (settled) return
        settled = true
        clearTimeout(timer)
        resolve(value)
      }
      let child
      try {
        child = spawn(realSudo.path, ['-k', '-S', '-v'], {
          stdio: ['pipe', 'ignore', 'pipe'],
          env: sudoEnv(),
        })
      } catch {
        finish({ ok: false, spawned: false })
        return
      }
      const timer = setTimeout(() => {
        child.kill('SIGKILL')
        finish({ ok: false, spawned: true })
      }, 20_000)
      // Bounded: sudo's stderr is a few lines, and a runaway one must not grow
      // without limit. The password is never written to it.
      let err = ''
      child.stderr.on('data', (chunk) => {
        if (err.length < 8_000) err += chunk.toString('utf8')
      })
      child.on('error', () => finish({ ok: false, spawned: false }))
      child.on('close', (code) => {
        if (code === 0) {
          finish({ ok: true, spawned: true })
          return
        }
        const marker = lockoutMarker(err)
        finish({ ok: false, spawned: true, ...(marker === undefined ? {} : { marker }) })
      })
      child.stdin.on('error', () => {})
      child.stdin.end(`${secret}\n`)
    })
  }

  /** Run one non-interactive sudo probe; resolves with its exit status. */
  function probeSudo(args, timeoutMs) {
    return new Promise((resolve) => {
      let settled = false
      const finish = (value) => {
        if (settled) return
        settled = true
        clearTimeout(timer)
        resolve(value)
      }
      let child
      try {
        child = spawn(realSudo.path, args, { stdio: ['ignore', 'ignore', 'ignore'], env: sudoEnv() })
      } catch {
        finish(false)
        return
      }
      const timer = setTimeout(() => {
        child.kill('SIGKILL')
        finish(false)
      }, timeoutMs)
      child.on('error', () => finish(false))
      child.on('close', (code) => finish(code === 0))
    })
  }

  /**
   * Whether the credential cache a validated password leaves behind can be
   * reused by the command itself.
   *
   * It cannot on a default `timestamp_type=tty` setup: the validation runs with
   * no controlling terminal, so the record is filed under a key the command's
   * own (equally tty-less) sudo does not look up. A false answer is normal and
   * is what sends `auto` to the askpass shim; a true answer means no shim and no
   * password file are needed at all.
   * @returns whether `sudo -n` already works without a password.
   */
  function timestampUsable() {
    return probeSudo(['-n', '-v'], 5_000)
  }

  /** Drop the invoking user's cached sudo credential; best effort. */
  function clearTimestamp() {
    return probeSudo(['-k'], 5_000)
  }

  /**
   * Hand one validated secret to exactly one dispatch.
   *
   * Two deliveries are possible. When the sudo credential cache is reusable the
   * command needs no help at all: it runs untouched and the cache is dropped
   * afterwards. Otherwise a shim is built for this dispatch and injected through
   * the spec of its spawn only, so no other process can inherit the password.
   *
   * Both paths drop the timestamp cache when they are done. That record is not a
   * detail of the delivery method: it is what lets a later `sudo` skip the
   * password entirely, so an approval must never leave one behind.
   * @param exec - the tool call being dispatched.
   * @param secret - the validated password.
   * @param next - the rest of the middleware chain.
   */
  async function dispatchWithSecret(exec, secret, next) {
    if (config().credential !== 'askpass' && (await timestampUsable())) {
      audit({ event: 'execute', callId: exec.callId, credential: 'timestamp' })
      try {
        return await next()
      } finally {
        await clearTimestamp()
        audit({ event: 'finished', callId: exec.callId })
      }
    }
    if (config().credential === 'timestamp') {
      audit({ event: 'denied', reason: 'credential-unavailable', callId: exec.callId })
      throw new Error(MESSAGES.credential)
    }
    let run
    try {
      run = await shim.materialize(secret)
    } catch (error) {
      audit({ event: 'shim-error', callId: exec.callId, message: errorText(error) })
      return next()
    }
    audit({ event: 'execute', callId: exec.callId, credential: 'askpass', scoped: shim.isScoped() })
    try {
      return await scope.run(run, () => next())
    } finally {
      await shim.dematerialize(run)
      // The approved command's own `sudo -A` authenticates, and a successful
      // authentication writes a timestamp record. Drop it on this path too: the
      // record is what would turn one approval into a password-free window for
      // anything that can reuse its key, whatever `credential` was configured.
      await clearTimestamp()
      audit({ event: 'finished', callId: exec.callId })
    }
  }

  return { sudoEnv, authenticate, probeSudo, timestampUsable, clearTimestamp, dispatchWithSecret }
}
