/**
 * Telling "the account is locked" apart from "the password is wrong".
 *
 * `pam_faillock`'s `preauth` line rejects an authentication *before* the password
 * is checked, so once the tally reaches `deny` every password fails — including
 * the correct one. sudo reports that as an ordinary authentication failure, and a
 * surface that reads it as "wrong password" sends the operator into a retry loop
 * that keeps the lock alive.
 *
 * Two signals are available to a non-root process, and neither is guaranteed:
 *
 *  - sudo's own stderr, which carries PAM's conversation text when the `preauth`
 *    line is not `silent`;
 *  - `faillock --user`, which can read the tally only where the tally directory
 *    is traversable by its owner.
 *
 * Both are best effort. "Unknown" is reported as unknown, never as "wrong
 * password": the caller words its message so that a lockout stays possible.
 * @module dsh-sudo-approve/lib/lockout
 */

import { spawn } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { userInfo } from 'node:os'

import { resolveTrusted } from './trusted.js'

/** Where a `faillock` binary may live; resolved on fixed paths, never `PATH`. */
export const FAILLOCK_CANDIDATES = Object.freeze([
  '/usr/sbin/faillock',
  '/sbin/faillock',
  '/usr/bin/faillock',
  '/bin/faillock',
])

/** `pam_faillock`'s own default when `faillock.conf` says nothing. */
export const DEFAULT_DENY = 3

/** Where `pam_faillock` reads its defaults from. */
export const FAILLOCK_CONF = '/etc/security/faillock.conf'

/**
 * Text sudo or PAM prints when the failure is a lockout, not a wrong password.
 *
 * Deliberately narrow: a marker that also matched an ordinary failure would turn
 * every typo into "your account is locked".
 */
const LOCKOUT_MARKERS = Object.freeze([
  /account is locked/i,
  /account validation failure/i,
  /temporarily locked/i,
  /locked out/i,
  /too many (?:failed|incorrect) (?:login )?attempts/i,
])

/** The invoking user's name, for the tally lookup. */
function currentUser() {
  try {
    return userInfo().username
  } catch {
    return process.env.USER ?? process.env.LOGNAME ?? ''
  }
}

/**
 * The lockout marker in a piece of sudo output, if any.
 * @param text - sudo's stderr.
 * @returns the matched text, or undefined.
 */
export function lockoutMarker(text) {
  if (typeof text !== 'string' || text === '') return undefined
  for (const marker of LOCKOUT_MARKERS) {
    const match = marker.exec(text)
    if (match !== null) return match[0]
  }
  return undefined
}

/**
 * `deny` from `faillock.conf`, or the module default.
 *
 * Only the `deny = N` line matters here; every other setting is irrelevant to
 * "is this account locked right now". A PAM line that overrides `deny` is not
 * read: following `include` directives is a rabbit hole, and a wrong limit only
 * shifts the threshold, never the direction of the answer.
 * @param text - the file's contents, or undefined when it could not be read.
 * @returns the configured limit, or {@link DEFAULT_DENY}.
 */
export function denyFrom(text) {
  if (typeof text !== 'string') return DEFAULT_DENY
  for (const line of text.split(/\r?\n/)) {
    const match = /^\s*deny\s*=\s*(\d+)\s*$/.exec(line)
    if (match === null) continue
    const value = Number.parseInt(match[1], 10)
    if (Number.isSafeInteger(value) && value > 0) return value
  }
  return DEFAULT_DENY
}

/**
 * Count the still-valid failures in `faillock --user` output.
 *
 * The table is `When Type Source Valid`, one row per recorded failure, and the
 * last column is `V` while the record still counts and `I` once it has aged out.
 * Anything that does not parse is reported as unknown rather than as zero: a
 * format this code does not recognise must not read as "not locked".
 * @param text - `faillock --user` stdout.
 * @returns the number of valid rows, or undefined when the table is not there.
 */
export function validFailures(text) {
  if (typeof text !== 'string') return undefined
  const lines = text.split(/\r?\n/)
  const header = lines.findIndex((line) => /^\s*When\s+Type\s+Source\s+Valid\s*$/.test(line))
  if (header < 0) return undefined
  let count = 0
  for (const line of lines.slice(header + 1)) {
    if (line.trim() === '') continue
    if (/\sV\s*$/.test(line)) count += 1
  }
  return count
}

/**
 * Read the account's lockout state from `pam_faillock`'s tally.
 * @param deps - the user to look up and the config file to read; both default to
 *   this machine.
 * @returns `{ read }`, where `read()` resolves with `{ locked, source, detail }`
 *   and `locked` is undefined when the tally could not answer.
 */
export function createLockoutProbe(deps = {}) {
  const { user = currentUser(), denyFile = FAILLOCK_CONF } = deps
  /** Resolved once: the binary does not move while the Host runs. */
  let resolved
  let deny

  function binary() {
    if (resolved === undefined) resolved = resolveTrusted('', FAILLOCK_CANDIDATES) ?? null
    return resolved ?? undefined
  }

  function denyLimit() {
    if (deny === undefined) {
      let text
      try {
        text = readFileSync(denyFile, 'utf8')
      } catch {
        text = undefined
      }
      deny = denyFrom(text)
    }
    return deny
  }

  /** Run `faillock --user`; resolves with its stdout, or undefined. */
  function readTally(target) {
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
        child = spawn(target.path, ['--user', user], {
          stdio: ['ignore', 'pipe', 'ignore'],
          env: {
            PATH: '/usr/sbin:/usr/bin:/sbin:/bin',
            HOME: process.env.HOME ?? '',
            LANG: 'C',
            LC_ALL: 'C',
          },
        })
      } catch {
        finish(undefined)
        return
      }
      const timer = setTimeout(() => {
        child.kill('SIGKILL')
        finish(undefined)
      }, 2_000)
      let out = ''
      child.stdout.on('data', (chunk) => {
        if (out.length < 64_000) out += chunk.toString('utf8')
      })
      child.on('error', () => finish(undefined))
      child.on('close', (code) => finish(code === 0 ? out : undefined))
    })
  }

  /**
   * Whether the account looks locked right now.
   * @returns `{ locked, source, detail }`. `source` is `'faillock'` when the
   *   tally answered and `'unknown'` when it could not; `locked` is undefined in
   *   the second case, so a caller never mistakes silence for "not locked".
   */
  async function read() {
    if (user === '') return { locked: undefined, source: 'unknown', detail: 'no-user' }
    const target = binary()
    if (target === undefined) return { locked: undefined, source: 'unknown', detail: 'faillock-not-found' }
    const text = await readTally(target)
    const valid = validFailures(text)
    if (valid === undefined) return { locked: undefined, source: 'unknown', detail: 'tally-unreadable' }
    const limit = denyLimit()
    return { locked: valid >= limit, source: 'faillock', detail: `${valid}/${limit}` }
  }

  return { read }
}
