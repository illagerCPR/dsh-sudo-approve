/**
 * Trusted-binary resolution.
 *
 * Two binaries here receive material the gate must never lose: the real `sudo`,
 * which is handed the password, and the dialog, which collects it. Both are
 * therefore resolved on a fixed list of root-owned locations and re-validated
 * after `realpath`, never through `PATH`. The Host's `PATH` begins with
 * `~/.local/bin`, which the agent itself can write, so "the first match on PATH"
 * would let a script planted there answer for the real binary — and a fake
 * `zenity` answering for the dialog would harvest the login password at the very
 * moment the user typed it.
 *
 * A binary counts only when it *and every directory above it* are root-owned and
 * not group- or world-writable. Checking the file alone is not enough: a
 * root-owned file sitting in a writable directory can still be replaced.
 * @module dsh-sudo-approve/lib/trusted
 */

import { realpathSync, statSync } from 'node:fs'
import { dirname } from 'node:path'

/** Whether every level from `/` down to the binary is out of reach of non-root. */
function pathIsTrusted(target) {
  let current = dirname(target)
  for (;;) {
    const stat = statSync(current)
    if (!stat.isDirectory()) return false
    if (stat.uid !== 0) return false
    if ((stat.mode & 0o022) !== 0) return false
    const parent = dirname(current)
    if (parent === current) return true
    current = parent
  }
}

/**
 * Validate one absolute candidate.
 *
 * `sudo` is normally a symlink (`/usr/bin/sudo -> /etc/alternatives/sudo`), so
 * what runs — and what has to pass the checks — is the link target.
 * @param candidate - an absolute path, possibly a symlink.
 * @returns the resolved path, or undefined when any check fails.
 */
function validate(candidate) {
  if (typeof candidate !== 'string' || !candidate.startsWith('/')) return undefined
  try {
    const real = realpathSync(candidate)
    const stat = statSync(real)
    if (!stat.isFile()) return undefined
    if (stat.uid !== 0) return undefined
    if ((stat.mode & 0o022) !== 0) return undefined
    if ((stat.mode & 0o111) === 0) return undefined
    return pathIsTrusted(real) ? real : undefined
  } catch {
    return undefined
  }
}

/**
 * Find a trusted binary, letting a configured path go first.
 *
 * A `sudoPath` override is checked exactly like the defaults: anything that fails
 * validation leaves the plugin inactive rather than falling back to something
 * weaker.
 * @param configured - a config-supplied absolute path, or an empty string.
 * @param candidates - fallback list, already absolute.
 * @returns `{ path }` for the real binary and `{ link }` for the name asked for,
 *   or undefined.
 */
export function resolveTrusted(configured, candidates) {
  const list = configured === undefined || configured === '' ? candidates : [configured, ...candidates]
  for (const candidate of list) {
    const path = validate(candidate)
    if (path !== undefined) return { path, link: candidate }
  }
  return undefined
}

/**
 * The dialog backends a native approval can drive, in preference order.
 *
 * Fixed system locations only: this list used to be searched on `PATH`, which
 * meant a directory the agent can write could supply the program that asks for
 * the password. zenity comes before kdialog because it has its own timeout,
 * button labels and `--no-markup`.
 */
export const DIALOG_CANDIDATES = Object.freeze([
  Object.freeze({ name: 'zenity', path: '/usr/bin/zenity' }),
  Object.freeze({ name: 'zenity', path: '/usr/local/bin/zenity' }),
  Object.freeze({ name: 'kdialog', path: '/usr/bin/kdialog' }),
  Object.freeze({ name: 'kdialog', path: '/usr/local/bin/kdialog' }),
])

/**
 * First trusted dialog backend.
 * @param candidates - override for tests; defaults to {@link DIALOG_CANDIDATES}.
 * @returns `{ name, path }`, where `name` selects the argument style, or
 *   undefined when no backend passes validation.
 */
export function resolveDialogBinary(candidates = DIALOG_CANDIDATES) {
  for (const entry of candidates) {
    const path = validate(entry.path)
    if (path !== undefined) return { name: entry.name, path }
  }
  return undefined
}
