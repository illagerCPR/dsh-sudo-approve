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
 *
 * A rejection is reported with the step that failed ({@link diagnoseTrust}), so
 * the page can say *why* the plugin is not running instead of leaving the user
 * to guess from a silent Host. The reason names a path and a mode, never
 * anything the password or the command touches.
 * @module dsh-sudo-approve/lib/trusted
 */

import { realpathSync, statSync } from 'node:fs'
import { dirname } from 'node:path'

/** Permission bits in the octal spelling `ls -l` shows. */
function modeOf(stat) {
  return (stat.mode & 0o7777).toString(8)
}

/**
 * The first directory above `target` that a non-root user could rewrite.
 *
 * Walking stops at `/`: a writable `/` would make every binary on the machine
 * replaceable, which is exactly the fact the caller needs to hear.
 * @param target - an absolute, already-resolved file path.
 * @returns `{ path, mode }` for the offending directory, or undefined when the
 *   whole chain is out of reach of non-root.
 */
function untrustedAncestor(target) {
  let current = dirname(target)
  for (;;) {
    let stat
    try {
      stat = statSync(current)
    } catch {
      return { path: current, mode: undefined }
    }
    if (!stat.isDirectory()) return { path: current, mode: modeOf(stat) }
    if (stat.uid !== 0) return { path: current, mode: modeOf(stat) }
    if ((stat.mode & 0o022) !== 0) return { path: current, mode: modeOf(stat) }
    const parent = dirname(current)
    if (parent === current) return undefined
    current = parent
  }
}

/**
 * Validate one absolute candidate, naming the step that fails.
 *
 * `sudo` is normally a symlink (`/usr/bin/sudo -> /etc/alternatives/sudo`), so
 * what runs — and what has to pass the checks — is the link target.
 * @param candidate - an absolute path, possibly a symlink.
 * @returns `{ ok: true, path }` with the resolved path, or `{ ok: false, check,
 *   path, mode?, uid? }` naming the first failed check.
 */
function inspect(candidate) {
  if (typeof candidate !== 'string' || !candidate.startsWith('/')) {
    return { ok: false, check: 'relative-path', path: String(candidate) }
  }
  let real
  let stat
  try {
    real = realpathSync(candidate)
    stat = statSync(real)
  } catch {
    return { ok: false, check: 'missing', path: candidate }
  }
  if (!stat.isFile()) return { ok: false, check: 'not-a-file', path: real }
  if (stat.uid !== 0) return { ok: false, check: 'not-root-owned', path: real, uid: stat.uid }
  if ((stat.mode & 0o022) !== 0) return { ok: false, check: 'group-or-world-writable', path: real, mode: modeOf(stat) }
  if ((stat.mode & 0o111) === 0) return { ok: false, check: 'not-executable', path: real }
  const ancestor = untrustedAncestor(real)
  if (ancestor !== undefined) return { ok: false, check: 'untrusted-directory', ...ancestor }
  return { ok: true, path: real }
}

/**
 * The candidates to try.
 *
 * A pinned path is the whole list: falling back to the defaults would hand the
 * password to a binary the operator explicitly did not name — including when the
 * pin stopped passing its checks, which is exactly the case the check exists for.
 * An install that pins `sudoPath` therefore goes inactive, it does not drift back
 * to `/usr/bin/sudo`.
 */
function candidatesOf(configured, candidates) {
  if (typeof configured === 'string' && configured !== '') return [configured]
  return candidates
}

/**
 * Find a trusted binary.
 *
 * A `sudoPath` override is checked exactly like the defaults, but it replaces
 * them: anything that fails validation leaves the plugin inactive rather than
 * falling back to something weaker (see {@link candidatesOf}).
 * @param configured - a config-supplied absolute path, or an empty string.
 * @param candidates - fallback list, already absolute.
 * @returns `{ path }` for the real binary and `{ link }` for the name asked for,
 *   or undefined.
 */
export function resolveTrusted(configured, candidates) {
  for (const candidate of candidatesOf(configured, candidates)) {
    const result = inspect(candidate)
    if (result.ok) return { path: result.path, link: candidate }
  }
  return undefined
}

/**
 * Explain why {@link resolveTrusted} found nothing.
 *
 * Only the first candidate's failure is described: every later one repeats the
 * same environment problem, and a page that lists them all buries the one fix
 * that matters ("make this directory root-owned and not writable").
 * @param configured - a config-supplied absolute path, or an empty string.
 * @param candidates - fallback list, already absolute.
 * @returns `{ ok: true, path }` when something *is* trusted, otherwise
 *   `{ ok: false, check, path, mode?, uid?, tried }`.
 */
export function diagnoseTrust(configured, candidates) {
  const list = candidatesOf(configured, candidates)
  for (const candidate of list) {
    const result = inspect(candidate)
    if (result.ok) return { ok: true, path: result.path, link: candidate }
  }
  const first = inspect(list[0])
  const failure = { ok: false, check: first.check, path: first.path, tried: [...list] }
  if (first.mode !== undefined) failure.mode = first.mode
  if (first.uid !== undefined) failure.uid = first.uid
  return failure
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
    const result = inspect(entry.path)
    if (result.ok) return { name: entry.name, path: result.path }
  }
  return undefined
}
