/**
 * What the panel is shown, derived from the command string alone.
 *
 * Pure functions: no Host state, no I/O. Every answer here is a security fact,
 * not a display detail — an approval covers the whole command string, so a
 * command that cannot be shown in full must never be approved.
 * @module dsh-sudo-approve/lib/analysis
 */

import { createHash } from 'node:crypto'

/**
 * The `sudo` / `sudoedit` word, wherever it appears. Detection is fail-closed on
 * purpose: an absolute path (`/usr/bin/sudo`), a wrapper (`exec`, `env`,
 * `xargs`, `timeout`), or a quoted `bash -c "sudo …"` all reach the real
 * binary, so requiring a command word position under-detects and would let a
 * command run without the password panel.
 */
export const SUDO_TOKEN = /(?:^|[^\w-])(?:sudo|sudoedit)(?=$|[^\w-])/

/** Forms that never authenticate, so they must not be given `-A`. */
export const METADATA_ONLY_SUDO =
  /^(?:[A-Za-z_][A-Za-z0-9_]*=(?:"[^"]*"|'[^']*'|[^\s;&|()]*)\s+)*(?:sudo|sudoedit)\s+(?:-k|-K|-V|-h|--reset-timestamp|--remove-timestamp|--version|--help)\s*;?\s*$/

/** Cap on displayed command lines; a longer script is truncated in the panel. */
export const MAX_DISPLAY_LINES = 60
/** Cap on one displayed line. */
export const MAX_DISPLAY_WIDTH = 400

/**
 * Remove shell line continuations.
 *
 * A backslash before a newline is deleted before the line is split into words,
 * so `su\` + newline + `do` runs `sudo` while the raw text never contains the
 * word. Folding first is what makes the scan and the panel describe the command
 * bash will actually parse. Folding is deliberately over-eager: a backslash
 * inside single quotes stays literal for the shell, and folding it anyway can
 * only add a panel, never remove one.
 * @param text - the raw command string.
 * @returns the same command with continuations folded away.
 */
export function foldContinuations(text) {
  return text.replace(/\\\r?\n/g, '')
}

/** Stable short fingerprint of a command string, for the audit log and `armed`. */
export function digestOf(command) {
  return createHash('sha256').update(command, 'utf8').digest('hex').slice(0, 16)
}

/**
 * Turn a bash command into the lines the panel lists.
 *
 * `truncated` is a security fact, not a display detail: an approval covers the
 * whole command string, so a command the panel cannot show in full must never
 * be approved — the caller refuses it instead.
 * @param command - the tool's `command` argument.
 * @returns the displayed items, whether any of them needs real authority,
 *   whether the word appears at all, and whether the panel would hide part of
 *   the command.
 */
export function analyzeCommand(command) {
  // Folding before splitting means the panel lists the text bash will parse.
  const folded = foldContinuations(command)
  const items = []
  let truncated = false
  for (const raw of folded.split(/\r?\n/)) {
    const text = raw.trim()
    if (text === '') continue
    if (items.length >= MAX_DISPLAY_LINES) {
      truncated = true
      break
    }
    // A whole-line shell comment can never execute, so it never asks.
    const sudo = !text.startsWith('#') && SUDO_TOKEN.test(text)
    if (text.length > MAX_DISPLAY_WIDTH) truncated = true
    items.push({
      text: text.length > MAX_DISPLAY_WIDTH ? `${text.slice(0, MAX_DISPLAY_WIDTH)}…` : text,
      sudo,
      // `sudo -k` / `sudo -V` never authenticate, so they need no password.
      privileged: sudo && !METADATA_ONLY_SUDO.test(text),
    })
  }
  if (truncated) items.push({ text: `…（仅显示前 ${MAX_DISPLAY_LINES} 行 / 每行 ${MAX_DISPLAY_WIDTH} 字符）`, sudo: false, privileged: false, note: true })
  return {
    items,
    hasSudo: items.some((item) => item.privileged),
    // Whether the word appears at all is a separate question from whether it
    // needs authority: it may sit in a comment, or in a `-k` form.
    mentionsSudo: SUDO_TOKEN.test(folded),
    truncated,
    digest: digestOf(command),
  }
}
