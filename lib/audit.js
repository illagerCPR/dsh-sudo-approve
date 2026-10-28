/**
 * The audit log.
 *
 * One JSON object per line, appended best-effort: an audit failure must never
 * break the gate. Nothing here ever receives a password, and command text never
 * reaches it — only digests, counts and reasons.
 * @module dsh-sudo-approve/lib/audit
 */

import { appendFileSync, mkdirSync } from 'node:fs'
import { dirname } from 'node:path'

/**
 * @param logPath - absolute path of the JSONL file.
 * @returns the append function used by every other part.
 */
export function createAudit(logPath) {
  return function audit(event) {
    try {
      mkdirSync(dirname(logPath), { recursive: true })
      appendFileSync(logPath, `${JSON.stringify({ time: new Date().toISOString(), ...event })}\n`, {
        mode: 0o600,
      })
    } catch {
      // audit is best effort; never break the gate
    }
  }
}
