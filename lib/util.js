/**
 * Tiny shared helpers. No plugin state, no Harness dependency.
 * @module dsh-sudo-approve/lib/util
 */

/** `true` for plain JSON-ish objects. */
export function isPlainObject(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

/** Compact error text for logs and tool results. */
export function errorText(error) {
  return error instanceof Error ? error.message : String(error)
}

/** One-line rejection reason; control characters folded, length capped. */
export function normalizeReason(value) {
  if (typeof value !== 'string') return undefined
  const text = value
    .replace(/[\u0000-\u001f\u007f]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
  if (text === '') return undefined
  return text.length > 200 ? `${text.slice(0, 200)}…` : text
}
