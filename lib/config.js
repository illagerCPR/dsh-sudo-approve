/**
 * Config resolution and the settings store.
 *
 * Two layers exist on purpose. The install-time `config` comes from
 * `cordis.patch.yml`; the saved store under `DSH_HOME` sits above it and is the
 * only place the browser can write, and it accepts just the timing knobs. Every
 * switch that decides what the gate does stays file-only, because a script
 * holding a session cookie must not be able to turn the gate off.
 * @module dsh-sudo-approve/lib/config
 */

import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { dirname } from 'node:path'
import { isPlainObject } from './util.js'

/** Bounds for the tunable config values. */
export const LIMITS = {
  timeoutMs: [5_000, 900_000],
  presenceWindowMs: [2_000, 300_000],
  memoryTtlMs: [60_000, 24 * 60 * 60 * 1000],
}

/**
 * The presence window the page may set.
 *
 * `presenceWindowMs` is how long a stale "I am on screen" claim is trusted, so
 * the page may narrow it but must not widen it: a script that could set five
 * minutes would keep the gate convinced somebody is watching long after the tab
 * was closed. The file keeps the wider `LIMITS` range for slow, headless setups.
 */
export const PAGE_LIMITS = { presenceWindowMs: [2_000, 30_000] }

/**
 * The only settings the page may change. They decide timing, not authority, so
 * a script holding a session cookie can move them without gaining anything but
 * a wider window; everything that decides what the gate does stays file-only.
 * `sanitizeRuntimePatch` below and the reset both have to agree with this list.
 */
export const PAGE_EDITABLE_KEYS = Object.freeze(['timeoutMs', 'presenceWindowMs'])

/** Keys the settings page shows but refuses to write. */
export const READ_ONLY_KEYS = Object.freeze([
  'enabled',
  'remember',
  'credential',
  'allowRemoteDeployment',
  'sudoPath',
  'passwordDialog',
])

/** Defaults; a `cordis.patch.yml` `config` object overrides them. */
export const DEFAULTS = Object.freeze({
  /** Master switch. */
  enabled: true,
  /** `never` asks for the password every time; `session` reuses it in memory. */
  remember: 'never',
  /**
   * How the validated password reaches the command: `askpass` installs a shim
   * that adds `-A` for exactly one spawn, `timestamp` relies on the sudo
   * credential cache, and `auto` probes the cache and falls back to the shim.
   */
  credential: 'auto',
  /** How long the password panel stays open before it denies. */
  timeoutMs: 120_000,
  /** How recently a page must have polled to count as connected. */
  presenceWindowMs: 15_000,
  /** Tool names that can carry a shell command. */
  toolNames: Object.freeze(['bash']),
  /** Refuse to accept passwords when the deployment trusts non-loopback hosts. */
  allowRemoteDeployment: false,
  /** Remembered passwords idle for this long are dropped. */
  memoryTtlMs: 6 * 60 * 60 * 1000,
  /** Absolute path of the real sudo; empty means "resolve on a trusted path". */
  sudoPath: '',
  /**
   * Where the password is typed: `auto` picks the host's system dialog when the
   * deployment can show one and the Web page otherwise, `native` insists on the
   * dialog, `browser` insists on the page.
   */
  passwordDialog: 'auto',
})

/**
 * Keep only well-typed values from the settings file. Security-relevant keys
 * are accepted here on purpose: the file is the documented way to change them,
 * while the HTTP route below deliberately cannot.
 */
export function sanitizePatch(raw) {
  const patch = {}
  if (!isPlainObject(raw)) return patch
  if (typeof raw.enabled === 'boolean') patch.enabled = raw.enabled
  if (raw.remember === 'never' || raw.remember === 'session') patch.remember = raw.remember
  if (raw.credential === 'auto' || raw.credential === 'askpass' || raw.credential === 'timestamp') {
    patch.credential = raw.credential
  }
  if (typeof raw.sudoPath === 'string' && raw.sudoPath !== '') patch.sudoPath = raw.sudoPath
  if (typeof raw.timeoutMs === 'number' && Number.isFinite(raw.timeoutMs)) patch.timeoutMs = Math.round(raw.timeoutMs)
  if (typeof raw.presenceWindowMs === 'number' && Number.isFinite(raw.presenceWindowMs)) {
    patch.presenceWindowMs = Math.round(raw.presenceWindowMs)
  }
  if (typeof raw.allowRemoteDeployment === 'boolean') patch.allowRemoteDeployment = raw.allowRemoteDeployment
  if (raw.passwordDialog === 'auto' || raw.passwordDialog === 'native' || raw.passwordDialog === 'browser') {
    patch.passwordDialog = raw.passwordDialog
  }
  return patch
}

/**
 * The subset the browser may change. `enabled`, `remember`, `credential`,
 * `allowRemoteDeployment` and `sudoPath` decide what the gate does, so a page
 * (or any script running in it) must not be able to flip them: they stay
 * file-only.
 */
export function sanitizeRuntimePatch(raw) {
  const patch = {}
  if (!isPlainObject(raw)) return patch
  if (typeof raw.timeoutMs === 'number' && Number.isFinite(raw.timeoutMs)) patch.timeoutMs = Math.round(raw.timeoutMs)
  if (typeof raw.presenceWindowMs === 'number' && Number.isFinite(raw.presenceWindowMs)) {
    // Clamped here and not only in `resolveConfig`, because the stored value is
    // what the next request reads: a page must not be able to bank a wide one.
    const [low, high] = PAGE_LIMITS.presenceWindowMs
    patch.presenceWindowMs = Math.min(Math.max(Math.round(raw.presenceWindowMs), low), high)
  }
  return patch
}

/**
 * Read and clamp the plugin config.
 * @param raw - the Loader entry's `config` object.
 * @returns the resolved config.
 */
export function resolveConfig(raw) {
  const input = isPlainObject(raw) ? raw : {}
  const clamp = (value, [min, max], fallback) =>
    typeof value === 'number' && Number.isFinite(value) ? Math.min(Math.max(value, min), max) : fallback
  const toolNames = Array.isArray(input.toolNames)
    ? input.toolNames.filter((name) => typeof name === 'string' && name !== '')
    : [...DEFAULTS.toolNames]
  return {
    enabled: input.enabled !== false,
    remember: input.remember === 'session' ? 'session' : 'never',
    credential: input.credential === 'askpass' || input.credential === 'timestamp' ? input.credential : 'auto',
    timeoutMs: clamp(input.timeoutMs, LIMITS.timeoutMs, DEFAULTS.timeoutMs),
    presenceWindowMs: clamp(input.presenceWindowMs, LIMITS.presenceWindowMs, DEFAULTS.presenceWindowMs),
    memoryTtlMs: clamp(input.memoryTtlMs, LIMITS.memoryTtlMs, DEFAULTS.memoryTtlMs),
    toolNames: new Set(toolNames.length > 0 ? toolNames : [...DEFAULTS.toolNames]),
    allowRemoteDeployment: input.allowRemoteDeployment === true,
    sudoPath: typeof input.sudoPath === 'string' ? input.sudoPath : '',
    passwordDialog:
      input.passwordDialog === 'native' || input.passwordDialog === 'browser' ? input.passwordDialog : DEFAULTS.passwordDialog,
  }
}

/** Saved settings, when the file reads back as editable values. */
function readStored(storePath) {
  try {
    const parsed = JSON.parse(readFileSync(storePath, 'utf8'))
    return isPlainObject(parsed) ? sanitizePatch(parsed) : {}
  } catch {
    return {}
  }
}

/**
 * The live config plus the file it persists to.
 *
 * `onApply` is the assembly's hook: a config change can invalidate remembered
 * secrets, and that store belongs to the caller, so it is told rather than
 * reached into.
 * @param deps - install config, store path, and the values `snapshot` reports.
 */
export function createSettings(deps) {
  const { installConfig, storePath, build, auditLog, sudoOf } = deps
  let overrides = readStored(storePath)
  let config = resolveConfig({ ...installConfig, ...overrides })

  /** Recompute live config and announce it. */
  function applyOverrides(next) {
    overrides = next
    config = resolveConfig({ ...installConfig, ...overrides })
    settings.onApply(config)
  }

  const settings = {
    /** Replaced by the assembly; called after every persisted change. */
    onApply: () => {},
    /** The config every request reads. */
    get: () => config,
    /** Path of the store file, for the settings page. */
    store: storePath,
    /** Audit log path, for the settings page. */
    auditLog,
    /**
     * Persist a validated patch and apply it to new requests immediately.
     * @param patch - already sanitized by `sanitizeRuntimePatch`.
     */
    save(patch) {
      const next = { ...overrides, ...patch }
      mkdirSync(dirname(storePath), { recursive: true })
      writeFileSync(storePath, `${JSON.stringify(next, null, 2)}\n`, { mode: 0o600 })
      applyOverrides(next)
    },
    /**
     * Drop the saved values the page is allowed to change; keep the rest.
     *
     * A reset that deleted the whole store used to hand the page a way around
     * the file-only rule: it could not POST `enabled:false`, but it could delete
     * a file that said `enabled:false` and fall back to the install-time value.
     * The two timing knobs belong to the page, so only they go.
     * @returns the keys that survived, so the audit line can name them.
     */
    reset() {
      const next = { ...overrides }
      for (const key of PAGE_EDITABLE_KEYS) delete next[key]
      try {
        if (Object.keys(next).length === 0) rmSync(storePath, { force: true })
        else writeFileSync(storePath, `${JSON.stringify(next, null, 2)}\n`, { mode: 0o600 })
      } catch {
        // best effort: the in-memory reset still applies
      }
      applyOverrides(next)
      return Object.keys(next)
    },
    /** Values and bounds the settings page renders. */
    snapshot() {
      return {
        build,
        store: storePath,
        auditLog,
        limits: { timeoutMs: LIMITS.timeoutMs, presenceWindowMs: PAGE_LIMITS.presenceWindowMs },
        readOnly: [...READ_ONLY_KEYS],
        values: {
          enabled: config.enabled,
          remember: config.remember,
          credential: config.credential,
          timeoutMs: config.timeoutMs,
          presenceWindowMs: config.presenceWindowMs,
          allowRemoteDeployment: config.allowRemoteDeployment,
          passwordDialog: config.passwordDialog,
        },
        sudo: sudoOf(),
        install: sanitizePatch(installConfig),
        overrides: { ...overrides },
      }
    },
  }

  return settings
}
