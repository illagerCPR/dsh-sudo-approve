/**
 * The PATH shim that teaches one spawn how to reach the password.
 *
 * Nothing global is mutated when scoped delivery is available: a private
 * directory holds a `sudo`/`sudoedit` wrapper that adds `-A` plus an askpass
 * helper, and the directory is named only in the `PATH` of the one spawn it was
 * built for. The scope handed in here is the same AsyncLocalStorage instance the
 * `tools/execute` hook opens, which is what keeps two concurrent approvals from
 * seeing each other's shim.
 * @module dsh-sudo-approve/lib/shim
 */

import { readdirSync, rmSync, statSync } from 'node:fs'
import { chmod, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { errorText, isPlainObject } from './util.js'

/**
 * Generated `sudo` shim. It exists only while an approved command runs and only
 * adds `-A`; forms that sudo-rs refuses to combine with `-A` (`-k`, `-V`, `-h`)
 * are forwarded untouched. The askpass helper travels in the shim's own
 * environment instead of the Host's, so concurrent installs cannot take the
 * password source away from each other.
 */
const SUDO_SHIM = `#!/bin/sh
for arg do
  case "$arg" in
    -k|-K|-V|-h|--reset-timestamp|--remove-timestamp|--version|--help)
      exec "@SUDO@" "$@" ;;
  esac
done
SUDO_ASKPASS="@ASKPASS@" exec "@SUDO@" -A "$@"
`

/**
 * @param deps - plugin name, the approval scope, the Host PATH and the trusted
 *   sudo paths this deployment resolved.
 */
export function createShim(deps) {
  const { name, scope, basePath, realSudo, realSudoedit, audit } = deps

  /** Shim installs that still own a directory; cleaned on unload or exit. */
  const liveRuns = new Set()
  /**
   * Installs that had to fall back to a process-wide `PATH` because the shell
   * service refused to be wrapped. Kept so the fallback can still be undone.
   */
  const globalRuns = []
  /** Whether the shim is delivered per spawn instead of through `process.env`. */
  let scopedShims = false

  /** Rebuild the process-wide PATH from the fallback installs, oldest last. */
  function syncGlobalPath() {
    process.env.PATH = globalRuns.length === 0 ? basePath : `${globalRuns.map((run) => run.bin).join(':')}:${basePath}`
  }

  /**
   * Put one PATH shim and askpass helper in a private directory.
   * @param secret - the validated password.
   * @returns the run record the scope carries.
   */
  async function materialize(secret) {
    const root = await mkdtemp(join(process.env.XDG_RUNTIME_DIR || tmpdir(), `${name}-`))
    const run = { root }
    try {
      await chmod(root, 0o700)
      const bin = join(root, 'bin')
      await mkdir(bin, { mode: 0o700 })
      const passwordFile = join(root, 'askpass.txt')
      await writeFile(passwordFile, secret, { mode: 0o600 })
      await chmod(passwordFile, 0o600)
      const askpass = join(root, 'askpass.sh')
      await writeFile(askpass, `#!/bin/sh\nexec cat "${passwordFile}"\n`, { mode: 0o700 })
      await chmod(askpass, 0o700)
      const shim = (target) => SUDO_SHIM.replaceAll('@SUDO@', target).replaceAll('@ASKPASS@', askpass)
      await writeFile(join(bin, 'sudo'), shim(realSudo.path), { mode: 0o700 })
      await chmod(join(bin, 'sudo'), 0o700)
      if (realSudoedit !== undefined) {
        await writeFile(join(bin, 'sudoedit'), shim(realSudoedit.path), { mode: 0o700 })
        await chmod(join(bin, 'sudoedit'), 0o700)
      }
      run.bin = bin
      run.askpass = askpass
      liveRuns.add(run)
      if (!scopedShims) {
        // Degraded: the shell service could not be wrapped, so the shim has to
        // ride the process environment. Audited so the difference is visible.
        globalRuns.push(run)
        syncGlobalPath()
      }
      return run
    } catch (error) {
      await dematerialize(run)
      throw error
    }
  }

  /** Delete one shim directory and forget it. */
  async function dematerialize(run) {
    if (run === undefined) return
    liveRuns.delete(run)
    const index = globalRuns.indexOf(run)
    if (index >= 0) {
      globalRuns.splice(index, 1)
      syncGlobalPath()
    }
    if (run.root === undefined) return
    await rm(run.root, { recursive: true, force: true }).catch(() => {})
  }

  /** Synchronous last-resort cleanup for process exit and plugin unload. */
  function hardCleanup() {
    const runs = [...liveRuns]
    liveRuns.clear()
    globalRuns.length = 0
    syncGlobalPath()
    for (const run of runs) {
      try {
        rmSync(run.root, { recursive: true, force: true })
      } catch {
        // ignore
      }
    }
  }

  /**
   * Delete shim directories a crashed Host left behind. They hold a plaintext
   * password, so a stale one must not survive the next start; the age guard
   * keeps a concurrently starting Host's fresh directory untouched.
   */
  function sweepStaleRuns() {
    const parent = process.env.XDG_RUNTIME_DIR || tmpdir()
    let entries
    try {
      entries = readdirSync(parent)
    } catch {
      return
    }
    for (const entry of entries) {
      if (!entry.startsWith(`${name}-`)) continue
      const target = join(parent, entry)
      try {
        const stat = statSync(target)
        if (!stat.isDirectory()) continue
        if (Date.now() - stat.mtimeMs < 60_000) continue
        rmSync(target, { recursive: true, force: true })
        audit({ event: 'stale-cleanup', path: target })
      } catch {
        // best effort
      }
    }
  }

  /**
   * Teach the shell service to deliver a shim to one spawn.
   *
   * The bash tool asks `ctx.shell.resolve()` for a fully specified spec and then
   * spawns it with `spec.env`; wrapping `resolve` therefore lets this plugin put
   * its `PATH` on exactly the spawn the user approved. The approval travels in
   * an AsyncLocalStorage store set by the `tools/execute` hook, which is what
   * keeps two concurrent approvals from seeing each other's shim.
   * @param ctx - the plugin context.
   */
  function installScoped(ctx) {
    ctx.effect(() => {
      let restore
      const child = ctx.inject(['shell'], (inner) => {
        const service = inner.get('shell')
        if (service === undefined || typeof service.resolve !== 'function') return
        const original = service.resolve
        /** Counts calls that reached the wrapper; identity cannot be used, see below. */
        const hits = { count: 0 }
        const patched = function resolve(request) {
          hits.count += 1
          const spec = original.call(service, request)
          const run = scope.getStore()
          if (run === undefined || typeof run.bin !== 'string') return spec
          const inherited = isPlainObject(spec.env) && typeof spec.env.PATH === 'string' ? spec.env.PATH : basePath
          return {
            ...spec,
            env: { ...(isPlainObject(spec.env) ? spec.env : {}), PATH: `${run.bin}:${inherited}` },
          }
        }
        /**
         * Whether the write actually reaches callers. Cordis hands out a fresh
         * proxy for every method read (per-context shadowing), so comparing
         * `service.resolve` against `patched` always reports a mismatch even when
         * the assignment worked — the wrapper has to be observed instead. The
         * probe only builds a spec; nothing is spawned.
         */
        const reaches = () => {
          const before = hits.count
          try {
            service.resolve({ command: 'true', workdir: process.cwd() })
          } catch {
            return false
          }
          return hits.count > before
        }

        try {
          service.resolve = patched
          if (!reaches()) throw new Error('service instance refused the write')
          scopedShims = true
          restore = () => {
            try {
              delete service.resolve
            } catch {
              service.resolve = original
            }
            scopedShims = false
          }
          audit({ event: 'shim-scope', mode: 'instance' })
          return
        } catch {
          // Fall through: patch the class method instead of the instance.
        }

        try {
          const proto = Object.getPrototypeOf(service)
          if (proto === null || typeof proto.resolve !== 'function') throw new Error('no writable resolve on the prototype')
          const previous = proto.resolve
          proto.resolve = patched
          if (!reaches()) {
            proto.resolve = previous
            throw new Error('prototype refused the write')
          }
          scopedShims = true
          restore = () => {
            proto.resolve = previous
            scopedShims = false
          }
          audit({ event: 'shim-scope', mode: 'prototype' })
        } catch (error) {
          audit({ event: 'shim-global', reason: 'shell-not-wrappable', message: errorText(error) })
        }
      })
      return () => {
        restore?.()
        child?.dispose?.()
      }
    }, `${name}: scoped shim`)
  }

  return {
    installScoped,
    materialize,
    dematerialize,
    hardCleanup,
    sweepStaleRuns,
    /** Whether delivery is per spawn (the safe mode) or process-wide. */
    isScoped: () => scopedShims,
  }
}
