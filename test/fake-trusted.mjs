// Test-only stand-in for lib/trusted.js.
//
// It re-exports the real resolver (so `resolveTrusted` keeps its real behaviour)
// but answers `resolveDialogBinary` with a scripted path, because the dialog is
// resolved on fixed root-owned paths and the tests must never open a real
// window.
export * from '../lib/trusted.js?real'

export function resolveDialogBinary() {
  return { name: process.env.DSA_FAKE_DIALOG_NAME ?? 'zenity', path: process.env.DSA_FAKE_ZENITY }
}
