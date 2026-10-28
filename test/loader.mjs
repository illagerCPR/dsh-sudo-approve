// Redirects `lib/trusted.js` to the scripted stand-in; everything else loads
// normally. The real module stays reachable as `lib/trusted.js?real`.
const target = new URL('../lib/trusted.js', import.meta.url).href
const stub = new URL('./fake-trusted.mjs', import.meta.url).href

export async function resolve(specifier, context, next) {
  const resolved = await next(specifier, context)
  if (resolved.url === target) return { url: stub, shortCircuit: true }
  return resolved
}
