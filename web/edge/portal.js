// The portal's edge function (Cloudflare Pages Functions middleware,
// functions/_middleware.js): it gives the connect page its fixed policy,
// which allows the connect service (CONTRACT.md, The connect page). Every
// other page is served by the static host as it is, with web/_headers.

// DEFAULT_HEADERS are web/_headers' /* block, the same as the engine's own
// pages (internal/websec); a test fails on drift. The function sets all of
// them on the answer it builds, so they never depend on the static host
// applying _headers to a function's answer.
export const DEFAULT_CSP = "default-src 'self'; connect-src wss://relay.basaltvault.app; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
export const DEFAULT_HEADERS = Object.freeze({
  "Content-Security-Policy": DEFAULT_CSP,
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
  "Cross-Origin-Opener-Policy": "same-origin",
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
});

// The connect page (CONTRACT.md, The connect page) reaches the connect
// service and nothing else: the default policy with connect-src naming that
// one origin, the same for everyone, never stored. Its own meta CSP names
// the same source; internal/websec ConnectPageCSP is the copy basalt portal
// verify expects, and a test fails on drift.
export const CONNECT_SERVICE = "https://connect.basaltvault.app";
export const CONNECT_CSP = "default-src 'self'; connect-src https://connect.basaltvault.app; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
const CONNECT_PAGE = /^\/connect\/?$/;

// connectPage serves the connect page with its own policy: the security
// headers, CSP with the connect service, never stored. It is the same for
// every request, so it varies with nothing.
function connectPage(upstream) {
  const out = new Response(upstream.body, upstream);
  for (const [k, v] of Object.entries(DEFAULT_HEADERS)) out.headers.set(k, v);
  out.headers.set("Content-Security-Policy", CONNECT_CSP);
  out.headers.set("Cache-Control", "no-store");
  out.headers.delete("ETag");
  out.headers.delete("Last-Modified");
  return out;
}

// handle answers one request: next(request) fetches the static asset.
export async function handle(request, next) {
  const url = new URL(request.url);
  if (!CONNECT_PAGE.test(url.pathname)) return next(request);

  // Never let a conditional request turn into a 304 that keeps another
  // policy in a cache: always fetch the whole page.
  const clean = new Headers(request.headers);
  clean.delete("If-None-Match");
  clean.delete("If-Modified-Since");
  return connectPage(await next(new Request(request.url, { method: request.method, headers: clean })));
}

// onRequest is the Pages Functions entry point.
export function onRequest(context) {
  return handle(context.request, (req) => context.next(req));
}
