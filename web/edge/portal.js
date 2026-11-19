// The portal's edge function (Cloudflare Pages Functions middleware,
// functions/_middleware.js): the per-person allow list of the DIRECT
// transport (CONTRACT.md, Direct transport, CSP; owner decision 14 Nov
// 2026). A page that may run DIRECT gets connect-src 'self' plus each
// engine this device pinned, read from the __Host-basalt-engines cookie the
// portal page sets after pinning. Only an origin that passes the engine
// address grammar (web/lib/engineaddr.js, the one laptop init and Postgres
// apply) is added; anything else is dropped, and with nothing left the
// strict default is served as it is. It also gives the connect page its
// fixed policy, which allows the connect service (CONTRACT.md, The connect
// page).
//
// This is defence in depth, not what makes signing safe. Signing rests on
// subresource integrity on every script, the engine record pinned in
// Postgres with the pinned key checked in every handshake, and the
// person's passkey, verified in Postgres.
//
// Every answer this function changes is per person, so each one carries
// Cache-Control: no-store and Vary: Cookie, and it is built fresh for the
// request: nothing is shared between two requests, and the asset it starts
// from is never changed in place.

import { parseEngineAddress, socketOrigin } from "../lib/engineaddr.js";

export const PINS_COOKIE = "__Host-basalt-engines";
const COOKIE_SEPARATOR = "|";
export const MAX_ORIGINS = 8;
// A cookie value longer than 8 pins of the longest address cannot be ours.
const MAX_COOKIE_VALUE = MAX_ORIGINS * 300;

// DEFAULT_HEADERS are web/_headers' /* block, the same as the engine's own
// pages (internal/websec); a test fails on drift. The function sets all of
// them on every answer it builds, so they never depend on the static host
// applying _headers to a function's answer.
export const DEFAULT_CSP = "default-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
export const DEFAULT_HEADERS = Object.freeze({
  "Content-Security-Policy": DEFAULT_CSP,
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
  "Cross-Origin-Opener-Policy": "same-origin",
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
});

// The pages that open a link session (/approvals/<id>, /reverts/<id>) and
// the pin page, which checks one address not pinned yet.
const SESSION_PAGE = /^\/(approvals|reverts)\/[^/]+$/;
const PIN_PAGE = "/engines/add";

// The connect page (CONTRACT.md, The connect page) reaches the connect
// service and nothing else: the default policy with connect-src naming that
// one origin, the same for everyone, never stored. Its own meta CSP names
// the same source; internal/websec ConnectPageCSP is the copy basalt portal
// verify expects, and a test fails on drift.
export const CONNECT_SERVICE = "https://connect.basaltvault.app";
export const CONNECT_CSP = "default-src 'self'; connect-src https://connect.basaltvault.app; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
const CONNECT_PAGE = /^\/connect\/?$/;

// Cookie pairs are separated by "; " and only spaces and tabs are trimmed
// (RFC 6265). String.trim would also strip Unicode spaces, so a cookie
// another host set as "\u00a0__Host-basalt-engines" (no __Host- rules for
// the browser) would read as ours.
const OWS = /^[ \t]+|[ \t]+$/g;

// cookieOrigins reads the pinned engine origins from a Cookie header: only
// written engine addresses, each once, at most MAX_ORIGINS. The page sets
// one cookie of that name; two in one header mean another host planted one
// (a nameless cookie whose value starts with the name reads the same), so
// neither is used and the strict default is served.
export function cookieOrigins(cookieHeader) {
  let value = null;
  for (const part of String(cookieHeader ?? "").split(";")) {
    const at = part.indexOf("=");
    if (at < 0 || part.slice(0, at).replace(OWS, "") !== PINS_COOKIE) continue;
    if (value !== null) return [];
    value = part.slice(at + 1).replace(OWS, "");
  }
  if (value === null || value === "" || value.length > MAX_COOKIE_VALUE) return [];
  const out = [];
  for (const raw of value.split(COOKIE_SEPARATOR)) {
    // Only an address already in its written form: nothing is repaired.
    if (parseEngineAddress(raw) !== raw || out.includes(raw)) continue;
    out.push(raw);
    if (out.length === MAX_ORIGINS) break;
  }
  return out;
}

// candidateOrigin is the one address the pin page checks (?address=), or
// null.
export function candidateOrigin(url) {
  const values = url.searchParams.getAll("address");
  if (values.length !== 1) return null;
  // Only an address in its written form, as the pin page sends it.
  return parseEngineAddress(values[0]) === values[0] ? values[0] : null;
}

// connectSources lists what connect-src allows besides 'self': each
// pinned engine's https origin (the probe) and wss origin (the session).
export function connectSources(origins, { sockets = true } = {}) {
  return origins.flatMap((o) => (sockets ? [o, socketOrigin(o)] : [o]));
}

// policyWith is the default policy with connect-src 'self' and sources.
export function policyWith(sources) {
  const directives = DEFAULT_CSP.split("; ");
  directives.splice(1, 0, ["connect-src 'self'", ...sources].join(" "));
  return directives.join("; ");
}

const META_CSP = /(<meta http-equiv="Content-Security-Policy" content=")([^"]*)(">)/;

// rewriteMeta adds sources to the connect-src of the page's own meta CSP:
// a browser enforces both policies, so the meta must allow them too. A
// page without that meta is left as it is (and DIRECT then fails safe).
export function rewriteMeta(html, sources) {
  return html.replace(META_CSP, (all, open, content, close) => {
    const directives = content.split(";").map((d) => d.trim());
    const at = directives.findIndex((d) => d.startsWith("connect-src "));
    if (at < 0) return all;
    const current = directives[at].split(/\s+/).slice(1).filter((s) => s !== "'none'");
    directives[at] = ["connect-src", ...current, ...sources].join(" ");
    return open + directives.join("; ") + close;
  });
}

// personal marks an answer as built for this request: the security
// headers, never stored, and varying with the cookie.
function personal(headers) {
  for (const [k, v] of Object.entries(DEFAULT_HEADERS)) headers.set(k, v);
  headers.set("Cache-Control", "no-store");
  const vary = (headers.get("Vary") ?? "")
    .split(",")
    .map((v) => v.trim())
    .filter((v) => v !== "" && v.toLowerCase() !== "cookie");
  headers.set("Vary", [...vary, "Cookie"].join(", "));
}

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
  const session = SESSION_PAGE.test(url.pathname);
  const pin = url.pathname === PIN_PAGE;
  const connect = CONNECT_PAGE.test(url.pathname);
  if (!session && !pin && !connect) return next(request);

  // Never let a conditional request turn into a 304 that keeps another
  // policy in a cache: always fetch the whole page.
  const clean = new Headers(request.headers);
  clean.delete("If-None-Match");
  clean.delete("If-Modified-Since");
  const upstream = await next(new Request(request.url, { method: request.method, headers: clean }));
  if (connect) return connectPage(upstream);

  let sources = [];
  if (session) sources = connectSources(cookieOrigins(request.headers.get("Cookie")));
  if (pin) {
    const candidate = candidateOrigin(url);
    sources = candidate === null ? [] : connectSources([candidate], { sockets: false });
  }
  const html = upstream.status === 200 && (upstream.headers.get("Content-Type") ?? "").startsWith("text/html");
  if (sources.length === 0 || !html) {
    const out = new Response(upstream.body, upstream);
    personal(out.headers);
    return out;
  }
  const body = rewriteMeta(await upstream.text(), sources);
  const headers = new Headers(upstream.headers);
  personal(headers);
  headers.set("Content-Security-Policy", policyWith(sources));
  headers.delete("ETag");
  headers.delete("Last-Modified");
  headers.delete("Content-Length");
  return new Response(request.method === "HEAD" ? null : body, { status: 200, headers });
}

// onRequest is the Pages Functions entry point.
export function onRequest(context) {
  return handle(context.request, (req) => context.next(req));
}
