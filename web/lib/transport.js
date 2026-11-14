// The pages reach the engine through one small interface, so nothing above
// it knows which transport carries a request (design: vault channel,
// section 4.1):
//
//   transport.kind                              SAME_ORIGIN, DIRECT (later RELAY)
//   transport.open(link) -> Promise<session>    link: { page, id, secret }
//   session.request(method, path, headers, body)
//     -> Promise<{ status, headers, body }>
//   session.close()
//
// A request is the pages API's: a path under /api/v1/, lowercase headers
// (basalt-link-secret, and content-type on a POST), and a JSON text body or
// none. A response is the engine's answer whatever its status: status, its
// headers with lowercase names, and its body as text ("" when it has none).
// A request rejects only when it got no answer, and the caller decides
// whether to try again. Headers a transport needs for itself are its own to
// add: the same-origin one adds accept, a link session adds origin.
//
// One session serves one page's link: the request, then reveals, rescopes
// and the relay of the signature. A widen gives the link a new secret, and
// the session stays open; later requests carry the new secret.

import { PORTAL } from "./codec.js";
import { directTransport } from "./direct.js";
import { pinStore } from "./pins.js";

export const SAME_ORIGIN = "SAME_ORIGIN";

// The browser's network calls. Only the transports (this file, direct.js
// and channel.js) reach the network; the pages call them.
const windowFetch = (path, init) => window.fetch(path, init);
export const browserFetch = windowFetch;
export const browserSocket = (url) => new window.WebSocket(url);

async function bodyText(res) {
  try {
    return await res.text();
  } catch {
    return "";
  }
}

// sameOriginSession sends each request as a fetch to the page's own origin:
// the engine's local pages, on localhost, as before the transports.
export function sameOriginSession(fetchFn = windowFetch) {
  let closed = false;
  return {
    transport: SAME_ORIGIN,
    async request(method, path, headers = {}, body = null) {
      if (closed) throw new Error("this session to the engine is closed");
      const init = {
        method,
        headers: { accept: "application/json", ...headers },
        cache: "no-store",
        credentials: "omit",
      };
      if (body !== null && body !== undefined) init.body = body;
      const res = await fetchFn(path, init);
      return { status: res.status, headers: Object.fromEntries(res.headers ?? []), body: await bodyText(res) };
    },
    close() {
      closed = true;
    },
  };
}

// sameOriginTransport needs nothing from the link: the engine serving the
// page checks the secret each request carries.
export function sameOriginTransport(fetchFn = windowFetch) {
  return {
    kind: SAME_ORIGIN,
    open: async () => sameOriginSession(fetchFn),
  };
}

// RELOADED marks, for this tab, that the page already reloaded once to
// bring its CSP up to date with the pins, so it never loops.
const RELOADED = "basalt-engines-reloaded";

// reloadOnce reloads the page once per tab after the pins cookie was
// rewritten: the portal's edge function builds this load's connect-src
// from the cookie it received, so a stale cookie means a CSP without the
// pins. true when it reloads.
function reloadOnce(loc, storage) {
  try {
    if (storage.getItem(RELOADED) === "1") return false;
    storage.setItem(RELOADED, "1");
  } catch {
    return false;
  }
  loc.reload();
  return true;
}

// pageTransport is the transport the approval and revert pages use: on the
// portal, DIRECT over this device's pinned engines (the relay transport
// comes with its own ticket); on the engine's own local pages, the same
// origin.
export function pageTransport(loc = globalThis.window?.location) {
  if (loc?.origin !== PORTAL) return sameOriginTransport();
  const tab = globalThis.sessionStorage;
  return directTransport({
    store: pinStore(),
    fetchFn: browserFetch,
    socket: browserSocket,
    onStaleCookie: () => reloadOnce(loc, tab),
    onOpened: () => {
      try {
        tab.removeItem(RELOADED);
      } catch {
        // Nothing to clear.
      }
    },
  });
}
