// The engine's local pages (CONTRACT.md, Local pages): a short link
// /approvals/<id> or /reverts/<id> opens a page the engine serves itself. The
// page reads the request for that id from the engine and, after the passkey
// signs, posts the response back for the engine to relay. Same origin only.
// Pure functions with the fetch passed in, so they run under `node --test`.

const UUID_PATH = "([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})";

// RelayError is an answer from the engine that is not a success, or no
// answer at all. code is the contract's error code when the engine gave one.
export class RelayError extends Error {
  constructor(message, code = "", status = 0) {
    super(message);
    this.name = "RelayError";
    this.code = code;
    this.status = status;
  }
}

// shortLinkId is the id a page link carries in its path (page "approvals"
// or "reverts", as in /approvals/<id>), or null for any other path.
export function shortLinkId(pathname, page) {
  const m = new RegExp(`^/${page}/${UUID_PATH}/?$`).exec(pathname);
  return m ? m[1] : null;
}

// pageId is the id in the page's path, which every approval and revert link
// carries (/approvals/<id>, /reverts/<id>; CONTRACT.md, Page links). A
// format 2 request takes its id from its binding, so the page refuses to
// run without an id to check it against.
export function pageId(pathname, page) {
  const id = shortLinkId(pathname, page);
  if (id === null) throw new Error(`this link has no ${page === "approvals" ? "approval" : "revert"} id in its path; open the whole link the engine gave`);
  return id;
}

// Paths of the relay for a short link's page and id.
export function relayPaths(page, id) {
  const action = page === "approvals" ? "approve" : "apply";
  return { request: `/api/v1/${page}/${id}`, relay: `/api/v1/${page}/${id}/${action}` };
}

const UNREACHABLE = "cannot reach the BasaltDB engine: is it still running?";

// Reading the request retries an unreachable engine for about 5 seconds
// (REQUEST_ATTEMPTS tries, REQUEST_RETRY_MS apart), so a page opened while
// the engine restarts still loads. The relay POST is never retried.
export const REQUEST_ATTEMPTS = 6;
export const REQUEST_RETRY_MS = 1000;

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function reach(call, attempts, wait) {
  for (let i = 1; ; i++) {
    try {
      return await call();
    } catch {
      if (i >= attempts) {
        throw new RelayError(UNREACHABLE);
      }
    }
    await wait(REQUEST_RETRY_MS);
  }
}

async function answer(call, attempts = 1, wait = sleep) {
  const res = await reach(call, attempts, wait);
  let body = null;
  try {
    body = await res.json();
  } catch {
    // An answer without a JSON body: the status says enough.
  }
  if (!res.ok) {
    throw new RelayError(body?.message ?? `the engine answered ${res.status}`, body?.code ?? "", res.status);
  }
  return body;
}

// SECRET_HEADER carries a short link's secret to the engine (CONTRACT.md,
// Link secrets). The secret lives in the link's fragment, which the browser
// never sends, so it stays out of logs; the page passes it here, to the
// same origin only.
export const SECRET_HEADER = "basalt-link-secret";

// linkSecret is the secret a short link's fragment carries (#s=<secret>),
// or "" when there is none.
export function linkSecret(hash) {
  const m = /^#?s=([A-Za-z0-9_-]+)$/.exec(String(hash ?? ""));
  return m ? m[1] : "";
}

// isLongLink reports whether a fragment carries the request itself
// (#2.<request>, or #1.<request> before format 2), as long links do.
export function isLongLink(hash) {
  return /^#?[12]\./.test(String(hash ?? ""));
}

// fetchRequest reads the request a short link stands for.
// fetchRequest reads the request; wait (ms) => Promise is injected by
// tests and defaults to a timer.
export function fetchRequest(fetchFn, path, secret, wait = sleep) {
  return answer(
    () =>
      fetchFn(path, {
        headers: { Accept: "application/json", [SECRET_HEADER]: secret },
        cache: "no-store",
        credentials: "omit",
      }),
    REQUEST_ATTEMPTS,
    wait,
  );
}

// postResponse relays the signed response JSON to the engine.
export function postResponse(fetchFn, path, secret, json) {
  return answer(() =>
    fetchFn(path, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json", [SECRET_HEADER]: secret },
      body: json,
      cache: "no-store",
      credentials: "omit",
    }),
  );
}

// revertDone says what a relayed revert did (the result of apply_revert).
export function revertDone(result) {
  if (result?.batched) {
    return `Signed. Your agent restores the ${result.pending} remaining rows in batches; nothing else to do here.`;
  }
  return `Reverted: ${result?.rows ?? 0} rows restored, ${result?.skipped ?? 0} left as they are.`;
}
