// The engine's local pages (CONTRACT.md, Local pages): a short link
// /approve/<id> or /revert/<id> opens a page the engine serves itself. The
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

// shortLinkId is the id a short link carries in its path, or null for any
// other path (the long link carries its request in the fragment instead).
export function shortLinkId(pathname, page) {
  const m = new RegExp(`^/${page}/${UUID_PATH}/?$`).exec(pathname);
  return m ? m[1] : null;
}

// Paths of the relay for a short link's page and id.
export function relayPaths(page, id) {
  const kind = page === "approve" ? "approvals" : "reverts";
  const action = page === "approve" ? "approve" : "apply";
  return { request: `/api/v1/${kind}/${id}`, relay: `/api/v1/${kind}/${id}/${action}` };
}

async function answer(call) {
  let res;
  try {
    res = await call();
  } catch {
    throw new RelayError("cannot reach the BasaltDB engine: is it still running?");
  }
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

// fetchRequest reads the request a short link stands for.
export function fetchRequest(fetchFn, path) {
  return answer(() => fetchFn(path, { headers: { Accept: "application/json" }, cache: "no-store", credentials: "omit" }));
}

// postResponse relays the signed response JSON to the engine.
export function postResponse(fetchFn, path, json) {
  return answer(() =>
    fetchFn(path, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
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
