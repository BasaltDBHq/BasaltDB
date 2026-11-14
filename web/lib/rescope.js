// The revert page's scope route (CONTRACT.md, Revert, Rescope, widen and
// reject): narrowing the agent's proposal, and widening it to other agents'
// changes with the person's passkey proof bound to a new link secret the
// page makes. Postgres decides every check; the page only builds what it
// sends and checks what comes back, as for any revert request.
//
// What the page sends, and where:
// - A narrow posts only {select}, under the current link secret.
// - A widen first asks the passkey (no assertion, nothing is sent), then
//   posts {select, proof, newSecret} to the engine that served the page. The
//   new secret lives in the page's memory and that one body; it is never
//   shown, put in the address or sent anywhere else.
import { b64urlDecode, b64urlEncode, checkRevertRequest, CodeError, hex, sha256, utf8 } from "./codec.js";
import { postResponse, revertPaths } from "./local.js";

const RESCOPE_PREFIX = "basalt-rescope.1";
const RESCOPE_KEY_INFO = "basalt-rescope-key.1";
const RESCOPE_KEY_BITS = 256;
const SECRET_BYTES = 16;
const PROMPT_TIMEOUT_MS = 120000;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

// compareText orders strings by their UTF-8 bytes, as COLLATE "C" does.
function compareText(a, b) {
  const x = utf8(a);
  const y = utf8(b);
  for (let i = 0; i < Math.min(x.length, y.length); i++) {
    if (x[i] !== y[i]) return x[i] - y[i];
  }
  return x.length - y.length;
}

function normList(list, lower = false) {
  if (list === null) return null;
  const items = list.map((s) => (lower ? s.toLowerCase() : s));
  return [...new Set(items)].sort(compareText);
}

// selectText is a scope descriptor as Postgres normalizes it
// (basalt_meta._revert_select_norm, then jsonb's text): keys in jsonb's
// order (shorter first), lists sorted by their bytes and deduplicated, ids
// lowercase, ", " and ": " between items. The widen proof signs this text,
// so it must be the guard's byte for byte (shared fixtures).
export function selectText(select) {
  const value = {
    runs: normList(select.runs, true),
    scope: select.scope,
    agents: normList(select.agents),
    tables: normList(select.tables),
    scopeId: select.scopeId.toLowerCase(),
  };
  return "{" + Object.entries(value).map(([k, v]) => `${JSON.stringify(k)}: ${jsonText(v)}`).join(", ") + "}";
}

function jsonText(v) {
  if (Array.isArray(v)) return "[" + v.map((s) => JSON.stringify(s)).join(", ") + "]";
  return JSON.stringify(v);
}

// rescopeKey is HKDF-SHA-256 of the new link secret, salt empty, info
// "basalt-rescope-key.1", 32 bytes: what the engine sends Postgres instead
// of the secret.
export async function rescopeKey(secret) {
  const subtle = globalThis.crypto.subtle;
  const ikm = await subtle.importKey("raw", secret, "HKDF", false, ["deriveBits"]);
  const bits = await subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: utf8(RESCOPE_KEY_INFO) },
    ikm,
    RESCOPE_KEY_BITS,
  );
  return new Uint8Array(bits);
}

// widenChallenge is the challenge the person's passkey signs for a widen:
// sha256 of "basalt-rescope.1", the revert id, the nonce (base64url), the
// hex sha256 of the rescope key and the normalized select, one per line.
export async function widenChallenge(revertId, nonce, key, text) {
  const keyHash = hex(await sha256(key));
  return sha256(utf8([RESCOPE_PREFIX, revertId, nonce, keyHash, text].join("\n")));
}

// widenSelect is what "Include other agents' changes" asks for: every
// agent, run and table of the scope. The person narrows from there.
export function widenSelect(binding) {
  return { scope: binding.select.scope, scopeId: binding.select.scopeId, agents: null, runs: null, tables: null };
}

// canWiden: the page offers the widen for a task (a run or a change is one
// agent's already), only when it talks to the engine (relay) and the engine
// gave the nonce the proof must name, and only until the person widened.
export function canWiden(req, relay, catalog) {
  return relay !== null && catalog === null && req.rescopeNonce !== null && req.binding.select.scope === "TASK";
}

// newLinkSecret is the link secret the revert gets after a widen: 16
// random bytes, base64url.
export function newLinkSecret() {
  return b64urlEncode(globalThis.crypto.getRandomValues(new Uint8Array(SECRET_BYTES)));
}

// scopeBody is the body of POST …/scope (revert-scope-request.schema.json).
export function scopeBody(select, proof, newSecret) {
  if (!proof) return JSON.stringify({ select });
  return JSON.stringify({
    select,
    proof: {
      credentialId: b64urlEncode(proof.credentialId),
      authenticatorData: b64urlEncode(proof.authenticatorData),
      clientDataJson: b64urlEncode(proof.clientDataJson),
      signature: b64urlEncode(proof.signature),
    },
    newSecret,
  });
}

function catalogError(what) {
  return new CodeError(`the engine's catalog has a bad ${what}`);
}

function strictItems(list, what, keys, check) {
  if (!Array.isArray(list)) throw catalogError(what);
  return list.map((item) => {
    if (item === null || typeof item !== "object" || Object.keys(item).sort().join() !== [...keys].sort().join() || !check(item)) {
      throw catalogError(what);
    }
    return item;
  });
}

const count = (n) => Number.isInteger(n) && n >= 0;
const name = (s) => typeof s === "string" && s !== "";

// changeAgents checks the catalog's change id to agent map (basalt_meta
// version 32) and returns it as a Map.
function changeAgents(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw catalogError("change map");
  const out = new Map();
  for (const [id, agent] of Object.entries(value)) {
    if (!UUID.test(id) || !name(agent)) throw catalogError("change map");
    out.set(id, agent);
  }
  return out;
}

// parseCatalog checks the catalog a proven scope call returns
// (revert-scope-response.schema.json), or null when there is none.
export function parseCatalog(value) {
  if (value === undefined || value === null) return null;
  const keys = typeof value === "object" ? Object.keys(value).sort().join() : "";
  if (keys !== "agents,runs,tables" && keys !== "agents,changeAgents,runs,tables") throw catalogError("shape");
  return {
    changeAgents: keys === "agents,runs,tables" ? null : changeAgents(value.changeAgents),
    agents: strictItems(value.agents, "agent", ["agent", "changes"], (a) => name(a.agent) && count(a.changes)),
    runs: strictItems(value.runs, "run", ["runId", "agent", "startedAt", "changes"], (r) =>
      UUID.test(r.runId) && name(r.agent) && count(r.changes) && !Number.isNaN(Date.parse(r.startedAt)),
    ).map((r) => ({ ...r, startedAt: new Date(r.startedAt) })),
    tables: strictItems(value.tables, "table", ["table", "rows"], (t) => name(t.table) && count(t.rows)),
  };
}

// post sends a scope body and checks the answer: the request for this
// revert, hashing to its binding, and the catalog when there is one.
async function post(req, secret, fetchFn, body) {
  const out = await postResponse(fetchFn, revertPaths(req.revertId).scope, secret, body);
  const next = await checkRevertRequest(out?.request);
  if (next.revertId !== req.revertId) throw new CodeError(`the engine answered for another revert, ${next.revertId}`);
  return { req: next, catalog: parseCatalog(out.catalog) };
}

// narrow changes the scope within what needs no new proof: the agent's own
// work, or the person's widened scope (the engine adds its token).
export function narrow({ req, secret, fetchFn, select }) {
  return post(req, secret, fetchFn, scopeBody(select));
}

// widen asks the person's passkey for the widen proof and posts it with a
// new link secret. Nothing is sent unless the passkey signed. The answer
// carries the rebuilt request and the catalog; the page continues under
// the new secret, which it returns.
export async function widen({ req, rpId, secret, fetchFn, getAssertion }) {
  if (req.rescopeNonce === null) throw new CodeError("the engine gave no nonce for a widen");
  const newSecret = newLinkSecret();
  const key = await rescopeKey(b64urlDecode(newSecret));
  const select = widenSelect(req.binding);
  const challenge = await widenChallenge(req.revertId, req.rescopeNonce, key, selectText(select));
  const cred = await getAssertion({
    publicKey: {
      challenge,
      rpId,
      allowCredentials: req.credentialIds.map((id) => ({ type: "public-key", id })),
      userVerification: "required",
      timeout: PROMPT_TIMEOUT_MS,
    },
  });
  const r = cred.response;
  const proof = {
    credentialId: new Uint8Array(cred.rawId),
    authenticatorData: new Uint8Array(r.authenticatorData),
    clientDataJson: new Uint8Array(r.clientDataJSON),
    signature: new Uint8Array(r.signature),
  };
  const out = await post(req, secret, fetchFn, scopeBody(select, proof, newSecret));
  return { ...out, secret: newSecret };
}
