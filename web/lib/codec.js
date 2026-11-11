// Codecs for the approval, revert and passkey registration pages
// (CONTRACT.md, Approvals and Revert). Pure functions with no DOM access, so
// they run in the browser and under `node --test`. The Go side is
// internal/approval, internal/revert and internal/passkey; the tests read
// their testdata/fixtures.json.
//
// Rule: the binding text and the lines are hashed and parsed exactly as
// received, never re-serialized. Postgres built them; the passkey signs
// sha256 of the binding text's UTF-8 bytes.

export const PROD_RP_ID = "basaltvault.app";
export const PROD_ORIGIN = "https://basaltvault.app";

export const APPROVAL_REQUEST_PREFIX = "1.";
export const APPROVAL_RESPONSE_PREFIX = "basalt-approval.1.";
export const REGISTRATION_REQUEST_PREFIX = "1.";
export const REGISTRATION_RESPONSE_PREFIX = "basalt-passkey.1.";
export const REVERT_REQUEST_PREFIX = "1.";
export const REVERT_RESPONSE_PREFIX = "basalt-revert.1.";

export const KIND_APPROVE = "APPROVE";
export const MAX_ROWS = 50; // foundation, Default policy: over 50 rows is refused
export const KIND_REVERT = "REVERT";
export const MAX_REVERT_LINES = 1000; // decisions M3-9, N12-4: lines of a one-call revert, and lines a link carries
export const MAX_REVERT_BATCH = 200; // decision N12-3: lines per apply_revert_batch
export const REVERT_APPLY_HOURS = 24; // decision N12-2: a signed large plan runs within 24 hours
export const ALG_ES256 = -7;

const MAX_FRAGMENT_LENGTH = 1 << 20;
const MAX_INFLATED_BYTES = 1 << 20;
const CHALLENGE_BYTES = 32;
const USER_ID_BYTES = 16;
const MAX_LABEL_BYTES = 64;
const SHA256_HEX_LENGTH = 64;

export class CodeError extends Error {
  constructor(message) {
    super(message);
    this.name = "CodeError";
  }
}

// TruncatedLinkError is a link fragment that does not decode. Links carry
// the whole preview and run long; terminals wrap them and chats cut them,
// so a fragment that stops making sense was most likely cut short.
export class TruncatedLinkError extends CodeError {
  constructor(message) {
    super(message);
    this.name = "TruncatedLinkError";
  }
}

const B64URL = /^[A-Za-z0-9_-]*$/;
const HEX64 = /^[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

// base64url without padding (RFC 4648 §5), strict: no padding, no standard
// alphabet, no impossible lengths.
export function b64urlEncode(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function b64urlDecode(text) {
  if (typeof text !== "string" || !B64URL.test(text) || text.length % 4 === 1) {
    throw new CodeError("not base64url");
  }
  const bin = atob(text.replace(/-/g, "+").replace(/_/g, "/"));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  if (b64urlEncode(out) !== text) throw new CodeError("not canonical base64url");
  return out;
}

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

export function utf8(text) {
  return encoder.encode(text);
}

function fromUtf8(bytes) {
  try {
    return decoder.decode(bytes);
  } catch {
    throw new CodeError("not UTF-8");
  }
}

export async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}

export function hex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

// rowsHash: lowercase hex sha256 of the lines joined by "\n".
export async function rowsHash(lines) {
  return hex(await sha256(utf8(lines.join("\n"))));
}

// The WebAuthn challenge for a binding: sha256 of its UTF-8 bytes.
export async function challengeFor(bindingText) {
  return sha256(utf8(bindingText));
}

function parseJSON(text, what) {
  try {
    return JSON.parse(text);
  } catch {
    throw new CodeError(`${what} is not JSON`);
  }
}

// strictObject refuses anything but a plain object with exactly the allowed
// keys present, and all required keys set, like Go's DisallowUnknownFields.
function strictObject(value, what, required, optional = []) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new CodeError(`${what} is not an object`);
  }
  const allowed = new Set([...required, ...optional]);
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) throw new CodeError(`${what} has unknown field "${key}"`);
  }
  for (const key of required) {
    if (!(key in value)) throw new CodeError(`${what} is missing "${key}"`);
  }
  return value;
}

function requireString(value, what) {
  if (typeof value !== "string") throw new CodeError(`${what} is not a string`);
  return value;
}

function stripPrefix(text, prefix, what) {
  if (typeof text !== "string" || !text.startsWith(prefix)) {
    throw new CodeError(`${what} must start with "${prefix}"`);
  }
  const payload = text.slice(prefix.length);
  if (payload.length > MAX_FRAGMENT_LENGTH) throw new CodeError(`${what} is too long`);
  return payload;
}

async function inflateRaw(bytes, what) {
  const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream("deflate-raw"));
  const reader = stream.getReader();
  const chunks = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.length;
      if (total > MAX_INFLATED_BYTES) {
        await reader.cancel();
        throw new CodeError(`${what} inflates too far`);
      }
      chunks.push(value);
    }
  } catch (err) {
    if (err instanceof CodeError) throw err;
    throw new TruncatedLinkError(`${what} is not deflate-raw`);
  }
  const out = new Uint8Array(total);
  let at = 0;
  for (const c of chunks) {
    out.set(c, at);
    at += c.length;
  }
  return out;
}

// asTruncated runs one decoding step of a link fragment and reports its
// CodeError as a TruncatedLinkError.
function asTruncated(step) {
  try {
    return step();
  } catch (err) {
    if (err instanceof CodeError) throw new TruncatedLinkError(err.message);
    throw err;
  }
}

// decodeRequest decodes a link fragment, with or without '#':
// prefix + base64url(deflate-raw(json)), into an object with exactly the
// required and optional keys. A fragment that is empty or does not decode
// (base64url, deflate-raw, UTF-8, JSON) throws TruncatedLinkError.
async function decodeRequest(fragment, prefix, what, required, optional) {
  const text = String(fragment).replace(/^#/, "");
  if (prefix.startsWith(text)) throw new TruncatedLinkError(`${what} is empty`);
  const payload = stripPrefix(text, prefix, what);
  const compressed = asTruncated(() => b64urlDecode(payload));
  const raw = await inflateRaw(compressed, what);
  const json = asTruncated(() => parseJSON(fromUtf8(raw), what));
  return strictObject(json, what, required, optional);
}

function requireLineStrings(lines, what) {
  if (!Array.isArray(lines) || lines.some((l) => typeof l !== "string")) {
    throw new CodeError(`${what} lines must be strings`);
  }
}

function requireRowsHash(value, name = "rowsHash") {
  if (typeof value !== "string" || value.length !== SHA256_HEX_LENGTH || !HEX64.test(value)) {
    throw new CodeError(`binding ${name} is not a sha256 hex digest`);
  }
}

function parseExpiry(value) {
  const expires = new Date(value);
  if (Number.isNaN(expires.getTime())) throw new CodeError("binding expiresAt is not a time");
  return expires;
}

function decodeCredentialIds(ids) {
  return (ids ?? []).map((id) => b64urlDecode(requireString(id, "credential id")));
}

const BINDING_FIELDS = [
  "kind", "approvalId", "database", "agent", "runId", "intent", "statement",
  "params", "assignedColumns", "rows", "rowsHash", "expiresAt",
];

// parseBinding parses the binding text for display. The text itself is what
// gets signed.
export function parseBinding(text) {
  const b = strictObject(parseJSON(requireString(text, "binding"), "binding"), "binding", BINDING_FIELDS, ["taskId"]);
  if (b.kind !== KIND_APPROVE) throw new CodeError(`binding kind "${b.kind}"`);
  if (!Number.isInteger(b.rows) || b.rows < 1 || b.rows > MAX_ROWS) {
    throw new CodeError(`binding rows ${b.rows} out of 1..${MAX_ROWS}`);
  }
  requireRowsHash(b.rowsHash);
  if (!UUID.test(b.approvalId)) throw new CodeError("binding approvalId is not a uuid");
  if (!Array.isArray(b.params) || !Array.isArray(b.assignedColumns)) {
    throw new CodeError("binding params and assignedColumns must be arrays");
  }
  return { ...b, expiresAt: parseExpiry(b.expiresAt) };
}

const OPS = new Set(["INSERT", "UPDATE", "DELETE"]);

// parseLine parses one preview line for display.
export function parseLine(text) {
  const raw = parseJSON(requireString(text, "preview line"), "preview line");
  const redacted = raw !== null && typeof raw === "object" && raw.redacted === true;
  const l = redacted
    ? strictObject(raw, "preview line", ["op", "table", "rowHash", "cascaded", "redacted"])
    : strictObject(raw, "preview line", ["op", "key", "old", "set", "table", "cascaded"]);
  if (!OPS.has(l.op)) throw new CodeError(`preview line op "${l.op}"`);
  requireString(l.table, "preview line table");
  return {
    op: l.op,
    table: l.table,
    cascaded: l.cascaded === true,
    redacted,
    rowHash: redacted ? l.rowHash : null,
    key: redacted ? null : l.key,
    old: redacted ? null : l.old,
    set: redacted ? null : l.set,
  };
}

// parseApprovalRequest decodes and checks the approval link fragment, with or
// without '#': same approval in request and binding, one line per row, and
// the lines hash to the binding's rowsHash. Only then may the page ask for a
// signature.
export async function parseApprovalRequest(fragment) {
  return checkApprovalRequest(await decodeRequest(fragment, APPROVAL_REQUEST_PREFIX, "approval request", APPROVAL_REQUEST_FIELDS, ["credentialIds"]));
}

const APPROVAL_REQUEST_FIELDS = ["approvalId", "binding", "lines"];

// checkApprovalRequest checks a decoded approval request, from a link
// fragment or from the engine's local pages (GET /api/v1/approvals/{id}),
// exactly as parseApprovalRequest does.
export async function checkApprovalRequest(value) {
  const req = strictObject(value, "approval request", APPROVAL_REQUEST_FIELDS, ["credentialIds"]);
  const binding = parseBinding(req.binding);
  if (req.approvalId !== binding.approvalId) {
    throw new CodeError(`request is for approval ${req.approvalId}, binding for ${binding.approvalId}`);
  }
  requireLineStrings(req.lines, "approval request");
  if (req.lines.length !== binding.rows) {
    throw new CodeError(`request has ${req.lines.length} lines, binding ${binding.rows} rows`);
  }
  if ((await rowsHash(req.lines)) !== binding.rowsHash) {
    throw new CodeError("preview lines do not match the binding's rowsHash");
  }
  return {
    approvalId: req.approvalId,
    bindingText: req.binding,
    binding,
    lines: req.lines.map(parseLine),
    credentialIds: decodeCredentialIds(req.credentialIds),
    challenge: await challengeFor(req.binding),
  };
}

// encodeApprovalResponse builds the code the person copies. Keys in the
// contract's order, so Go and the page produce the same text.
export function encodeApprovalResponse(response) {
  return APPROVAL_RESPONSE_PREFIX + b64urlEncode(utf8(approvalResponseJSON(response)));
}

// approvalResponseJSON is the JSON an approval code carries, which the page
// posts to the engine's relay (POST /api/v1/approvals/{id}/approve).
export function approvalResponseJSON({ approvalId, ...assertion }) {
  return assertionJSON({ approvalId }, assertion);
}

// assertionJSON is a response's JSON with the id first and the assertion's
// byte fields after it, in the contract's order.
function assertionJSON(id, { credentialId, authenticatorData, clientDataJson, signature }) {
  return JSON.stringify({
    ...id,
    credentialId: b64urlEncode(credentialId),
    authenticatorData: b64urlEncode(authenticatorData),
    clientDataJson: b64urlEncode(clientDataJson),
    signature: b64urlEncode(signature),
  });
}

const REVERT_BINDING_FIELDS = [
  "kind", "revertId", "database", "scope", "scopeId", "agents", "intent",
  "rows", "skipped", "rowsHash", "expiresAt", "requestedBy",
];
const REVERT_SCOPES = new Set(["CHANGE", "RUN", "TASK"]);
const REVERT_ACTIONS = new Set(["RESTORE", "SKIP"]);
const REVERT_CONFLICTS = new Set([
  "CHANGED_AFTER", "ROW_GONE", "KEY_TAKEN", "ALREADY_REVERTED",
  "VALUES_PRUNED", "SCHEMA_CHANGED", "CASCADE", "CONSTRAINT",
]);

// parseRevertBinding parses a revert binding text for display. The text
// itself is what gets signed.
export function parseRevertBinding(text) {
  const b = strictObject(parseJSON(requireString(text, "binding"), "binding"), "binding", REVERT_BINDING_FIELDS, ["batched", "sampleHash"]);
  if (b.kind !== KIND_REVERT) throw new CodeError(`binding kind "${b.kind}"`);
  if (!REVERT_SCOPES.has(b.scope)) throw new CodeError(`binding scope "${b.scope}"`);
  if (!UUID.test(b.revertId) || !UUID.test(b.scopeId)) throw new CodeError("binding revertId and scopeId must be uuids");
  if (!Array.isArray(b.agents) || b.agents.length === 0) throw new CodeError("binding names no agents");
  if (!Number.isInteger(b.rows) || b.rows < 1) throw new CodeError(`binding rows ${b.rows}: a revert restores at least one row`);
  if (!Number.isInteger(b.skipped) || b.skipped < 0) throw new CodeError(`binding skipped ${b.skipped}`);
  requireRowsHash(b.rowsHash);
  const lines = b.rows + b.skipped;
  if ("batched" in b) {
    // A large plan (decision N12-1): signed once, applied in batches.
    if (b.batched !== true) throw new CodeError("binding batched must be true when present");
    if (lines <= MAX_REVERT_LINES) {
      throw new CodeError(`batched binding with ${lines} lines: only a plan of more than ${MAX_REVERT_LINES} lines is batched`);
    }
    requireRowsHash(b.sampleHash, "sampleHash");
    return { ...b, expiresAt: parseExpiry(b.expiresAt) };
  }
  if ("sampleHash" in b) throw new CodeError("binding has a sampleHash but is not batched");
  if (lines > MAX_REVERT_LINES) {
    throw new CodeError(`binding lines ${lines} out of 1..${MAX_REVERT_LINES}; a larger plan is batched`);
  }
  return { ...b, batched: false, expiresAt: parseExpiry(b.expiresAt) };
}

// parseRevertLine parses one revert line for display and checks that a
// RESTORE line has no conflict and a SKIP line names one.
export function parseRevertLine(text) {
  const raw = parseJSON(requireString(text, "revert line"), "revert line");
  const redacted = raw !== null && typeof raw === "object" && raw.redacted === true;
  const l = redacted
    ? strictObject(raw, "revert line", ["op", "table", "action", "rowHash", "cascaded", "conflict", "redacted", "changeIds"])
    : strictObject(raw, "revert line", ["op", "key", "now", "set", "table", "action", "cascaded", "conflict", "sqlState", "changeIds"]);
  if (!OPS.has(l.op)) throw new CodeError(`revert line op "${l.op}"`);
  requireString(l.table, "revert line table");
  if (!Array.isArray(l.changeIds) || l.changeIds.length === 0) throw new CodeError("revert line names no change");
  if (!REVERT_ACTIONS.has(l.action)) throw new CodeError(`revert line action "${l.action}"`);
  if (l.action === "RESTORE" && l.conflict !== null) throw new CodeError(`RESTORE line with conflict "${l.conflict}"`);
  if (l.action === "SKIP" && !REVERT_CONFLICTS.has(l.conflict)) throw new CodeError("SKIP line without a known conflict");
  return {
    op: l.op,
    table: l.table,
    action: l.action,
    conflict: l.conflict,
    sqlState: redacted ? null : l.sqlState,
    cascaded: l.cascaded === true,
    changeIds: l.changeIds,
    redacted,
    rowHash: redacted ? l.rowHash : null,
    key: redacted ? null : l.key,
    now: redacted ? null : l.now,
    set: redacted ? null : l.set,
  };
}

// parseRevertRequest decodes and checks the revert link fragment, with or
// without '#': same revert in request and binding, one line per row, as many
// RESTORE lines as the binding's rows, and the lines hash to rowsHash. Only
// then may the page ask for a signature.
export async function parseRevertRequest(fragment) {
  return checkRevertRequest(await decodeRequest(fragment, REVERT_REQUEST_PREFIX, "revert request", REVERT_REQUEST_FIELDS, ["credentialIds"]));
}

const REVERT_REQUEST_FIELDS = ["revertId", "binding", "lines"];

// checkRevertRequest checks a decoded revert request, from a link fragment
// or from the engine's local pages, exactly as parseRevertRequest does.
export async function checkRevertRequest(value) {
  const req = strictObject(value, "revert request", REVERT_REQUEST_FIELDS, ["credentialIds"]);
  const binding = parseRevertBinding(req.binding);
  if (req.revertId !== binding.revertId) {
    throw new CodeError(`request is for revert ${req.revertId}, binding for ${binding.revertId}`);
  }
  requireLineStrings(req.lines, "revert request");
  const lines = binding.batched ? await checkSample(req.lines, binding) : await checkAllLines(req.lines, binding);
  return {
    revertId: req.revertId,
    bindingText: req.binding,
    binding,
    lines,
    credentialIds: decodeCredentialIds(req.credentialIds),
    challenge: await challengeFor(req.binding),
  };
}

// checkAllLines: a one-call revert's request carries every line, hashing to
// rowsHash, with as many RESTORE lines as the binding's rows.
async function checkAllLines(texts, binding) {
  const total = binding.rows + binding.skipped;
  if (texts.length !== total) {
    throw new CodeError(`request has ${texts.length} lines, binding ${total}`);
  }
  if ((await rowsHash(texts)) !== binding.rowsHash) {
    throw new CodeError("revert lines do not match the binding's rowsHash");
  }
  const lines = texts.map(parseRevertLine);
  const restore = lines.filter((l) => l.action === "RESTORE").length;
  if (restore !== binding.rows) {
    throw new CodeError(`request has ${restore} RESTORE lines, binding ${binding.rows} rows`);
  }
  return lines;
}

// checkSample: a large plan's request carries its sample (decision N12-4):
// the first MAX_REVERT_LINES lines, SKIP lines first, hashing to sampleHash.
// The signature still covers every line through rowsHash.
async function checkSample(texts, binding) {
  if (texts.length !== MAX_REVERT_LINES) {
    throw new CodeError(`request has ${texts.length} lines, a batched plan's sample has ${MAX_REVERT_LINES}`);
  }
  if ((await rowsHash(texts)) !== binding.sampleHash) {
    throw new CodeError("revert lines do not match the binding's sampleHash");
  }
  const lines = texts.map(parseRevertLine);
  const found = lines.findIndex((l) => l.action === "RESTORE");
  const skips = found === -1 ? lines.length : found;
  if (lines.slice(skips).some((l) => l.action === "SKIP")) {
    throw new CodeError("the sample must list SKIP lines before RESTORE lines");
  }
  const want = Math.min(binding.skipped, MAX_REVERT_LINES);
  if (skips !== want) {
    throw new CodeError(`request has ${skips} SKIP lines, the binding's sample ${want}`);
  }
  return lines;
}

// encodeRevertResponse builds the code the person pastes into basalt revert.
export function encodeRevertResponse(response) {
  return REVERT_RESPONSE_PREFIX + b64urlEncode(utf8(revertResponseJSON(response)));
}

// revertResponseJSON is the JSON a revert code carries, which the page posts
// to the engine's relay (POST /api/v1/reverts/{id}/apply).
export function revertResponseJSON({ revertId, ...assertion }) {
  return assertionJSON({ revertId }, assertion);
}

function checkLabel(label, what) {
  requireString(label, what);
  const n = utf8(label).length;
  if (n === 0 || n > MAX_LABEL_BYTES) throw new CodeError(`${what} must be 1 to ${MAX_LABEL_BYTES} bytes`);
  return label;
}

// parseRegistrationRequest decodes the registration link fragment.
export function parseRegistrationRequest(fragment) {
  const payload = stripPrefix(String(fragment).replace(/^#/, ""), REGISTRATION_REQUEST_PREFIX, "registration request");
  const json = fromUtf8(b64urlDecode(payload));
  const req = strictObject(parseJSON(json, "registration request"), "registration request", ["challenge", "userId", "userName", "displayName"]);
  const challenge = b64urlDecode(requireString(req.challenge, "challenge"));
  const userId = b64urlDecode(requireString(req.userId, "userId"));
  if (challenge.length !== CHALLENGE_BYTES || userId.length !== USER_ID_BYTES) {
    throw new CodeError(`registration request needs a ${CHALLENGE_BYTES}-byte challenge and a ${USER_ID_BYTES}-byte user id`);
  }
  return {
    challenge,
    userId,
    userName: checkLabel(req.userName, "userName"),
    displayName: checkLabel(req.displayName, "displayName"),
  };
}

// encodeRegistrationResponse builds the code basalt init reads.
export function encodeRegistrationResponse({ credentialId, clientDataJson, authenticatorData, publicKey, publicKeyAlgorithm }) {
  if (publicKeyAlgorithm !== ALG_ES256) throw new CodeError("the passkey must use ES256");
  const json = JSON.stringify({
    credentialId: b64urlEncode(credentialId),
    clientDataJson: b64urlEncode(clientDataJson),
    authenticatorData: b64urlEncode(authenticatorData),
    publicKey: b64urlEncode(publicKey),
    publicKeyAlgorithm,
  });
  return REGISTRATION_RESPONSE_PREFIX + b64urlEncode(utf8(json));
}

// relyingParty returns the RP ID and origin for the page's location:
// basaltvault.app over HTTPS, or http://localhost:<port> for development.
// Anywhere else the pages refuse to run.
export function relyingParty(loc) {
  if (loc.protocol === "https:" && loc.hostname === PROD_RP_ID && loc.port === "") {
    return { rpId: PROD_RP_ID, origin: PROD_ORIGIN };
  }
  if (loc.protocol === "http:" && loc.hostname === "localhost" && loc.port !== "") {
    return { rpId: "localhost", origin: `http://localhost:${loc.port}` };
  }
  throw new CodeError(`this page only runs at ${PROD_ORIGIN}`);
}
