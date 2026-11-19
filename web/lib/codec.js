// Codecs for the approval, revert and passkey registration pages
// (CONTRACT.md, Approvals and Revert). Pure functions with no DOM access, so
// they run in the browser and under `node --test`. The Go side is
// internal/approval, internal/revert and internal/passkey; the tests read
// their testdata/fixtures.json.
//
// Rule: the binding text and the lines are hashed and parsed exactly as
// received, never re-serialized. Postgres built them; the passkey signs
// sha256 of the binding text's UTF-8 bytes. A format 2 link carries them in
// compact form, rebuilt byte for byte by compact.js before anything else.

import { CompactError, rebuildTexts } from "./compact.js";
import { DeflateError, deflateEnd } from "./deflate.js";

// The portal and its passkeys' RP ID (owner decisions, Decided
// Nov 12): RP ID basaltvault.app never changes. Until hosting exists the
// pages run on the engine's local pages, http://localhost:<port>.
export const PROD_RP_ID = "basaltvault.app";
export const PORTAL = "https://portal.basaltvault.app";

// Approval and revert links: format 2 (the compact request) is what the
// engine writes; format 1 is still read.
export const REQUEST_FORMAT_1 = "1.";
export const REQUEST_FORMAT_2 = "2.";
const REQUEST_FORMATS = [REQUEST_FORMAT_1, REQUEST_FORMAT_2];
export const APPROVAL_RESPONSE_PREFIX = "basalt-approval.1.";
export const REGISTRATION_REQUEST_PREFIX = "1.";
export const REGISTRATION_RESPONSE_PREFIX = "basalt-passkey.1.";
export const REVERT_RESPONSE_PREFIX = "basalt-revert.1.";

export const KIND_APPROVE = "APPROVE";
export const MAX_ROWS = 50; // foundation, Default policy: over 50 rows is refused
export const KIND_REVERT = "REVERT";
export const MAX_REVERT_LINES = 1000; // decisions M3-9, N12-4, RSS-1: lines of a one-call revert, and lines a link carries
export const REVERT_SAMPLE_SHARE = MAX_REVERT_LINES / 2; // decision RSS-1: room a sample keeps for each kind of line
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
const NONCE = /^[A-Za-z0-9_-]{22}$/;
const NONCE_BYTES = 16;

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
// ignoreBOM keeps a leading BOM, so JSON.parse refuses it as Go does.
const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

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
  // Refuse bytes after the deflate stream ourselves: not every
  // DecompressionStream refuses them.
  let end;
  try {
    end = deflateEnd(bytes);
  } catch (err) {
    if (err instanceof DeflateError) throw new TruncatedLinkError(`${what} is not deflate-raw`);
    throw err;
  }
  if (end !== bytes.length) throw new CodeError(`${what} has data after the end of its deflate stream`);
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

// decodeRequest decodes an approval or revert link fragment, with or
// without '#', in either format: format + base64url(deflate-raw(json)). It
// returns the format 1 request, an object with exactly the required and
// optional keys; for format 2 it rebuilds the binding text and at most
// maxLines lines, and takes the id (idKey) from the binding. A fragment that
// is empty or does not decode (base64url, deflate-raw, UTF-8, JSON) throws
// TruncatedLinkError.
async function decodeRequest(fragment, what, { idKey, maxLines, required, optional, parse }) {
  const text = String(fragment).replace(/^#/, "");
  if (REQUEST_FORMATS.some((f) => f.startsWith(text))) throw new TruncatedLinkError(`${what} is empty`);
  const format = REQUEST_FORMATS.find((f) => text.startsWith(f));
  if (format === undefined) throw new CodeError(`${what} must start with "${REQUEST_FORMAT_1}" or "${REQUEST_FORMAT_2}"`);
  const payload = stripPrefix(text, format, what);
  const compressed = asTruncated(() => b64urlDecode(payload));
  const raw = await inflateRaw(compressed, what);
  const json = asTruncated(() => parseJSON(fromUtf8(raw), what));
  if (format === REQUEST_FORMAT_1) return strictObject(json, what, required, optional);
  return expandCompact(json, what, idKey, maxLines, parse);
}

// expandCompact turns a format 2 payload into the format 1 request: the
// first text is the binding, the rest are the lines. The check that
// follows parses the binding again and refuses it there.
function expandCompact(json, what, idKey, maxLines, parse) {
  // The binding travels as the first text.
  const texts = Array.isArray(json) && Array.isArray(json[1]) ? json[1] : [];
  if (texts.length > maxLines + 1) throw new CodeError(`${what} has ${texts.length - 1} lines, at most ${maxLines}`);
  let rebuilt;
  try {
    rebuilt = rebuildTexts(json, maxLines + 1);
  } catch (err) {
    if (err instanceof CompactError) throw new CodeError(`${what} ${err.message}`);
    throw err;
  }
  if (rebuilt.length < 2) throw new CodeError(`${what} has no lines after its binding`);
  const [binding, ...lines] = rebuilt;
  let id = null;
  try {
    id = parse(binding)[idKey];
  } catch {
    // check*Request parses the binding again and reports why.
  }
  const ids = linkCredentialIds(json, what);
  return ids === null ? { [idKey]: id, binding, lines } : { [idKey]: id, binding, lines, credentialIds: ids };
}

// MAX_LINK_CREDENTIAL_IDS caps the credential ids a format 2 link carries:
// the bound the relays read the database's passkeys with.
const MAX_LINK_CREDENTIAL_IDS = 100;
const MAX_CREDENTIAL_ID_BYTES = 1023;

// linkCredentialIds reads a format 2 payload's optional third element: the
// database's credential ids, 1 to 100 distinct base64url ids of 1 to 1023
// bytes, which the page passes as allowCredentials. null when absent.
function linkCredentialIds(json, what) {
  if (json.length < 3) return null;
  const ids = json[2];
  if (!Array.isArray(ids) || ids.length === 0 || ids.length > MAX_LINK_CREDENTIAL_IDS) {
    throw new CodeError(`${what} credentialIds must list 1 to ${MAX_LINK_CREDENTIAL_IDS} ids`);
  }
  if (new Set(ids).size !== ids.length) throw new CodeError(`${what} credentialIds names an id twice`);
  for (const id of ids) {
    const raw = b64urlDecode(requireString(id, "credential id"));
    if (raw.length === 0 || raw.length > MAX_CREDENTIAL_ID_BYTES) {
      throw new CodeError(`${what} has a credential id of ${raw.length} bytes`);
    }
  }
  return ids;
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

// JSON_SPACE is the whitespace JSON allows between tokens.
const JSON_SPACE = " \t\n\r";

function skipSpace(s, i) {
  while (i < s.length && JSON_SPACE.includes(s[i])) i++;
  return i;
}

// stringEnd returns the index after the JSON string starting at i.
function stringEnd(s, i) {
  for (let j = i + 1; j < s.length; j++) {
    if (s[j] === "\\") j++;
    else if (s[j] === '"') return j + 1;
  }
  return s.length;
}

// valueEnd returns the index after the JSON value starting at i.
function valueEnd(s, i) {
  if (s[i] === '"') return stringEnd(s, i);
  let depth = 0;
  for (let j = i; j < s.length; j++) {
    const c = s[j];
    if (c === '"') {
      j = stringEnd(s, j) - 1;
    } else if (c === "{" || c === "[") {
      depth++;
    } else if (c === "}" || c === "]") {
      if (depth === 0) return j;
      depth--;
      if (depth === 0) return j + 1;
    } else if (c === "," && depth === 0) {
      return j;
    }
  }
  return s.length;
}

// memberTexts returns the members of a JSON object's text, each value as its
// exact text. Only for text JSON.parse has already accepted.
export function memberTexts(text) {
  const out = new Map();
  let i = skipSpace(text, 0) + 1;
  for (;;) {
    i = skipSpace(text, i);
    if (i >= text.length || text[i] !== '"') return out;
    const keyEnd = stringEnd(text, i);
    const key = JSON.parse(text.slice(i, keyEnd));
    i = skipSpace(text, keyEnd) + 1;
    i = skipSpace(text, i);
    const end = valueEnd(text, i);
    out.set(key, text.slice(i, end).trim());
    i = skipSpace(text, end);
    if (text[i] === ",") i++;
  }
}

// valueTexts returns, for each object member of a line (key, old, set,
// now), its columns' values as their exact text, so a page shows a number
// as Postgres printed it (JSON.parse rounds integers past 2^53).
export function valueTexts(text) {
  const out = {};
  for (const [name, value] of memberTexts(text)) {
    if (value.startsWith("{")) out[name] = memberTexts(value);
  }
  return out;
}

// displayValue is a column's value as the page shows it: a string as it is,
// anything else as the exact text the line carries.
export function displayValue(value, text) {
  if (value === undefined) return "";
  if (typeof value === "string") return value;
  return text ?? JSON.stringify(value);
}

// paramsText is a binding's params as the exact text the passkey signs, so
// the page shows 9007199254740993 and 1e400 as they are (JSON.parse turns
// them into 9007199254740992 and Infinity, which JSON.stringify prints as
// null). Only for a binding parseBinding has accepted.
export function paramsText(bindingText) {
  return memberTexts(bindingText).get("params") ?? "[]";
}

// HIDDEN matches what hides text or changes how it reads: controls (C0, DEL,
// C1), format characters (bidi controls such as U+202E, zero-width
// characters), line and paragraph separators, spaces other than U+0020,
// lone surrogates and every default-ignorable character (variation
// selectors such as U+FE0F and U+E0100, Mongolian ones such as U+180B,
// Hangul fillers). The CLI escapes the same set (cmd/basalt, visibleText).
const HIDDEN = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Cs}\p{Default_Ignorable_Code_Point}\u00a0\u1680\u2000-\u200a\u202f\u205f\u3000]/u;
const MARK = /\p{M}/u;

// MAX_MARKS is how many combining marks in a row show as marks; the rest
// are escaped, so a stack of hundreds cannot paint over the cells around it.
const MAX_MARKS = 2;

function escapeHidden(c) {
  return `<U+${c.codePointAt(0).toString(16).toUpperCase().padStart(4, "0")}>`;
}

// visibleText shows text an agent wrote (values, table names, the intent)
// as it is, except each character HIDDEN matches and each combining mark
// after the first MAX_MARKS in a row, shown as <U+XXXX>: 0001 with a U+202E
// in it cannot read as 1000, and a zero-width space or a no-break space
// shows. With lines set, line feeds and tabs stay (the statement keeps its
// layout).
export function visibleText(text, { lines = false } = {}) {
  let out = "";
  let marks = 0;
  for (const c of String(text)) {
    if (HIDDEN.test(c)) {
      out += lines && (c === "\n" || c === "\t") ? c : escapeHidden(c);
      marks = 0;
      continue;
    }
    marks = MARK.test(c) ? marks + 1 : 0;
    out += marks > MAX_MARKS ? escapeHidden(c) : c;
  }
  return out;
}

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
    texts: redacted ? null : valueTexts(text),
  };
}

// parseApprovalRequest decodes and checks the approval link fragment, with or
// without '#': same approval in request and binding, one line per row, and
// the lines hash to the binding's rowsHash. Only then may the page ask for a
// signature.
export async function parseApprovalRequest(fragment) {
  return checkApprovalRequest(await decodeRequest(fragment, "approval request", {
    idKey: "approvalId", maxLines: MAX_ROWS, required: APPROVAL_REQUEST_FIELDS, optional: ["credentialIds"], parse: parseBinding,
  }));
}

const APPROVAL_REQUEST_FIELDS = ["approvalId", "binding", "lines"];

// checkApprovalRequest checks a decoded approval request, from a link
// fragment or from the engine's local pages (GET /api/v1/approvals/{id}),
// exactly as parseApprovalRequest does. The engine may also send
// revealNonce; a long link never carries it.
export async function checkApprovalRequest(value) {
  const req = strictObject(value, "approval request", APPROVAL_REQUEST_FIELDS, ["credentialIds", "revealNonce", "columns"]);
  const revealNonce = checkNonce(req, "revealNonce", "approval request");
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
    revealNonce,
    columns: checkColumns(req, "approval request"),
    challenge: await challengeFor(req.binding),
  };
}

// checkColumns reads the optional, unsigned column order the engine serves
// for the page's display (CONTRACT.md, Local pages): table name to its
// column names in table order, each name once (the first place it is
// listed). A Map; empty when absent.
function checkColumns(req, what) {
  const out = new Map();
  if (!("columns" in req)) return out;
  const cols = req.columns;
  if (cols === null || typeof cols !== "object" || Array.isArray(cols)) throw new CodeError(`${what} columns is not an object`);
  for (const [table, names] of Object.entries(cols)) {
    if (!Array.isArray(names) || names.some((n) => typeof n !== "string" || n === "")) {
      throw new CodeError(`${what} columns of "${table}" is not a list of names`);
    }
    out.set(table, [...new Set(names)]);
  }
  return out;
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
  "kind", "revertId", "database", "select", "widened", "intent",
  "rows", "skipped", "rowsHash", "expiresAt", "requestedBy",
];
const REVERT_SELECT_FIELDS = ["scope", "scopeId", "agents", "runs", "tables"];
const REVERT_SCOPES = new Set(["CHANGE", "RUN", "TASK"]);
// Runs and tables a scope descriptor lists at most (owner, Q10).
const MAX_REVERT_FILTER = 20;
const REVERT_ACTIONS = new Set(["RESTORE", "SKIP"]);
const REVERT_CONFLICTS = new Set([
  "CHANGED_AFTER", "ROW_GONE", "KEY_TAKEN", "ALREADY_REVERTED",
  "VALUES_PRUNED", "SCHEMA_CHANGED", "CASCADE", "CONSTRAINT",
]);

// parseRevertSelect checks a scope descriptor (CONTRACT.md, The scope
// descriptor): the binding's select or proposed. null lists mean all.
function parseRevertSelect(value, what) {
  const s = strictObject(value, what, REVERT_SELECT_FIELDS);
  if (!REVERT_SCOPES.has(s.scope)) throw new CodeError(`${what} scope "${s.scope}"`);
  if (!UUID.test(s.scopeId)) throw new CodeError(`${what} scopeId must be a uuid`);
  for (const key of ["agents", "runs", "tables"]) {
    const list = s[key];
    if (list === null) continue;
    if (!Array.isArray(list) || list.length === 0 || !list.every((x) => typeof x === "string" && x !== "")) {
      throw new CodeError(`${what} ${key} must be null or a list of at least one`);
    }
    if (key !== "agents" && list.length > MAX_REVERT_FILTER) {
      throw new CodeError(`${what} lists more than ${MAX_REVERT_FILTER} ${key}`);
    }
  }
  if (s.runs !== null && s.scope !== "TASK") throw new CodeError(`${what} lists runs for a ${s.scope} scope`);
  return s;
}

// parseRevertBinding parses a revert binding text for display. The text
// itself is what gets signed.
export function parseRevertBinding(text) {
  const b = strictObject(parseJSON(requireString(text, "binding"), "binding"), "binding", REVERT_BINDING_FIELDS,
    ["proposed", "agentRows", "batched", "sampleHash"]);
  if (b.kind !== KIND_REVERT) throw new CodeError(`binding kind "${b.kind}"`);
  if (!UUID.test(b.revertId)) throw new CodeError("binding revertId must be a uuid");
  parseRevertSelect(b.select, "binding select");
  if ("proposed" in b) parseRevertSelect(b.proposed, "binding proposed");
  const widened = b.select.agents === null || b.select.agents.some((a) => a !== b.requestedBy);
  if (b.widened !== widened) throw new CodeError(`binding widened ${b.widened} does not match its select and requestedBy`);
  if (widened !== ("agentRows" in b)) throw new CodeError("binding agentRows goes with widened, and only with it");
  if (!Number.isInteger(b.skipped) || b.skipped < 0) throw new CodeError(`binding skipped ${b.skipped}`);
  // A task proposal with no line of the agent's own is stored for the
  // person to widen; it has nothing to sign as it is.
  const empty = b.select.scope === "TASK" && b.rows === 0 && b.skipped === 0 && !("batched" in b);
  if (!Number.isInteger(b.rows) || (b.rows < 1 && !empty)) throw new CodeError(`binding rows ${b.rows}: a revert restores at least one row`);
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
    texts: redacted ? null : valueTexts(text),
  };
}

// parseRevertRequest decodes and checks the revert link fragment, with or
// without '#': same revert in request and binding, one line per row, as many
// RESTORE lines as the binding's rows, and the lines hash to rowsHash. Only
// then may the page ask for a signature.
export async function parseRevertRequest(fragment) {
  return checkRevertRequest(await decodeRequest(fragment, "revert request", {
    idKey: "revertId", maxLines: MAX_REVERT_LINES, required: REVERT_REQUEST_FIELDS, optional: ["credentialIds"], parse: parseRevertBinding,
  }));
}

const REVERT_REQUEST_FIELDS = ["revertId", "binding", "lines"];

// checkRevertRequest checks a decoded revert request, from a link fragment
// or from the engine's local pages, exactly as parseRevertRequest does. The
// engine may also send rescopeNonce, the nonce of the next widen proof, and
// revealNonce, the nonce of a reveal proof; a long link carries neither
// (decodeRequest refuses them there).
export async function checkRevertRequest(value) {
  const req = strictObject(value, "revert request", REVERT_REQUEST_FIELDS, ["credentialIds", "rescopeNonce", "revealNonce", "columns"]);
  const rescopeNonce = checkNonce(req, "rescopeNonce", "revert request");
  const revealNonce = checkNonce(req, "revealNonce", "revert request");
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
    rescopeNonce,
    revealNonce,
    columns: checkColumns(req, "revert request"),
    challenge: await challengeFor(req.binding),
  };
}

// checkNonce reads an optional nonce the engine serves (rescopeNonce,
// revealNonce): exactly 16 bytes, canonical base64url. null when absent.
function checkNonce(req, key, what) {
  if (!(key in req)) return null;
  if (typeof req[key] !== "string" || !NONCE.test(req[key]) || !decodesTo(req[key], NONCE_BYTES)) {
    throw new CodeError(`${what} has a bad ${key}`);
  }
  return req[key];
}

// decodesTo reports whether text is canonical base64url of exactly n bytes.
function decodesTo(text, n) {
  try {
    return b64urlDecode(text).length === n;
  } catch {
    return false;
  }
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

// revertSampleCounts is how many SKIP and RESTORE lines a batched plan's
// sample carries, from the signed binding's skipped and rows: up to
// REVERT_SAMPLE_SHARE of each, and when one kind has fewer the other fills
// the rest, at most MAX_REVERT_LINES (decision RSS-1, amending N12-4). Same as
// revert.SampleCounts in Go.
export function revertSampleCounts(skipped, rows) {
  const skips = Math.min(skipped, Math.max(REVERT_SAMPLE_SHARE, MAX_REVERT_LINES - rows));
  return { skips, restores: Math.min(rows, MAX_REVERT_LINES - skips) };
}

// revertShown is what a checked revert request shows and hides, for the
// page's "x of N shown" lines. Every number comes from signed data: the
// totals from the binding, the shown counts from the lines, which hash to
// rowsHash (one call) or sampleHash (a batched plan). The request carries
// nothing else the page could count from.
export function revertShown(req) {
  const restoreShown = req.lines.filter((l) => l.action === "RESTORE").length;
  const skipShown = req.lines.length - restoreShown;
  return {
    restoreShown,
    skipShown,
    restoreHidden: req.binding.rows - restoreShown,
    skipHidden: req.binding.skipped - skipShown,
  };
}

// checkSample: a large plan's request carries its sample (decisions N12-4,
// RSS-1): MAX_REVERT_LINES lines, SKIP lines first, as many of each kind as
// revertSampleCounts gives, hashing to sampleHash. The signature still
// covers every line through rowsHash.
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
  const want = revertSampleCounts(binding.skipped, binding.rows).skips;
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

// Plugin approvals (CONTRACT.md, Plugins, What a plugin approval binds and
// The plugin approval page). The link carries two texts, the binding and
// the settings; the page checks the binding against binding.schema.json,
// strictly at every depth, and the settings against settingsSha256, before
// it shows anything. Same as internal/approval/plugin.go, which checks less:
// the page is where a person reads the binding.
export const KIND_PLUGIN = "PLUGIN";
export const PLUGIN_RESPONSE_PREFIX = "basalt-plugin.1.";

// Why a plugin approval link is refused, when the page names the reason:
// a binding of another kind, or settings that do not hash to
// settingsSha256 (the vectors' expect.error).
export const WRONG_KIND = "WRONG_KIND";
export const SETTINGS_MISMATCH = "SETTINGS_MISMATCH";

export class PluginLinkError extends CodeError {
  constructor(reason, message) {
    super(message);
    this.name = "PluginLinkError";
    this.reason = reason;
  }
}

const PLUGIN_BINDING_REQUIRED = [
  "kind", "approvalId", "database", "expiresAt", "requestedBy", "agents", "name", "instance",
  "version", "manifestSha256", "settingsSha256", "hooks", "egress", "endpoint", "signer",
];
const PLUGIN_BINDING_OPTIONAL = ["roles", "isolation", "signerKeyId", "change"];
const PLUGIN_CHANGE_KEYS = [
  "fromVersion", "fromManifestSha256", "hooksAdded", "hooksRemoved", "rolesAdded", "rolesRemoved",
  "egressAdded", "egressRemoved", "fromEndpoint", "fromIsolation", "fromSigner", "agentsAdded",
  "agentsRemoved", "settingsChanged",
];
const PLUGIN_SETTINGS_KEYS = ["config", "auth", "timeoutMs", "minConfidence"];
export const PLUGIN_HOOKS = new Set(["approval.deliver", "classify.suggest", "feed.observe", "wire.detect"]);
const PLUGIN_ROLES = new Set(["NAME_CUE", "VALUE"]);
export const SIGNER_KNOWN = "KNOWN";
export const SIGNER_UNKNOWN = "UNKNOWN";
const SIGNERS = new Set([SIGNER_KNOWN, SIGNER_UNKNOWN]);
export const ENDPOINT_LOCAL = "LOCAL";
export const ENDPOINT_REMOTE = "REMOTE";
const ISOLATION_FILES = new Set(["OS_USER", "NONE"]);
const ISOLATION_NETWORK = new Set(["ENFORCED", "DECLARED", "NOT_ENFORCED"]);
const WIRE_DETECT = "wire.detect";

const ROLE_NAME = /^[a-z_][a-z0-9_]*$/;
const MAX_ROLE_NAME = 63;
const PLUGIN_NAME = /^[a-z][a-z0-9-]{1,39}$/;
const PLUGIN_INSTANCE = /^[a-z][a-z0-9_]{0,31}$/;
const SEMVER = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$/;
const MAX_VERSION = 64;
const MICRO_TIME = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z$/;
// A host and port as a manifest declares them (manifest.schema.json,
// hostPort). The endpoint's host must be in egress, so it has this form too.
const HOST_PORT = /^(([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*|\[[0-9a-f:.]+\]|[0-9]{1,3}(\.[0-9]{1,3}){3}):[0-9]{1,5}$/;
const MAX_HOST_PORT = 260;
const KEY_ID = /^[A-Za-z0-9_-]{22}$/;

function requireMatch(value, re, what, maxLength = Infinity) {
  if (typeof value !== "string" || value.length > maxLength || !re.test(value)) throw new CodeError(`${what} is not valid`);
  return value;
}

// requireList checks a list of distinct items, each passing check, with at
// least min of them.
function requireList(value, what, min, check) {
  if (!Array.isArray(value) || value.length < min) throw new CodeError(`${what} must list at least ${min}`);
  if (new Set(value).size !== value.length) throw new CodeError(`${what} names an item twice`);
  for (const item of value) check(item, `${what} item`);
  return value;
}

const inSet = (set) => (value, what) => {
  if (!set.has(value)) throw new CodeError(`${what} "${value}" is not known`);
};
const roleName = (value, what) => requireMatch(value, ROLE_NAME, what, MAX_ROLE_NAME);
const hostPort = (value, what) => requireMatch(value, HOST_PORT, what, MAX_HOST_PORT);

function checkEndpoint(value, what) {
  if (value?.kind === ENDPOINT_LOCAL) return strictObject(value, what, ["kind"]);
  if (value?.kind === ENDPOINT_REMOTE) {
    const e = strictObject(value, what, ["kind", "host"]);
    hostPort(e.host, `${what} host`);
    return e;
  }
  throw new CodeError(`${what} kind is not LOCAL or REMOTE`);
}

function checkIsolation(value, what) {
  const i = strictObject(value, what, ["files", "network"]);
  inSet(ISOLATION_FILES)(i.files, `${what} files`);
  inSet(ISOLATION_NETWORK)(i.network, `${what} network`);
  return i;
}

// checkChange checks a binding's change: only the contract's keys, each
// present only with a value of its kind; {} is the same entry turned on
// again.
function checkChange(value) {
  const c = strictObject(value, "binding change", [], PLUGIN_CHANGE_KEYS);
  const lists = {
    hooksAdded: inSet(PLUGIN_HOOKS), hooksRemoved: inSet(PLUGIN_HOOKS),
    rolesAdded: inSet(PLUGIN_ROLES), rolesRemoved: inSet(PLUGIN_ROLES),
    egressAdded: hostPort, egressRemoved: hostPort,
    agentsAdded: roleName, agentsRemoved: roleName,
  };
  for (const [key, check] of Object.entries(lists)) {
    if (key in c) requireList(c[key], `binding change ${key}`, 1, check);
  }
  if ("fromVersion" in c) requireMatch(c.fromVersion, SEMVER, "binding change fromVersion", MAX_VERSION);
  if ("fromManifestSha256" in c) requireMatch(c.fromManifestSha256, HEX64, "binding change fromManifestSha256");
  if ("fromSigner" in c) inSet(SIGNERS)(c.fromSigner, "binding change fromSigner");
  if ("fromEndpoint" in c) checkEndpoint(c.fromEndpoint, "binding change fromEndpoint");
  if ("fromIsolation" in c && c.fromIsolation !== null) checkIsolation(c.fromIsolation, "binding change fromIsolation");
  if ("settingsChanged" in c && c.settingsChanged !== true) throw new CodeError("binding change settingsChanged must be true");
  return c;
}

// parsePluginBinding parses a plugin approval's binding text for display
// and checks it against binding.schema.json, with its rules between keys:
// isolation exactly with LOCAL, host exactly with REMOTE, signerKeyId
// exactly with KNOWN, roles exactly with wire.detect. A binding of another
// kind is refused first, as WRONG_KIND. The text itself is what gets signed.
export function parsePluginBinding(text) {
  const raw = parseJSON(requireString(text, "binding"), "binding");
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) throw new CodeError("binding is not an object");
  if (raw.kind !== KIND_PLUGIN) throw new PluginLinkError(WRONG_KIND, `binding kind "${raw.kind}" is not a plugin approval`);
  const b = strictObject(raw, "binding", PLUGIN_BINDING_REQUIRED, PLUGIN_BINDING_OPTIONAL);
  requireMatch(b.approvalId, UUID, "binding approvalId");
  requireString(b.database, "binding database");
  requireMatch(b.expiresAt, MICRO_TIME, "binding expiresAt");
  roleName(b.requestedBy, "binding requestedBy");
  requireList(b.agents, "binding agents", 1, roleName);
  requireMatch(b.name, PLUGIN_NAME, "binding name");
  requireMatch(b.instance, PLUGIN_INSTANCE, "binding instance");
  requireMatch(b.version, SEMVER, "binding version", MAX_VERSION);
  requireMatch(b.manifestSha256, HEX64, "binding manifestSha256");
  requireMatch(b.settingsSha256, HEX64, "binding settingsSha256");
  requireList(b.hooks, "binding hooks", 1, inSet(PLUGIN_HOOKS));
  requireList(b.egress, "binding egress", 0, hostPort);
  checkEndpoint(b.endpoint, "binding endpoint");
  inSet(SIGNERS)(b.signer, "binding signer");
  if (b.hooks.includes(WIRE_DETECT) !== ("roles" in b)) throw new CodeError("binding roles go with wire.detect, and only with it");
  if ("roles" in b) requireList(b.roles, "binding roles", 1, inSet(PLUGIN_ROLES));
  if ((b.endpoint.kind === ENDPOINT_LOCAL) !== ("isolation" in b)) throw new CodeError("binding isolation goes with a LOCAL endpoint, and only with it");
  if ("isolation" in b) checkIsolation(b.isolation, "binding isolation");
  if ((b.signer === SIGNER_KNOWN) !== ("signerKeyId" in b)) throw new CodeError("binding signerKeyId goes with a KNOWN signer, and only with it");
  if ("signerKeyId" in b) requireMatch(b.signerKeyId, KEY_ID, "binding signerKeyId");
  if ("change" in b) checkChange(b.change);
  return { ...b, expiresAt: parseExpiry(b.expiresAt) };
}

// checkPluginSettings checks the settings text is an object of the entry's
// settings (binding.schema.json, $defs/settings). The page shows the text
// itself, never a re-serialized parse: 0.60 stays 0.60.
function checkPluginSettings(text) {
  const s = strictObject(parseJSON(requireString(text, "settings"), "settings"), "settings", [], PLUGIN_SETTINGS_KEYS);
  const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
  if ("config" in s && !isObject(s.config)) throw new CodeError("settings config is not an object");
  if ("auth" in s) strictObject(s.auth, "settings auth", ["credentialFile"]);
  if ("timeoutMs" in s && !Number.isInteger(s.timeoutMs)) throw new CodeError("settings timeoutMs is not an integer");
  if ("minConfidence" in s && typeof s.minConfidence !== "number") throw new CodeError("settings minConfidence is not a number");
}

const PLUGIN_REQUEST_FIELDS = ["approvalId", "binding", "settings"];

// checkPluginRequest checks a plugin approval request, from a link or from
// the engine (GET /api/v1/plugins/{id}): the binding (parsePluginBinding),
// the same approval in request and binding, and the settings text hashing
// to settingsSha256 (SETTINGS_MISMATCH otherwise). Only then may the page
// show it or ask for a signature.
export async function checkPluginRequest(value) {
  const req = strictObject(value, "plugin approval request", PLUGIN_REQUEST_FIELDS, ["credentialIds"]);
  const binding = parsePluginBinding(req.binding);
  if (req.approvalId !== binding.approvalId) {
    throw new CodeError(`request is for plugin approval ${req.approvalId}, binding for ${binding.approvalId}`);
  }
  requireString(req.settings, "settings");
  if (hex(await sha256(utf8(req.settings))) !== binding.settingsSha256) {
    throw new PluginLinkError(SETTINGS_MISMATCH, "the settings do not match the binding's settingsSha256");
  }
  checkPluginSettings(req.settings);
  if ("credentialIds" in req) {
    requireList(req.credentialIds, "plugin approval request credentialIds", 0, (id) => requireString(id, "credential id"));
    if (req.credentialIds.length > MAX_LINK_CREDENTIAL_IDS) throw new CodeError("plugin approval request has too many credential ids");
  }
  return {
    approvalId: req.approvalId,
    bindingText: req.binding,
    binding,
    settingsText: req.settings,
    credentialIds: decodeCredentialIds(req.credentialIds),
    challenge: await challengeFor(req.binding),
  };
}

// parsePluginRequest decodes a plugin approval link fragment, with or
// without '#': format 2 only, exactly two texts (the binding, then the
// settings) and optionally the database's credential ids; then
// checkPluginRequest.
export async function parsePluginRequest(fragment) {
  const text = String(fragment).replace(/^#/, "");
  if (text.startsWith(REQUEST_FORMAT_1)) throw new CodeError(`a plugin approval link is format "${REQUEST_FORMAT_2}" only`);
  const r = await decodeRequest(text, "plugin approval request", {
    idKey: "approvalId", maxLines: 1, required: [], optional: [], parse: (t) => JSON.parse(t),
  });
  const req = { approvalId: r.approvalId, binding: r.binding, settings: r.lines[0] };
  if ("credentialIds" in r) req.credentialIds = r.credentialIds;
  return checkPluginRequest(req);
}

// encodePluginResponse builds the code the person gives the agent, who
// runs basalt plugin approve with it.
export function encodePluginResponse(response) {
  return PLUGIN_RESPONSE_PREFIX + b64urlEncode(utf8(pluginResponseJSON(response)));
}

// pluginResponseJSON is the JSON a plugin approval code carries, which the
// page posts to the engine's relay (POST /api/v1/plugins/{id}/approve).
export function pluginResponseJSON({ approvalId, ...assertion }) {
  return assertionJSON({ approvalId }, assertion);
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
  const req = strictObject(parseJSON(json, "registration request"), "registration request", ["challenge", "userId", "userName", "displayName"], [
    "handBack",
  ]);
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
    handBack: handBackSecret(req.handBack),
  };
}

// handBackSecret is the secret of basalt init's hand-back route, or "" when
// the request has none: 16 bytes, base64url.
function handBackSecret(value) {
  if (value === undefined) return "";
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{22}$/.test(value)) {
    throw new CodeError("registration handBack must be 16 bytes, base64url");
  }
  return value;
}

// encodeRegistrationResponse builds the code basalt init reads.
export function encodeRegistrationResponse(fields) {
  return REGISTRATION_RESPONSE_PREFIX + b64urlEncode(utf8(registrationResponseJson(fields)));
}

// registrationResponseJson is the JSON the registration code carries, which
// the page posts to basalt init's hand-back route.
export function registrationResponseJson({ credentialId, clientDataJson, authenticatorData, publicKey, publicKeyAlgorithm, prfSupported = false }) {
  if (publicKeyAlgorithm !== ALG_ES256) throw new CodeError("the passkey must use ES256");
  return JSON.stringify({
    credentialId: b64urlEncode(credentialId),
    clientDataJson: b64urlEncode(clientDataJson),
    authenticatorData: b64urlEncode(authenticatorData),
    publicKey: b64urlEncode(publicKey),
    publicKeyAlgorithm,
    ...(prfSupported === true ? { prfSupported: true } : {}),
  });
}

// relyingParty returns the RP ID and origin for the page's location: the
// portal (RP ID basaltvault.app), or the engine's local pages at
// http://localhost:<port> (RP ID localhost). Anywhere else the pages refuse
// to run.
export function relyingParty(loc) {
  if (`${loc.protocol}//${loc.hostname}` === PORTAL && loc.port === "") {
    return { rpId: PROD_RP_ID, origin: PORTAL };
  }
  if (loc.protocol === "http:" && loc.hostname === "localhost" && loc.port !== "") {
    return { rpId: "localhost", origin: `http://localhost:${loc.port}` };
  }
  throw new CodeError(`this page only runs at ${PORTAL} or http://localhost:<port>`);
}

// Rows hidden from the agent (CONTRACT.md, Approvals; owner decision HR-1):
// the reveal proof's challenge, and the check of each revealed row before
// the page shows any value. Same as internal/approval/reveal.go, against the
// shared vectors (internal/approval/testdata/reveal.json).
const REVEAL_PREFIX = "basalt-reveal.1";
const REVEAL_KEY_INFO = "basalt-reveal-key.1";
const REVEAL_KEY_BITS = 256;
const REVEAL_SECRET_BYTES = 16;
const REVEAL_ROW_VALUES = 3; // key, then old or now, then set

// revealKey is HKDF-SHA-256 of the page's reveal secret, salt empty, info
// "basalt-reveal-key.1", 32 bytes: what the engine sends Postgres instead of
// the secret.
export async function revealKey(secret) {
  if (!(secret instanceof Uint8Array) || secret.length !== REVEAL_SECRET_BYTES) {
    throw new CodeError("the reveal secret must be 16 bytes");
  }
  const subtle = globalThis.crypto.subtle;
  const ikm = await subtle.importKey("raw", secret, "HKDF", false, ["deriveBits"]);
  const bits = await subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: utf8(REVEAL_KEY_INFO) },
    ikm,
    REVEAL_KEY_BITS,
  );
  return new Uint8Array(bits);
}

// newRevealSecret is a fresh reveal secret: 16 random bytes, made for one
// reveal and sent only to the engine with the proof.
export function newRevealSecret() {
  return globalThis.crypto.getRandomValues(new Uint8Array(REVEAL_SECRET_BYTES));
}

// revealChallenge is the challenge a reveal proof signs: sha256 of
// "basalt-reveal.1", the kind, the id, the nonce (base64url), the hex
// sha256 of the reveal key and the binding's rowsHash, one per line.
export async function revealChallenge(kind, id, nonce, key, hash) {
  if (kind !== KIND_APPROVE && kind !== KIND_REVERT) throw new CodeError(`reveal kind "${kind}"`);
  if (typeof id !== "string" || !UUID.test(id)) throw new CodeError("reveal id is not a lowercase uuid");
  if (typeof nonce !== "string" || !NONCE.test(nonce) || !decodesTo(nonce, NONCE_BYTES)) throw new CodeError("bad reveal nonce");
  if (!(key instanceof Uint8Array) || key.length !== REVEAL_KEY_BITS / 8) throw new CodeError("the reveal key must be 32 bytes");
  if (typeof hash !== "string" || !HEX64.test(hash)) throw new CodeError("rowsHash is not a sha256 hex digest");
  const keyHash = hex(await sha256(key));
  return sha256(utf8([REVEAL_PREFIX, kind, id, nonce, keyHash, hash].join("\n")));
}

// checkRevealedRow checks one revealed row against the redacted line it
// answers and says whether its values were checked. A row without
// secretColumns must hash to the line's rowHash ("checked"): only then are
// its values the ones bound into what the person signs. A row with
// secretColumns cannot be checked: every named column must be in the row
// and null wherever it is, and the row is "unverified", shown as "Not
// checked against what you sign", never as checked. Anything else throws.
export async function checkRevealedRow(line, revealed) {
  const rowHash = redactedHash(line);
  const r = strictObject(revealed, "revealed row", ["line", "row"], ["secretColumns"]);
  const values = revealedValues(requireString(r.row, "revealed row"));
  const texts = rowTexts(r.row);
  if (!("secretColumns" in r)) {
    if (hex(await sha256(utf8(r.row))) !== rowHash) {
      throw new CodeError("revealed row does not hash to its line's rowHash");
    }
    return { checked: true, values, texts, secretColumns: [] };
  }
  checkSecretColumns(values, r.secretColumns);
  return { checked: false, values, texts, secretColumns: [...r.secretColumns] };
}

// redactedHash is the rowHash of a redacted line, given as its text or as
// parseLine parsed it; anything else throws.
function redactedHash(line) {
  const l = typeof line === "string" ? parseJSON(line, "revealed line") : line;
  if (l === null || typeof l !== "object" || l.redacted !== true || typeof l.rowHash !== "string" || !HEX64.test(l.rowHash)) {
    throw new CodeError("revealed line is not a redacted line");
  }
  return l.rowHash;
}

// rowTexts is, for each of a revealed row's three values that is an
// object, its columns' exact text (valueTexts), so a revealed number shows
// as Postgres printed it. Only for a row revealedValues accepted.
function rowTexts(row) {
  const out = [];
  let i = skipSpace(row, 0) + 1;
  for (let n = 0; n < REVEAL_ROW_VALUES; n++) {
    i = skipSpace(row, i);
    const end = valueEnd(row, i);
    const text = row.slice(i, end).trim();
    out.push(text.startsWith("{") ? memberTexts(text) : new Map());
    i = skipSpace(row, end);
    if (row[i] === ",") i++;
  }
  return out;
}

// checkRevealAnswer checks the reveal answer against the request's lines
// (their texts, or the lines parseLine and parseRevertLine return): rows in
// line order, each a redacted line at most once, each passing
// checkRevealedRow. It returns, per row, the line, whether it was checked,
// its values and their exact texts, and its SECRET columns.
export async function checkRevealAnswer(lineTexts, answer) {
  const a = strictObject(answer, "reveal answer", ["rows"]);
  if (!Array.isArray(a.rows)) throw new CodeError("reveal answer rows is not a list");
  const out = [];
  let last = -1;
  for (const r of a.rows) {
    const line = r?.line;
    if (!Number.isInteger(line) || line <= last || line >= lineTexts.length) {
      throw new CodeError(`revealed line ${line} is out of order or out of range`);
    }
    last = line;
    out.push({ line, ...(await checkRevealedRow(lineTexts[line], r)) });
  }
  return out;
}

// revealedValues parses a row: three values, each an object or null.
function revealedValues(row) {
  const values = parseJSON(row, "revealed row");
  if (!Array.isArray(values) || values.length !== REVEAL_ROW_VALUES) {
    throw new CodeError("revealed row is not three values");
  }
  for (const v of values) {
    if (v !== null && (typeof v !== "object" || Array.isArray(v))) {
      throw new CodeError("revealed row value is not an object or null");
    }
  }
  return values;
}

// checkSecretColumns: a non-empty list, each column named once, present in
// the row and null wherever it appears.
function checkSecretColumns(values, cols) {
  if (!Array.isArray(cols) || cols.length === 0) throw new CodeError("secretColumns is not a non-empty list");
  const seen = new Set();
  for (const col of cols) {
    if (typeof col !== "string" || col === "" || seen.has(col)) {
      throw new CodeError(`secret column "${col}" is empty or named twice`);
    }
    seen.add(col);
    let found = false;
    for (const v of values) {
      if (v === null || !Object.hasOwn(v, col)) continue;
      if (v[col] !== null) throw new CodeError(`secret column "${col}" has a value`);
      found = true;
    }
    if (!found) throw new CodeError(`secret column "${col}" is not in the row`);
  }
}
