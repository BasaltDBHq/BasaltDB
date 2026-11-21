// The page's side of a link session (CONTRACT.md, Vault channel: Link
// secrets in a session, Handshake, Frames, Limits): the portal page runs
// Noise_NNpsk0_P256_AESGCM_SHA256 as the initiator over a WebSocket, then
// speaks the pages API in padded, encrypted frames. Nothing here knows which
// socket carries the session; the transport (relay.js) opens the socket
// and says which transport the prologue names. Every
// primitive is WebCrypto. The shared vectors (api/mcp/vault/testdata) check
// it against the Go engine in channel.test.mjs.

import { b64urlDecode, b64urlEncode, utf8 } from "./codec.js";

export const RELAY = "RELAY";

const subtle = () => globalThis.crypto.subtle;
const strictUtf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

const PROTOCOL_NAME = "Noise_NNpsk0_P256_AESGCM_SHA256";
const VERSION = 0x01;
const HELLO = 0x01;
const WELCOME = 0x02;
const FRAME = 0x03;
const HEADER = 2;
const POINT = 65;
const TAG = 16;
const TOKEN = 16;
const SECRET_BYTES = 16;
const PSK_BYTES = 32;
const HASH_BYTES = 32;
const SIG_BYTES = 64;
const MESSAGE2_MAX = 1024;
const LEN_PREFIX = 4;
const PAD_MIN = 1024;
const PAD_MAX = 32768;
const CONTENT_MAX = PAD_MAX - LEN_PREFIX;
const FRAME_MAX = HEADER + PAD_MAX + TAG;
// A response body over 16 MiB closes the session (TOO_LARGE).
const RESPONSE_MAX = 16 << 20;
// Requests per session (the engine closes with RATE_LIMITED past it).
export const MAX_REQUESTS = 64;
// The page gives the handshake 10 seconds from opening the socket.
export const HANDSHAKE_MS = 10000;
// How long the page waits for a whole response. The engine's own longest
// answer is a rescope, stopped at 100 seconds.
export const RESPONSE_MS = 120000;
// Characters of a request body per frame: even if every one were escaped
// as \u00XX, a frame's JSON stays under CONTENT_MAX.
const BODY_PIECE = 4096;

const SESSION_CONTEXT = "basalt-vault-session-sig.1\n";
const SPKI_P256_PREFIX = Uint8Array.from([
  0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03,
  0x01, 0x07, 0x03, 0x42, 0x00,
]);
const SPKI_BYTES = SPKI_P256_PREFIX.length + POINT;
const ENGINE_ID_BYTES = 16;
const FINGERPRINT_CHARS = 16;
const FINGERPRINT_GROUP = 4;

// Close codes (api/mcp/vault/close-codes.json) by number and by name.
export const CLOSE = Object.freeze({
  PROTOCOL: 4000,
  UNSUPPORTED_VERSION: 4001,
  AUTH_FAILED: 4002,
  REPLACED: 4003,
  LINK_UNKNOWN: 4004,
  ENGINE_OFFLINE: 4005,
  LINK_REFUSED: 4006,
  HANDSHAKE_FAILED: 4007,
  FRAME_INVALID: 4008,
  TOO_LARGE: 4009,
  RATE_LIMITED: 4010,
  SESSION_LIMIT: 4011,
  TIMEOUT: 4012,
  ENGINE_REVOKED: 4013,
  ENGINE_SHUTDOWN: 4014,
});
const CLOSE_NAMES = new Map(Object.entries(CLOSE).map(([name, code]) => [code, name]));
const NORMAL_CLOSE = 1000;
// A socket that never opened or dropped without a close frame.
export const NO_CLOSE_FRAME = "CONNECTION_FAILED";

// ChannelError ends a session: code is the close code's name (CLOSE), or
// NO_CLOSE_FRAME, or "CLOSED" for a session the page itself ended. A code
// the other side or the path sent only decides what the page shows
// (VC-39); nothing else trusts it.
export class ChannelError extends Error {
  constructor(code, message = "") {
    super(message || `the session to the engine ended (${code})`);
    this.name = "ChannelError";
    this.code = code;
  }
}

function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

function equalBytes(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

async function sha256(data) {
  return new Uint8Array(await subtle().digest("SHA-256", data));
}

// --- Link secrets ---

// linkKeys derives a short link's routing token and the session's psk from
// its secret (the 22 characters after #s=). Neither reveals the secret.
export async function linkKeys(secret) {
  let s;
  try {
    s = b64urlDecode(secret);
  } catch {
    s = new Uint8Array(0);
  }
  if (s.length !== SECRET_BYTES) throw new ChannelError("LINK", "this link's secret is not 16 bytes; open the whole link the agent gave");
  const key = await subtle().importKey("raw", s, "HKDF", false, ["deriveBits"]);
  const bits = async (info, n) =>
    new Uint8Array(await subtle().deriveBits({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: utf8(info) }, key, n * 8));
  const token = await bits("basalt-vault-link.1", TOKEN);
  return { token, tokenText: b64urlEncode(token), psk: await bits("basalt-vault-psk.1", PSK_BYTES) };
}

// --- Engine keys ---

// parseEngineKey imports the engine's signing key from its SPKI text,
// accepting only the 91-byte form: id-ecPublicKey, prime256v1, an
// uncompressed point on the curve. null for anything else.
export async function parseEngineKey(spki) {
  let der;
  try {
    der = b64urlDecode(spki);
  } catch {
    return null;
  }
  if (der.length !== SPKI_BYTES || !equalBytes(der.subarray(0, SPKI_P256_PREFIX.length), SPKI_P256_PREFIX)) return null;
  if (der[SPKI_P256_PREFIX.length] !== 0x04) return null;
  try {
    return await subtle().importKey("spki", der, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  } catch {
    return null;
  }
}

// engineIdOf is the engine id of an SPKI text: base64url of the first 16
// bytes of its SHA-256 (CONTRACT.md, Engine keys).
export async function engineIdOf(spki) {
  return b64urlEncode((await sha256(b64urlDecode(spki))).subarray(0, ENGINE_ID_BYTES));
}

// fingerprint is how an engine id is shown to people: its first 16
// characters in four groups of four.
export function fingerprint(engineId) {
  return String(engineId).slice(0, FINGERPRINT_CHARS).match(new RegExp(`.{1,${FINGERPRINT_GROUP}}`, "g")).join(" ");
}

// --- Signatures and receipts ---

// CONTEXTS are the signing contexts of the engine's key (CONTRACT.md,
// Primitives and encodings): every message it signs starts with one line.
export const CONTEXTS = Object.freeze({
  VAULT_AUTH: "basalt-vault-engine.1\n",
  SESSION: SESSION_CONTEXT,
  RECEIPT: "basalt-receipt.1\n",
  BOX_KEY: "basalt-engine-box-key.1\n",
  ROTATE: "basalt-engine-rotate.1\n",
  CONNECT_COLLECT: "basalt-connect-collect.1\n",
  CONNECT_REACH: "basalt-connect-reach.1\n",
});

// verifySigned checks sig (64 bytes r || s, base64url) by the engine key
// spki over message, which must start with the line of context. false for
// any refusal.
export async function verifySigned(spki, context, message, sig) {
  const line = utf8(CONTEXTS[context] ?? "");
  if (line.length === 0 || message.length < line.length || !equalBytes(message.subarray(0, line.length), line)) return false;
  const key = await parseEngineKey(spki);
  let raw;
  try {
    raw = b64urlDecode(sig);
  } catch {
    return false;
  }
  if (key === null || raw.length !== SIG_BYTES) return false;
  return subtle().verify({ name: "ECDSA", hash: "SHA-256" }, key, raw, message);
}

const RECEIPT_PREFIX = "basalt-receipt.1.";
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const RECEIPT_HEADLINE_MAX = 500;
// RECEIPT_FIELDS is receipt.schema.json, closed: each field's check.
const RECEIPT_FIELDS = Object.freeze({
  format: (v) => v === 1,
  kind: (v) => v === "APPROVAL" || v === "REVERT",
  itemId: (v) => typeof v === "string" && UUID.test(v),
  status: (v) => v === "APPROVED" || v === "APPLIED" || v === "APPLYING",
  headline: (v) => typeof v === "string" && [...v].length >= 1 && [...v].length <= RECEIPT_HEADLINE_MAX,
  rowsHash: (v) => typeof v === "string" && /^[0-9a-f]{64}$/.test(v),
  agent: (v) => typeof v === "string" && v.length > 0,
  engineId: (v) => typeof v === "string" && /^[A-Za-z0-9_-]{22}$/.test(v),
  at: (v) => typeof v === "string" && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(v) && !Number.isNaN(Date.parse(v)),
  changeId: (v) => typeof v === "string" && UUID.test(v),
});
const RECEIPT_OPTIONAL = new Set(["changeId"]);

// checkReceipt verifies a receipt token against spki, the engine key the
// caller expects from outside the receipt (CONTRACT.md, Receipts), in the
// contract's order: the signature, the parse, that engineId is that key's
// id, then the closed schema. It returns the payload, or null for any
// refusal. In the page the only key there is the session's own, so a
// receipt checked there proves no more than the fingerprint the page shows.
export async function checkReceipt(token, spki) {
  if (typeof token !== "string" || !token.startsWith(RECEIPT_PREFIX)) return null;
  const parts = token.slice(RECEIPT_PREFIX.length).split(".");
  if (parts.length !== 2) return null;
  let payload;
  try {
    payload = b64urlDecode(parts[0]);
  } catch {
    return null;
  }
  if (!(await verifySigned(spki, "RECEIPT", concat(utf8(CONTEXTS.RECEIPT), payload), parts[1]))) return null;
  let p;
  try {
    p = JSON.parse(strictUtf8.decode(payload));
  } catch {
    return null;
  }
  if (p === null || typeof p !== "object" || Array.isArray(p)) return null;
  if (p.engineId !== (await engineIdOf(spki))) return null;
  for (const [k, v] of Object.entries(p)) {
    if (!Object.hasOwn(RECEIPT_FIELDS, k) || !RECEIPT_FIELDS[k](v)) return null;
  }
  for (const k of Object.keys(RECEIPT_FIELDS)) {
    if (!RECEIPT_OPTIONAL.has(k) && !Object.hasOwn(p, k)) return null;
  }
  return p;
}

// --- Noise ---

async function hmac(key, data) {
  const k = await subtle().importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await subtle().sign("HMAC", k, data));
}

async function noiseHKDF(ck, ikm, outputs) {
  const temp = await hmac(ck, ikm);
  const out = [];
  let prev = new Uint8Array(0);
  for (let i = 1; i <= outputs; i++) {
    prev = await hmac(temp, concat(prev, [i]));
    out.push(prev);
  }
  return out;
}

const NONCE_BYTES = 12;
const COUNTER_AT = 4;

function nonce(n) {
  const b = new Uint8Array(NONCE_BYTES);
  new DataView(b.buffer).setBigUint64(COUNTER_AT, BigInt(n));
  return b;
}

async function aesKey(raw, usage) {
  return subtle().importKey("raw", raw, "AES-GCM", false, [usage]);
}

async function seal(key, n, ad, plaintext) {
  return new Uint8Array(await subtle().encrypt({ name: "AES-GCM", iv: nonce(n), additionalData: ad }, key, plaintext));
}

async function open(key, n, ad, ciphertext, code) {
  try {
    return new Uint8Array(await subtle().decrypt({ name: "AES-GCM", iv: nonce(n), additionalData: ad }, key, ciphertext));
  } catch {
    throw new ChannelError(code);
  }
}

function prologue(transport, tokenText) {
  return utf8(`basalt-vault-prologue.1\n${transport}\n${tokenText}`);
}

class SymmetricState {
  static async init(prologueBytes) {
    const s = new SymmetricState();
    s.h = new Uint8Array(HASH_BYTES);
    s.h.set(utf8(PROTOCOL_NAME));
    s.ck = s.h.slice();
    s.k = null;
    s.n = 0;
    await s.mixHash(prologueBytes);
    return s;
  }

  async mixHash(data) {
    this.h = await sha256(concat(this.h, data));
  }

  async mixKey(ikm) {
    const [ck, k] = await noiseHKDF(this.ck, ikm, 2);
    this.ck = ck;
    this.k = await aesKey(k, "encrypt");
    this.kd = await aesKey(k, "decrypt");
    this.n = 0;
  }

  async mixKeyAndHash(ikm) {
    const [ck, th, k] = await noiseHKDF(this.ck, ikm, 3);
    this.ck = ck;
    await this.mixHash(th);
    this.k = await aesKey(k, "encrypt");
    this.kd = await aesKey(k, "decrypt");
    this.n = 0;
  }

  // The e token in psk mode: MixHash and MixKey of the 65 bytes as they are.
  async mixE(pub) {
    await this.mixHash(pub);
    await this.mixKey(pub);
  }

  async encryptAndHash(plaintext) {
    const ct = await seal(this.k, this.n++, this.h, plaintext);
    await this.mixHash(ct);
    return ct;
  }

  async decryptAndHash(ciphertext, code) {
    const pt = await open(this.kd, this.n, this.h, ciphertext, code);
    this.n++;
    await this.mixHash(ciphertext);
    return pt;
  }

  async split() {
    return noiseHKDF(this.ck, new Uint8Array(0), 2);
  }
}

async function publicPoint(priv) {
  const jwk = await subtle().exportKey("jwk", priv);
  return concat([0x04], b64urlDecode(jwk.x), b64urlDecode(jwk.y));
}

async function importPoint(point) {
  if (point.length !== POINT || point[0] !== 0x04) return null;
  try {
    return await subtle().importKey("raw", point, { name: "ECDH", namedCurve: "P-256" }, false, []);
  } catch {
    return null;
  }
}

function checkHeader(msg, type) {
  if (msg.length < HEADER) throw new ChannelError("PROTOCOL");
  if (msg[0] !== VERSION) throw new ChannelError("UNSUPPORTED_VERSION");
  if (msg[1] !== type) throw new ChannelError("PROTOCOL");
}

// startHandshake makes message 1 for keys (linkKeys) on transport. e is the
// page's ephemeral key pair, made fresh unless a test passes one.
export async function startHandshake(transport, keys, e = null) {
  const pair = e ?? (await subtle().generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]));
  const ePub = await publicPoint(pair.privateKey);
  const s = await SymmetricState.init(prologue(transport, keys.tokenText));
  await s.mixKeyAndHash(keys.psk);
  await s.mixE(ePub);
  const tag = await s.encryptAndHash(new Uint8Array(0));
  return { message: concat([VERSION, HELLO], keys.token, ePub, tag), state: s, e: pair.privateKey };
}

function parseWelcome(pt) {
  let p;
  try {
    p = JSON.parse(strictUtf8.decode(pt));
  } catch {
    throw new ChannelError("HANDSHAKE_FAILED");
  }
  const keys = p && typeof p === "object" && !Array.isArray(p) ? Object.keys(p).sort().join(",") : "";
  if (keys !== "engineKey,sig" || typeof p.engineKey !== "string" || typeof p.sig !== "string") {
    throw new ChannelError("HANDSHAKE_FAILED");
  }
  return p;
}

// finishHandshake reads message 2: the engine's ephemeral key, its signed
// payload, then Split. It returns the direction keys and the engine's
// identity; the caller compares that with a pin when it has one.
export async function finishHandshake(hs, msg) {
  checkHeader(msg, WELCOME);
  if (msg.length > MESSAGE2_MAX) throw new ChannelError("TOO_LARGE");
  if (msg.length < HEADER + POINT + TAG) throw new ChannelError("HANDSHAKE_FAILED");
  const rePub = msg.subarray(HEADER, HEADER + POINT);
  const re = await importPoint(rePub);
  if (re === null) throw new ChannelError("HANDSHAKE_FAILED");
  const s = hs.state;
  await s.mixE(rePub);
  await s.mixKey(new Uint8Array(await subtle().deriveBits({ name: "ECDH", public: re }, hs.e, 256)));
  const signed = s.h;
  const p = parseWelcome(await s.decryptAndHash(msg.subarray(HEADER + POINT), "HANDSHAKE_FAILED"));
  const key = await parseEngineKey(p.engineKey);
  let sig;
  try {
    sig = b64urlDecode(p.sig);
  } catch {
    sig = new Uint8Array(0);
  }
  if (key === null || sig.length !== SIG_BYTES) throw new ChannelError("HANDSHAKE_FAILED");
  const ok = await subtle().verify({ name: "ECDSA", hash: "SHA-256" }, key, sig, concat(utf8(SESSION_CONTEXT), signed));
  if (!ok) throw new ChannelError("HANDSHAKE_FAILED");
  const [k1, k2] = await s.split();
  // Noise erases ck and the ephemeral key after Split; drop them here.
  s.ck = null;
  hs.e = null;
  return { h: s.h, k1, k2, engineKey: p.engineKey, engineId: await engineIdOf(p.engineKey) };
}

// --- Frames ---

function bucket(contentLen) {
  let size = PAD_MIN;
  while (size < LEN_PREFIX + contentLen) size *= 2;
  return size;
}

export function pad(content) {
  if (content.length > CONTENT_MAX) throw new ChannelError("TOO_LARGE");
  const out = new Uint8Array(bucket(content.length));
  new DataView(out.buffer).setUint32(0, content.length);
  out.set(content, LEN_PREFIX);
  return out;
}

export function unpad(padded) {
  if (padded.length < LEN_PREFIX) throw new ChannelError("FRAME_INVALID");
  const n = new DataView(padded.buffer, padded.byteOffset).getUint32(0);
  if (n > CONTENT_MAX || padded.length !== bucket(n)) throw new ChannelError("FRAME_INVALID");
  for (let i = LEN_PREFIX + n; i < padded.length; i++) {
    if (padded[i] !== 0) throw new ChannelError("FRAME_INVALID");
  }
  return padded.slice(LEN_PREFIX, LEN_PREFIX + n);
}

const FRAME_HEADER = new Uint8Array([VERSION, FRAME]);

// Directions of a session: the page seals with k1 and opens with k2, each
// with its own counter from 0.
export async function sessionKeys(split) {
  return { send: await aesKey(split.k1, "encrypt"), receive: await aesKey(split.k2, "decrypt"), sent: 0, received: 0 };
}

export async function sealFrame(keys, content) {
  const frame = concat(FRAME_HEADER, await seal(keys.send, keys.sent, FRAME_HEADER, pad(content)));
  keys.sent++;
  return frame;
}

export async function openFrame(keys, frame) {
  if (frame.length > FRAME_MAX) throw new ChannelError("TOO_LARGE");
  checkHeader(frame, FRAME);
  const padded = await open(keys.receive, keys.received, FRAME_HEADER, frame.subarray(HEADER), "FRAME_INVALID");
  keys.received++;
  return unpad(padded);
}

// --- The socket ---

// socketReader wraps a WebSocket (the browser's, or a test's) as a queue of
// binary messages and the close that ends it.
function socketReader(ws) {
  ws.binaryType = "arraybuffer";
  const queue = [];
  let waiting = null;
  let ended = null;
  const wake = () => {
    if (waiting === null) return;
    const w = waiting;
    waiting = null;
    w();
  };
  const end = (err) => {
    if (ended === null) ended = err;
    wake();
  };
  ws.addEventListener("message", (ev) => {
    if (typeof ev.data === "string") {
      end(new ChannelError("PROTOCOL"));
      closeSocket(ws, CLOSE.PROTOCOL);
      return;
    }
    queue.push(new Uint8Array(ev.data));
    wake();
  });
  ws.addEventListener("close", (ev) => {
    const name = CLOSE_NAMES.get(ev.code);
    end(new ChannelError(name ?? (ev.code === NORMAL_CLOSE ? "CLOSED" : NO_CLOSE_FRAME)));
  });
  ws.addEventListener("error", () => end(new ChannelError(NO_CLOSE_FRAME)));
  return {
    get ended() {
      return ended;
    },
    // next resolves with the next message, or rejects when the socket
    // ended or ms passed (TIMEOUT, and the page closes the socket).
    async next(ms) {
      for (;;) {
        if (queue.length > 0) return queue.shift();
        if (ended !== null) throw ended;
        let timer;
        const timedOut = await new Promise((resolve) => {
          waiting = () => resolve(false);
          timer = setTimeout(() => resolve(true), ms);
        });
        clearTimeout(timer);
        if (timedOut) {
          waiting = null;
          end(new ChannelError("TIMEOUT"));
          closeSocket(ws, CLOSE.TIMEOUT);
        }
      }
    },
    fail(err) {
      end(err);
    },
  };
}

function closeSocket(ws, code) {
  try {
    ws.close(code, CLOSE_NAMES.get(code) ?? "");
  } catch {
    // Already closing.
  }
}

// waitOpen resolves once ws is open, or rejects when it fails first.
function waitOpen(ws, ms) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      closeSocket(ws, CLOSE.TIMEOUT);
      reject(new ChannelError("TIMEOUT"));
    }, ms);
    const done = (fn) => (ev) => {
      clearTimeout(timer);
      fn(ev);
    };
    ws.addEventListener("open", done(() => resolve()), { once: true });
    ws.addEventListener("close", done((ev) => reject(new ChannelError(CLOSE_NAMES.get(ev.code) ?? NO_CLOSE_FRAME))), { once: true });
  });
}

// openChannel opens a socket with connect() and runs the handshake on it
// for the link of secret on transport. connect gets the link's token as
// its base64url text (the relay's socket path) and nothing else of the
// link. It resolves with the session.
export async function openChannel(connect, { transport, secret, handshakeMs = HANDSHAKE_MS, now = () => Date.now() }) {
  const keys = await linkKeys(secret);
  const started = now();
  const left = () => Math.max(0, handshakeMs - (now() - started));
  const ws = connect(keys.tokenText);
  const reader = socketReader(ws);
  try {
    await waitOpen(ws, left());
    const hs = await startHandshake(transport, keys);
    ws.send(hs.message);
    const welcome = await finishHandshake(hs, await reader.next(left()));
    return new Session(ws, reader, await sessionKeys(welcome), welcome);
  } catch (err) {
    const e = err instanceof ChannelError ? err : new ChannelError("HANDSHAKE_FAILED");
    reader.fail(e);
    // The page closes with HANDSHAKE_FAILED for anything wrong in message 2
    // (a different key included); closing a socket that already ended does
    // nothing.
    if (reader.ended === e) closeSocket(ws, e.code === "TIMEOUT" ? CLOSE.TIMEOUT : CLOSE.HANDSHAKE_FAILED);
    throw e;
  }
}

function splitBody(body) {
  const pieces = [];
  let rest = body;
  while (rest.length > BODY_PIECE) {
    let cut = BODY_PIECE;
    // Never split a surrogate pair: each piece must be valid UTF-16.
    const c = rest.charCodeAt(cut - 1);
    if (c >= 0xd800 && c <= 0xdbff) cut--;
    pieces.push(rest.slice(0, cut));
    rest = rest.slice(cut);
  }
  pieces.push(rest);
  return pieces;
}

function frameContent(content) {
  let msg;
  try {
    msg = JSON.parse(strictUtf8.decode(content));
  } catch {
    throw new ChannelError("PROTOCOL");
  }
  if (msg === null || typeof msg !== "object" || Array.isArray(msg)) throw new ChannelError("PROTOCOL");
  return msg;
}

const RESPONSE_KEYS = "body,headers,id,more,status,type";
const CONTINUE_KEYS = "body,id,more,type";
const MIN_STATUS = 200;
const MAX_STATUS = 599;

function checkResponse(msg, id) {
  const keys = Object.keys(msg).sort().join(",");
  const ok =
    keys === RESPONSE_KEYS &&
    msg.type === "RESPONSE" &&
    msg.id === id &&
    Number.isInteger(msg.status) &&
    msg.status >= MIN_STATUS &&
    msg.status <= MAX_STATUS &&
    msg.headers !== null &&
    typeof msg.headers === "object" &&
    !Array.isArray(msg.headers) &&
    Object.entries(msg.headers).every(([k, v]) => k === "content-type" && typeof v === "string") &&
    typeof msg.body === "string" &&
    typeof msg.more === "boolean";
  if (!ok) throw new ChannelError("PROTOCOL");
}

function checkContinue(msg, id) {
  const keys = Object.keys(msg).sort().join(",");
  if (keys !== CONTINUE_KEYS || msg.type !== "CONTINUE" || msg.id !== id || typeof msg.body !== "string" || typeof msg.more !== "boolean") {
    throw new ChannelError("PROTOCOL");
  }
}

// Session is one open link session: requests go one at a time, in order.
export class Session {
  constructor(ws, reader, keys, welcome) {
    this.ws = ws;
    this.reader = reader;
    this.keys = keys;
    this.engineKey = welcome.engineKey;
    this.engineId = welcome.engineId;
    this.nextId = 0;
    this.queue = Promise.resolve();
  }

  // ended is the error that ended the session, or null while it is open.
  get ended() {
    return this.reader.ended;
  }

  // request sends one pages API request and resolves with the engine's
  // answer whatever its status: { status, headers, body }. It rejects
  // (ChannelError) only when the session ends first.
  request(method, path, headers, body) {
    const run = this.queue.then(() => this.exchange(method, path, headers, body));
    this.queue = run.catch(() => {});
    return run;
  }

  async exchange(method, path, headers, body) {
    if (this.reader.ended !== null) throw this.reader.ended;
    // The engine allows 64 requests per session: end this one normally,
    // so the transport opens a new session for the next request.
    if (this.nextId >= MAX_REQUESTS) {
      this.close();
      throw this.reader.ended;
    }
    const id = ++this.nextId;
    try {
      const pieces = splitBody(body ?? "");
      await this.send({ type: "REQUEST", id, method, path, headers, body: pieces[0], more: pieces.length > 1 });
      for (let i = 1; i < pieces.length; i++) {
        await this.send({ type: "CONTINUE", id, body: pieces[i], more: i < pieces.length - 1 });
      }
      return await this.receive(id);
    } catch (err) {
      this.fail(err instanceof ChannelError ? err : new ChannelError("PROTOCOL"));
      throw this.reader.ended;
    }
  }

  async send(msg) {
    this.ws.send(await sealFrame(this.keys, utf8(JSON.stringify(msg))));
  }

  async receive(id) {
    const first = frameContent(await openFrame(this.keys, await this.reader.next(RESPONSE_MS)));
    checkResponse(first, id);
    let body = first.body;
    let bytes = utf8(first.body).length;
    if (bytes > RESPONSE_MAX) throw new ChannelError("TOO_LARGE");
    let more = first.more;
    while (more) {
      const next = frameContent(await openFrame(this.keys, await this.reader.next(RESPONSE_MS)));
      checkContinue(next, id);
      body += next.body;
      bytes += utf8(next.body).length;
      if (bytes > RESPONSE_MAX) throw new ChannelError("TOO_LARGE");
      more = next.more;
    }
    return { status: first.status, headers: { ...first.headers }, body };
  }

  // fail ends the session with err, closing the socket with its code.
  fail(err) {
    if (this.reader.ended !== null) return;
    this.reader.fail(err);
    closeSocket(this.ws, CLOSE[err.code] ?? CLOSE.PROTOCOL);
  }

  // close ends the session normally.
  close() {
    if (this.reader.ended !== null) return;
    this.reader.fail(new ChannelError("CLOSED"));
    try {
      this.ws.close(NORMAL_CLOSE);
    } catch {
      // Already closing.
    }
  }
}
