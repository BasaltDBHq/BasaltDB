// Runs with `node --test web/lib/*.test.mjs` (make web-check). The cases are
// the shared Vault channel vectors the Go reference writes and runs too
// (api/mcp/vault/testdata, CONTRACT.md, Vault channel, Test vectors). Every
// primitive here is WebCrypto, as the portal page will use it.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const subtle = globalThis.crypto.subtle;
const utf8 = new TextEncoder();
const strictUtf8 = new TextDecoder("utf-8", { fatal: true });

const load = (name) =>
  JSON.parse(readFileSync(new URL(`../../api/mcp/vault/testdata/${name}`, import.meta.url), "utf8"));

const PROTOCOL_NAME = "Noise_NNpsk0_P256_AESGCM_SHA256";
const VERSION = 0x01;
const HELLO = 0x01;
const WELCOME = 0x02;
const FRAME = 0x03;
const HEADER = 2;
const POINT = 65;
const TAG = 16;
const TOKEN = 16;
const MESSAGE1 = HEADER + TOKEN + POINT + TAG;
const MESSAGE2_MAX = 1024;
const LEN_PREFIX = 4;
const PAD_MIN = 1024;
const PAD_MAX = 32768;
const CONTENT_MAX = PAD_MAX - LEN_PREFIX;
const FRAME_MAX = HEADER + PAD_MAX + TAG;
const SIG = 64;

const CONTEXTS = {
  VAULT_AUTH: "basalt-vault-engine.1\n",
  SESSION: "basalt-vault-session-sig.1\n",
  RECEIPT: "basalt-receipt.1\n",
  BOX_KEY: "basalt-engine-box-key.1\n",
  ROTATE: "basalt-engine-rotate.1\n",
};

const SPKI_P256_PREFIX = fromHex("3059301306072a8648ce3d020106082a8648ce3d030107034200");
// PKCS#8 for a P-256 scalar without its public key; WebCrypto computes it.
const PKCS8_P256_PREFIX = fromHex("308141020100301306072a8648ce3d020106082a8648ce3d030107042730250201010420");

class Refusal extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

async function outcome(fn) {
  try {
    await fn();
    return "ACCEPT";
  } catch (e) {
    if (e instanceof Refusal) return e.code;
    throw e;
  }
}

function fromHex(s) {
  return Uint8Array.from(s.match(/../g) ?? [], (b) => parseInt(b, 16));
}

function toHex(b) {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

function b64(b) {
  return Buffer.from(b).toString("base64url");
}

// unb64 decodes base64url without padding and refuses a non-canonical form.
function unb64(s) {
  if (typeof s !== "string" || !/^[A-Za-z0-9_-]*$/.test(s)) throw new Refusal("REFUSE");
  const b = new Uint8Array(Buffer.from(s, "base64url"));
  if (b64(b) !== s) throw new Refusal("REFUSE");
  return b;
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

function equal(a, b) {
  return a.length === b.length && a.every((x, i) => x === b[i]);
}

async function sha256(data) {
  return new Uint8Array(await subtle.digest("SHA-256", data));
}

// --- Link secrets ---

async function deriveLink(secret) {
  const s = unb64(secret);
  assert.equal(s.length, 16);
  const key = await subtle.importKey("raw", s, "HKDF", false, ["deriveBits"]);
  const bits = async (info, n) =>
    new Uint8Array(
      await subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: utf8.encode(info) }, key, n * 8),
    );
  return { token: await bits("basalt-vault-link.1", TOKEN), psk: await bits("basalt-vault-psk.1", 32) };
}

function prologue(transport, token) {
  return utf8.encode(`basalt-vault-prologue.1\n${transport}\n${b64(token)}`);
}

// --- Keys ---

async function privateKey(scalar, algorithm, usages) {
  return subtle.importKey("pkcs8", concat(PKCS8_P256_PREFIX, scalar), { name: algorithm, namedCurve: "P-256" }, true, usages);
}

async function publicPoint(priv) {
  const jwk = await subtle.exportKey("jwk", priv);
  return concat([0x04], unb64(jwk.x), unb64(jwk.y));
}

// importPoint refuses anything but a 65-byte uncompressed point on the curve.
async function importPoint(point, algorithm, usages) {
  if (point.length !== POINT || point[0] !== 0x04) throw new Refusal("REFUSE");
  try {
    return await subtle.importKey("raw", point, { name: algorithm, namedCurve: "P-256" }, false, usages);
  } catch {
    throw new Refusal("REFUSE");
  }
}

// parseEngineKey accepts only the 91-byte SPKI: id-ecPublicKey, prime256v1,
// an uncompressed point on the curve.
async function parseEngineKey(spki) {
  const der = unb64(spki);
  if (der.length !== SPKI_P256_PREFIX.length + POINT || !equal(der.subarray(0, SPKI_P256_PREFIX.length), SPKI_P256_PREFIX)) {
    throw new Refusal("REFUSE");
  }
  return importPoint(der.subarray(SPKI_P256_PREFIX.length), "ECDSA", ["verify"]);
}

async function engineIdOf(spki) {
  return b64((await sha256(spki)).subarray(0, 16));
}

function fingerprintOf(engineId) {
  return engineId.slice(0, 16).match(/.{4}/g).join(" ");
}

async function verifySig(key, message, sig) {
  const raw = unb64(sig);
  if (raw.length !== SIG) throw new Refusal("REFUSE");
  if (!(await subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, raw, message))) throw new Refusal("REFUSE");
}

async function verifyContext(context, publicKey, message, sig) {
  const line = utf8.encode(CONTEXTS[context]);
  if (!equal(message.subarray(0, line.length), line)) throw new Refusal("REFUSE");
  await verifySig(await parseEngineKey(publicKey), message, sig);
}

// --- Noise ---

async function hmac(key, data) {
  const k = await subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await subtle.sign("HMAC", k, data));
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

function nonce(n) {
  const b = new Uint8Array(12);
  new DataView(b.buffer).setBigUint64(4, BigInt(n));
  return b;
}

async function seal(key, n, ad, plaintext) {
  const k = await subtle.importKey("raw", key, "AES-GCM", false, ["encrypt"]);
  return new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv: nonce(n), additionalData: ad }, k, plaintext));
}

async function open(key, n, ad, ciphertext, code) {
  const k = await subtle.importKey("raw", key, "AES-GCM", false, ["decrypt"]);
  try {
    return new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv: nonce(n), additionalData: ad }, k, ciphertext));
  } catch {
    throw new Refusal(code);
  }
}

class SymmetricState {
  static async init(prologueBytes) {
    const s = new SymmetricState();
    s.h = new Uint8Array(32);
    s.h.set(utf8.encode(PROTOCOL_NAME));
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
    [this.ck, this.k] = await noiseHKDF(this.ck, ikm, 2);
    this.n = 0;
  }

  async mixKeyAndHash(ikm) {
    const [ck, th, k] = await noiseHKDF(this.ck, ikm, 3);
    this.ck = ck;
    await this.mixHash(th);
    this.k = k;
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
    const pt = await open(this.k, this.n, this.h, ciphertext, code);
    this.n++;
    await this.mixHash(ciphertext);
    return pt;
  }

  async split() {
    return noiseHKDF(this.ck, new Uint8Array(0), 2);
  }
}

function readHeader(msg, type) {
  if (msg.length < HEADER) throw new Refusal("PROTOCOL");
  if (msg[0] !== VERSION) throw new Refusal("UNSUPPORTED_VERSION");
  if (msg[1] !== type) throw new Refusal("PROTOCOL");
}

async function writeMessage1(transport, link, ePub) {
  const s = await SymmetricState.init(prologue(transport, link.token));
  await s.mixKeyAndHash(link.psk);
  await s.mixE(ePub);
  const tag = await s.encryptAndHash(new Uint8Array(0));
  return { message: concat([VERSION, HELLO], link.token, ePub, tag), state: s };
}

async function engineReadMessage1(transport, link, msg) {
  readHeader(msg, HELLO);
  if (msg.length !== MESSAGE1) throw new Refusal("PROTOCOL");
  const token = msg.subarray(HEADER, HEADER + TOKEN);
  const ePub = msg.subarray(HEADER + TOKEN, HEADER + TOKEN + POINT);
  if (!equal(token, link.token)) throw new Refusal("LINK_REFUSED");
  const s = await SymmetricState.init(prologue(transport, link.token));
  await s.mixKeyAndHash(link.psk);
  await s.mixE(ePub);
  await s.decryptAndHash(msg.subarray(HEADER + TOKEN + POINT), "LINK_REFUSED");
  const re = await importPoint(ePub, "ECDH", []).catch(() => {
    throw new Refusal("LINK_REFUSED");
  });
  return { state: s, re };
}

async function dh(priv, pub) {
  return new Uint8Array(await subtle.deriveBits({ name: "ECDH", public: pub }, priv, 256));
}

async function writeMessage2(s, re, e, payload) {
  const ePub = await publicPoint(e);
  await s.mixE(ePub);
  await s.mixKey(await dh(e, re));
  const ct = await s.encryptAndHash(payload);
  const [k1, k2] = await s.split();
  return { message: concat([VERSION, WELCOME], ePub, ct), keys: { h: s.h, k1, k2 } };
}

function parseWelcome(pt) {
  let p;
  try {
    p = JSON.parse(strictUtf8.decode(pt));
  } catch {
    throw new Refusal("HANDSHAKE_FAILED");
  }
  const keys = p && typeof p === "object" && !Array.isArray(p) ? Object.keys(p).sort().join(",") : "";
  if (keys !== "engineKey,sig" || typeof p.engineKey !== "string" || typeof p.sig !== "string") {
    throw new Refusal("HANDSHAKE_FAILED");
  }
  return p;
}

async function pageReadMessage2(s, e, msg) {
  readHeader(msg, WELCOME);
  if (msg.length > MESSAGE2_MAX) throw new Refusal("TOO_LARGE");
  if (msg.length < HEADER + POINT + TAG) throw new Refusal("HANDSHAKE_FAILED");
  const rePub = msg.subarray(HEADER, HEADER + POINT);
  const re = await importPoint(rePub, "ECDH", []).catch(() => {
    throw new Refusal("HANDSHAKE_FAILED");
  });
  await s.mixE(rePub);
  await s.mixKey(await dh(e, re));
  const signed = s.h;
  const pt = await s.decryptAndHash(msg.subarray(HEADER + POINT), "HANDSHAKE_FAILED");
  const p = parseWelcome(pt);
  try {
    await verifySig(await parseEngineKey(p.engineKey), concat(utf8.encode(CONTEXTS.SESSION), signed), p.sig);
  } catch {
    throw new Refusal("HANDSHAKE_FAILED");
  }
  const [k1, k2] = await s.split();
  return { h: s.h, k1, k2 };
}

// --- Frames ---

function bucket(contentLen) {
  let size = PAD_MIN;
  while (size < LEN_PREFIX + contentLen) size *= 2;
  return size;
}

function pad(content) {
  const out = new Uint8Array(bucket(content.length));
  new DataView(out.buffer).setUint32(0, content.length);
  out.set(content, LEN_PREFIX);
  return out;
}

function unpad(padded) {
  if (padded.length < LEN_PREFIX) throw new Refusal("FRAME_INVALID");
  const n = new DataView(padded.buffer, padded.byteOffset).getUint32(0);
  if (n > CONTENT_MAX || padded.length !== bucket(n)) throw new Refusal("FRAME_INVALID");
  if (padded.subarray(LEN_PREFIX + n).some((b) => b !== 0)) throw new Refusal("FRAME_INVALID");
  return padded.slice(LEN_PREFIX, LEN_PREFIX + n);
}

const FRAME_HEADER = new Uint8Array([VERSION, FRAME]);

async function sealFrame(key, n, padded) {
  return concat(FRAME_HEADER, await seal(key, n, FRAME_HEADER, padded));
}

async function openFrame(key, n, frame) {
  if (frame.length > FRAME_MAX) throw new Refusal("TOO_LARGE");
  readHeader(frame, FRAME);
  return unpad(await open(key, n, frame.subarray(0, HEADER), frame.subarray(HEADER), "FRAME_INVALID"));
}

// --- Receipts ---

const RECEIPT_PREFIX = "basalt-receipt.1.";
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;
const RECEIPT_FIELDS = {
  format: (v) => v === 1,
  kind: (v) => v === "APPROVAL" || v === "REVERT",
  itemId: (v) => typeof v === "string" && UUID.test(v),
  status: (v) => ["APPROVED", "APPLIED", "APPLYING"].includes(v),
  headline: (v) => typeof v === "string" && [...v].length >= 1 && [...v].length <= 500,
  rowsHash: (v) => typeof v === "string" && /^[0-9a-f]{64}$/.test(v),
  agent: (v) => typeof v === "string" && v.length > 0,
  engineId: (v) => typeof v === "string" && /^[A-Za-z0-9_-]{22}$/.test(v),
  at: (v) => typeof v === "string" && RFC3339.test(v),
  changeId: (v) => typeof v === "string" && UUID.test(v),
};
const RECEIPT_OPTIONAL = new Set(["changeId"]);

// verifyReceipt checks the signature against the key the verifier expects,
// then that engineId is that key's id, then the closed schema.
async function verifyReceipt(token, expectedKey) {
  if (!token.startsWith(RECEIPT_PREFIX)) throw new Refusal("REFUSE");
  const parts = token.slice(RECEIPT_PREFIX.length).split(".");
  if (parts.length !== 2) throw new Refusal("REFUSE");
  const payload = unb64(parts[0]);
  await verifySig(await parseEngineKey(expectedKey), concat(utf8.encode(CONTEXTS.RECEIPT), payload), parts[1]);
  let p;
  try {
    p = JSON.parse(strictUtf8.decode(payload));
  } catch {
    throw new Refusal("REFUSE");
  }
  if (!p || typeof p !== "object" || Array.isArray(p)) throw new Refusal("REFUSE");
  if (p.engineId !== (await engineIdOf(unb64(expectedKey)))) throw new Refusal("REFUSE");
  for (const k of Object.keys(p)) {
    if (!(k in RECEIPT_FIELDS) || !RECEIPT_FIELDS[k](p[k])) throw new Refusal("REFUSE");
  }
  for (const k of Object.keys(RECEIPT_FIELDS)) {
    if (!RECEIPT_OPTIONAL.has(k) && !(k in p)) throw new Refusal("REFUSE");
  }
  return payload;
}

// --- The vectors ---

function cases(name, kind) {
  const f = load(name);
  assert.equal(f.kind, kind);
  assert.ok(f.cases.length > 0);
  return f.cases;
}

for (const c of cases("link-derivation.json", "LINK_DERIVATION")) {
  test(`link derivation: ${c.name}`, async () => {
    const link = await deriveLink(c.secret);
    assert.equal(b64(link.token), c.linkToken);
    assert.equal(toHex(link.psk), c.psk);
  });
}

for (const c of cases("engine-id.json", "ENGINE_ID")) {
  test(`engine id: ${c.name}`, async () => {
    assert.equal(await outcome(() => parseEngineKey(c.engineKey)), c.expect);
    if (c.expect !== "ACCEPT") return;
    const id = await engineIdOf(unb64(c.engineKey));
    assert.equal(id, c.engineId);
    assert.equal(fingerprintOf(id), c.fingerprint);
  });
}

for (const c of cases("padding.json", "PADDING")) {
  test(`padding: ${c.name}`, async () => {
    let content;
    assert.equal(await outcome(() => (content = unpad(fromHex(c.padded)))), c.expect);
    if (c.expect !== "ACCEPT") return;
    assert.equal(toHex(content), c.content);
    assert.equal(toHex(pad(content)), c.padded);
  });
}

function welcomeJSON(engineKey, sig) {
  return utf8.encode(JSON.stringify({ engineKey, sig }));
}

for (const c of cases("handshake.json", "HANDSHAKE")) {
  test(`handshake: ${c.name}`, async () => {
    const link = await deriveLink(c.secret);
    assert.equal(toHex(prologue(c.transport, link.token)), c.prologue);
    const signer = await privateKey(fromHex(c.engineSigningPrivate), "ECDSA", ["sign"]);
    assert.equal(b64(concat(SPKI_P256_PREFIX, await publicPoint(signer))), c.engineKey);
    const pageE = await privateKey(fromHex(c.pageEphemeralPrivate), "ECDH", ["deriveBits"]);
    const message1 = fromHex(c.message1);

    if (c.refusedBy === "ENGINE") {
      assert.equal(await outcome(() => engineReadMessage1(c.transport, link, message1)), c.expect);
      return;
    }

    // The page is honest in every other case: it writes message 1 itself.
    const written = await writeMessage1(c.transport, link, await publicPoint(pageE));
    assert.equal(toHex(written.message), c.message1);

    if (c.expect === "ACCEPT") {
      const { state, re } = await engineReadMessage1(c.transport, link, message1);
      const engineE = await privateKey(fromHex(c.engineEphemeralPrivate), "ECDH", ["deriveBits"]);
      const { message, keys } = await writeMessage2(state, re, engineE, welcomeJSON(c.engineKey, c.sig));
      assert.equal(toHex(message), c.message2);
      assertKeys(c, keys);
    }

    let keys;
    assert.equal(await outcome(async () => (keys = await pageReadMessage2(written.state, pageE, fromHex(c.message2)))), c.expect);
    if (c.expect === "ACCEPT") assertKeys(c, keys);
  });
}

function assertKeys(c, keys) {
  assert.equal(toHex(keys.h), c.handshakeHash);
  assert.equal(toHex(keys.k1), c.keyPageToEngine);
  assert.equal(toHex(keys.k2), c.keyEngineToPage);
}

for (const c of cases("frame.json", "FRAME")) {
  test(`frame: ${c.name}`, async () => {
    const key = fromHex(c.key);
    let content;
    assert.equal(await outcome(async () => (content = await openFrame(key, c.counter, fromHex(c.frame)))), c.expect);
    if (c.expect !== "ACCEPT") return;
    assert.equal(strictUtf8.decode(content), c.content);
    assert.equal(toHex(await sealFrame(key, c.counter, pad(utf8.encode(c.content)))), c.frame);
  });
}

const signatureCases = cases("signature.json", "SIGNATURE");
for (const c of signatureCases) {
  test(`signature: ${c.name}`, async () => {
    assert.equal(await outcome(() => verifyContext(c.context, c.publicKey, fromHex(c.message), c.sig)), c.expect);
  });
}

test("signature: every context has a valid vector", () => {
  const valid = new Set(signatureCases.filter((c) => c.expect === "ACCEPT").map((c) => c.context));
  assert.deepEqual([...valid].sort(), Object.keys(CONTEXTS).sort());
});

for (const c of cases("receipt.json", "RECEIPT")) {
  test(`receipt: ${c.name}`, async () => {
    let payload;
    assert.equal(await outcome(async () => (payload = await verifyReceipt(c.token, c.engineKey))), c.expect);
    if (c.expect === "ACCEPT") assert.equal(strictUtf8.decode(payload), c.payloadJson);
  });
}
