// The page's side of a link session against the shared vectors the Go
// engine runs too (api/mcp/vault/testdata), and its socket handling with a
// fake WebSocket.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  ChannelError,
  checkReceipt,
  CLOSE,
  engineIdOf,
  finishHandshake,
  fingerprint,
  linkKeys,
  openChannel,
  openFrame,
  pad,
  parseEngineKey,
  RELAY,
  sealFrame,
  startHandshake,
  unpad,
  verifySigned,
} from "./channel.js";

const subtle = globalThis.crypto.subtle;
const load = (name) => JSON.parse(readFileSync(new URL(`../../api/mcp/vault/testdata/${name}`, import.meta.url), "utf8"));
const fromHex = (s) => Uint8Array.from(s.match(/../g) ?? [], (b) => parseInt(b, 16));
const toHex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const PKCS8_P256_PREFIX = fromHex("308141020100301306072a8648ce3d020106082a8648ce3d030107042730250201010420");

async function outcome(fn) {
  try {
    await fn();
    return "ACCEPT";
  } catch (e) {
    if (e instanceof ChannelError) return e.code;
    throw e;
  }
}

function cases(name, kind) {
  const f = load(name);
  assert.equal(f.kind, kind);
  assert.ok(f.cases.length > 0);
  return f.cases;
}

for (const c of cases("link-derivation.json", "LINK_DERIVATION")) {
  test(`link derivation: ${c.name}`, async () => {
    const k = await linkKeys(c.secret);
    assert.equal(k.tokenText, c.linkToken);
    assert.equal(toHex(k.psk), c.psk);
  });
}

test("a secret that is not 16 bytes is refused before any socket", async () => {
  for (const s of ["", "AAAA", "AAAAAAAAAAAAAAAAAAAAAAAA", "not base64url!!!!!!!!!"]) {
    assert.equal(await outcome(() => linkKeys(s)), "LINK");
  }
});

test("message 1 is made only for the RELAY transport", async () => {
  const keys = await linkKeys(load("handshake.json").cases[0].secret);
  assert.equal((await startHandshake(RELAY, keys)).message.length, 99);
  for (const t of ["DIRECT", "relay", "", undefined]) {
    await assert.rejects(startHandshake(t, keys), /unknown transport/);
  }
});

for (const c of cases("engine-id.json", "ENGINE_ID")) {
  test(`engine id: ${c.name}`, async () => {
    const key = await parseEngineKey(c.engineKey);
    assert.equal(key === null ? "REFUSE" : "ACCEPT", c.expect === "ACCEPT" ? "ACCEPT" : "REFUSE");
    if (c.expect !== "ACCEPT") return;
    const id = await engineIdOf(c.engineKey);
    assert.equal(id, c.engineId);
    assert.equal(fingerprint(id), c.fingerprint);
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

async function ephemeral(scalarHex) {
  const privateKey = await subtle.importKey("pkcs8", new Uint8Array([...PKCS8_P256_PREFIX, ...fromHex(scalarHex)]), { name: "ECDH", namedCurve: "P-256" }, true, [
    "deriveBits",
  ]);
  return { privateKey };
}

// The page side of every handshake vector the engine does not refuse: the
// page writes the vector's message 1 and reads its message 2 as expected.
for (const c of cases("handshake.json", "HANDSHAKE").filter((c) => c.refusedBy !== "ENGINE")) {
  test(`handshake: ${c.name}`, async () => {
    const keys = await linkKeys(c.secret);
    const hs = await startHandshake(c.transport, keys, await ephemeral(c.pageEphemeralPrivate));
    assert.equal(toHex(hs.message), c.message1);
    let out;
    assert.equal(await outcome(async () => (out = await finishHandshake(hs, fromHex(c.message2)))), c.expect);
    if (c.expect !== "ACCEPT") return;
    assert.equal(toHex(out.h), c.handshakeHash);
    assert.equal(toHex(out.k1), c.keyPageToEngine);
    assert.equal(toHex(out.k2), c.keyEngineToPage);
    assert.equal(out.engineKey, c.engineKey);
    assert.equal(out.engineId, await engineIdOf(c.engineKey));
  });
}

async function frameKeys(keyHex, counter) {
  const raw = fromHex(keyHex);
  return {
    send: await subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt"]),
    receive: await subtle.importKey("raw", raw, "AES-GCM", false, ["decrypt"]),
    sent: counter,
    received: counter,
  };
}

for (const c of cases("frame.json", "FRAME")) {
  test(`frame: ${c.name}`, async () => {
    let content;
    const keys = await frameKeys(c.key, c.counter);
    assert.equal(await outcome(async () => (content = await openFrame(keys, fromHex(c.frame)))), c.expect);
    if (c.expect !== "ACCEPT") return;
    assert.equal(new TextDecoder().decode(content), c.content);
    assert.equal(keys.received, c.counter + 1);
    const sealer = await frameKeys(c.key, c.counter);
    assert.equal(toHex(await sealFrame(sealer, new TextEncoder().encode(c.content))), c.frame);
  });
}

// FakeSocket is a WebSocket the test drives: it records what the page
// sends and lets the test answer or close.
class FakeSocket extends EventTarget {
  constructor() {
    super();
    this.sent = [];
    this.closed = null;
  }

  send(data) {
    this.sent.push(data);
  }

  close(code = 1000) {
    if (this.closed !== null) return;
    this.closed = code;
    const ev = new Event("close");
    ev.code = code;
    this.dispatchEvent(ev);
  }

  open() {
    this.dispatchEvent(new Event("open"));
  }

  message(data) {
    const ev = new Event("message");
    ev.data = data;
    this.dispatchEvent(ev);
  }

  remoteClose(code) {
    const ev = new Event("close");
    ev.code = code;
    this.closed = code;
    this.dispatchEvent(ev);
  }
}

const SECRET = "oo3hsfnTW0SXS80SkQL_vQ";
const tick = () => new Promise((r) => setTimeout(r, 0));

async function untilSent(ws, n = 1) {
  for (let i = 0; i < 2000 && ws.sent.length < n; i++) await tick();
  assert.ok(ws.sent.length >= n, "the page sent message 1");
}

// opened starts openChannel and resolves once it created its socket (after
// deriving the link's keys), with the pending session.
async function opened(options) {
  const ws = new FakeSocket();
  let made;
  const connected = new Promise((r) => (made = r));
  const opening = openChannel(() => {
    made();
    return ws;
  }, options);
  opening.catch(() => {});
  await connected;
  return { ws, opening };
}

test("the page sends exactly one 99-byte message 1 after the socket opens", async () => {
  const { ws, opening } = await opened({ transport: RELAY, secret: SECRET });
  await tick();
  assert.equal(ws.sent.length, 0, "nothing before open");
  ws.open();
  await untilSent(ws);
  assert.equal(ws.sent[0].length, 99);
  assert.deepEqual([...ws.sent[0].subarray(0, 2)], [0x01, 0x01]);
  ws.remoteClose(CLOSE.LINK_REFUSED);
  await assert.rejects(opening, (e) => e.code === "LINK_REFUSED");
});

test("a text message during the handshake closes with PROTOCOL", async () => {
  const { ws, opening } = await opened({ transport: RELAY, secret: SECRET });
  ws.open();
  await untilSent(ws);
  ws.message("hello");
  await assert.rejects(opening, (e) => e.code === "PROTOCOL");
  assert.equal(ws.closed, CLOSE.PROTOCOL);
});

test("a garbled message 2 closes with HANDSHAKE_FAILED and shows nothing", async () => {
  const { ws, opening } = await opened({ transport: RELAY, secret: SECRET });
  ws.open();
  await untilSent(ws);
  const junk = new Uint8Array(2 + 65 + 16 + 10);
  junk[0] = 1;
  junk[1] = 2;
  junk[2] = 4;
  ws.message(junk.buffer);
  await assert.rejects(opening, (e) => e.code === "HANDSHAKE_FAILED");
  assert.equal(ws.closed, CLOSE.HANDSHAKE_FAILED);
});

test("a socket that never opens fails without sending", async () => {
  const { ws, opening } = await opened({ transport: RELAY, secret: SECRET });
  ws.remoteClose(1006);
  await assert.rejects(opening, (e) => e.code === "CONNECTION_FAILED");
  assert.equal(ws.sent.length, 0);
});

test("the handshake times out", async () => {
  const { ws, opening } = await opened({ transport: RELAY, secret: SECRET, handshakeMs: 200 });
  ws.open();
  await untilSent(ws);
  await assert.rejects(opening, (e) => e.code === "TIMEOUT");
  assert.equal(ws.closed, CLOSE.TIMEOUT);
});

// Every signing context: the page's verifier accepts the vectors' valid
// signatures and refuses another context, key, message or encoding.
for (const c of cases("signature.json", "SIGNATURE")) {
  test(`signature: ${c.name}`, async () => {
    const ok = await verifySigned(c.publicKey, c.context, fromHex(c.message), c.sig);
    assert.equal(ok ? "ACCEPT" : "REFUSE", c.expect);
  });
}

// Receipts, checked against the key the verifier expects (CONTRACT.md,
// Receipts): a receipt signed by another key, naming another engine, or off
// the closed schema is refused.
for (const c of cases("receipt.json", "RECEIPT")) {
  test(`receipt: ${c.name}`, async () => {
    const payload = await checkReceipt(c.token, c.engineKey);
    assert.equal(payload === null ? "REFUSE" : "ACCEPT", c.expect);
    if (c.expect !== "ACCEPT") return;
    assert.equal(payload.engineId, await engineIdOf(c.engineKey));
    if (c.payloadJson !== undefined) assert.deepEqual(payload, JSON.parse(c.payloadJson));
  });
}

test("a receipt token in another shape is refused", async () => {
  const key = cases("receipt.json", "RECEIPT")[0].engineKey;
  for (const token of ["", "basalt-receipt.1.", "basalt-receipt.2.a.b", "basalt-receipt.1.a.b.c", "basalt-receipt.1.!!.AA", null]) {
    assert.equal(await checkReceipt(token, key), null, String(token));
  }
});

test("the fingerprint is the engine id's first 16 characters in four groups of four", () => {
  assert.equal(fingerprint("R68WFYxAcGgIjMENS5Oqrw"), "R68W FYxA cGgI jMEN");
});
