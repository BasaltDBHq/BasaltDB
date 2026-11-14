// Runs with `node --test web/lib/*.test.mjs` (make web-check). The
// registration page's hand-back to basalt init: the pairing code it shows
// once init took the passkey, and what it says when init is gone.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { b64urlDecode } from "./codec.js";
import { SECRET_HEADER } from "./local.js";
import { sameOriginSession } from "./transport.js";
// Imported before any document exists, so the page's main() does not run.
import { HAND_BACK_PATH, sendToInit } from "./register.js";

const vectors = JSON.parse(readFileSync(new URL("../../api/mcp/passkey/pairing-code.json", import.meta.url), "utf8"));

function fakeDocument() {
  const nodes = {};
  for (const id of ["action", "register", "status", "done", "done-text", "pairing", "pairing-code", "result", "code", "copy", "share"]) {
    nodes[id] = { hidden: id === "done" || id === "pairing" || id === "result", textContent: "", value: "", disabled: false };
    nodes[id].addEventListener = () => {};
  }
  globalThis.document = { getElementById: (id) => nodes[id] };
  return nodes;
}

// A registration whose key is a vector's: SPKI is a fixed P-256 header,
// then 0x04 || x || y.
function vectorRegistration(v) {
  const spkiHeader = Uint8Array.from([
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
  ]);
  const publicKey = new Uint8Array([...spkiHeader, ...b64urlDecode(v.x), ...b64urlDecode(v.y)]);
  return {
    req: { challenge: b64urlDecode(v.challenge), handBack: "q3Jv8sLk2mT0xYp1aBcD9w" },
    fields: {
      credentialId: b64urlDecode(v.credentialId),
      clientDataJson: new Uint8Array([123, 125]),
      authenticatorData: new Uint8Array(37),
      publicKey,
      publicKeyAlgorithm: -7,
    },
  };
}

test("after init takes the passkey, the page shows the pairing code to type", async () => {
  const nodes = fakeDocument();
  const v = vectors.codes[0];
  const { req, fields } = vectorRegistration(v);
  const calls = [];
  const fetchFn = async (path, init) => {
    calls.push({ path, init });
    // No code is on the page while the post is in flight.
    assert.equal(nodes["pairing-code"].textContent, "");
    return new Response(JSON.stringify({ status: "RECEIVED" }), { status: 200 });
  };
  assert.equal(await sendToInit(sameOriginSession(fetchFn), req, fields), true);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].path, HAND_BACK_PATH);
  assert.equal(calls[0].init.headers[SECRET_HEADER], req.handBack);
  assert.match(nodes["pairing-code"].textContent, /^[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}$/);
  assert.equal(nodes["pairing-code"].textContent, v.code);
  assert.equal(nodes.pairing.hidden, false);
  assert.match(nodes["done-text"].textContent, /Type or paste this code into basalt init/);
  assert.equal(nodes.action.hidden, true);
  assert.equal(nodes.result.hidden, true, "no long code to paste");
});

test("handBack after init ended: the page says init is no longer waiting", async () => {
  for (const fetchFn of [
    async () => new Response(JSON.stringify({ code: "NOT_FOUND", message: "this registration link is not the one basalt init is waiting for" }), { status: 404 }),
    async () => {
      throw new TypeError("Failed to fetch");
    },
  ]) {
    const nodes = fakeDocument();
    const { req, fields } = vectorRegistration(vectors.codes[1]);
    assert.equal(await sendToInit(sameOriginSession(fetchFn), req, fields), true);
    assert.match(nodes["done-text"].textContent, /basalt init is no longer waiting; run it again/);
    assert.doesNotMatch(nodes["done-text"].textContent, /sent to basalt init|Type or paste/);
    assert.equal(nodes.pairing.hidden, true, "no pairing code: init has nothing to match it with");
    assert.equal(nodes["pairing-code"].textContent, "");
  }
});

test("a post init refuses falls back to the long code", async () => {
  const nodes = fakeDocument();
  const { req, fields } = vectorRegistration(vectors.codes[2]);
  const fetchFn = async () =>
    new Response(JSON.stringify({ code: "RATE_LIMITED", message: "basalt init received more passkeys than it takes" }), { status: 429 });
  assert.equal(await sendToInit(sameOriginSession(fetchFn), req, fields), false);
  assert.match(nodes["done-text"].textContent, /basalt init did not take the passkey \(basalt init received more/);
  assert.equal(nodes.pairing.hidden, true);
  assert.equal(nodes["pairing-code"].textContent, "");
});
