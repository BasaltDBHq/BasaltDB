// Runs with `node --test web/lib/*.test.mjs` (make web-check). The revert
// page's scope: the widen proof's challenge against the fixtures Go writes
// and the guard checks (internal/revert/testdata/fixtures.json), the scope
// route calls, and what the page may send where.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { inflateRawSync } from "node:zlib";

import { b64urlDecode, b64urlEncode, hex, parseRevertBinding, parseRevertRequest } from "./codec.js";
import {
  canWiden,
  narrow,
  newLinkSecret,
  parseCatalog,
  rescopeKey,
  scopeBody,
  selectText,
  widen,
  widenChallenge,
  widenSelect,
} from "./rescope.js";
import { sameOriginSession } from "./transport.js";

const fixtures = JSON.parse(
  readFileSync(new URL("../../internal/revert/testdata/fixtures.json", import.meta.url), "utf8"),
);
const ID = fixtures.request.revertId;
const NONCE = "AAECAwQFBgcICQoLDA0ODw";
const TASK = "0193a4c2-7d1e-7c3a-9f00-0000000000c1";

// requestObject is the fixture request as the engine serves it.
function requestObject() {
  return JSON.parse(inflateRawSync(Buffer.from(fixtures.request.fragment.slice(2), "base64url")).toString("utf8"));
}

// taskRequest is the fixture's proposal as a task scope, with the nonce the
// engine adds.
async function taskRequest() {
  const obj = requestObject();
  const binding = obj.binding.replace('"scope": "RUN"', '"scope": "TASK"').replace(/"scopeId": "[^"]+"/, `"scopeId": "${TASK}"`);
  const { checkRevertRequest } = await import("./codec.js");
  return { obj: { ...obj, binding, rescopeNonce: NONCE }, req: await checkRevertRequest({ ...obj, binding, rescopeNonce: NONCE }) };
}

test("the page's select text is the guard's normalized text (shared fixtures)", () => {
  assert.ok(fixtures.rescope.length >= 2);
  for (const f of fixtures.rescope) {
    assert.equal(selectText(f.select), f.selectText, f.name);
  }
});

test("the widen challenge matches Go's for the shared fixtures", async () => {
  for (const f of fixtures.rescope) {
    const key = await rescopeKey(b64urlDecode(f.newSecret));
    assert.equal(hex(key), f.rescopeKey, f.name);
    const challenge = await widenChallenge(f.revertId, f.nonce, key, f.selectText);
    assert.equal(b64urlEncode(challenge), f.challenge, f.name);
  }
});

test("the widen select is every agent, run and table of the task", () => {
  const b = parseRevertBinding(fixtures.request.binding.replace('"scope": "RUN"', '"scope": "TASK"'));
  assert.deepEqual(widenSelect(b), { scope: "TASK", scopeId: b.select.scopeId, agents: null, runs: null, tables: null });
});

test("Include other agents' changes is offered only for a task, from the engine, before a widen", async () => {
  const { req } = await taskRequest();
  const relay = { id: ID, secret: "s" };
  assert.equal(canWiden(req, relay, null), true);
  assert.equal(canWiden(req, null, null), false, "a long link has no engine");
  assert.equal(canWiden({ ...req, rescopeNonce: null }, relay, null), false, "no nonce, no proof");
  assert.equal(canWiden(req, relay, { agents: [], runs: [], tables: [] }), false, "already widened");
  const run = await parseRevertRequest("#" + fixtures.request.fragment);
  assert.equal(canWiden({ ...run, rescopeNonce: NONCE }, relay, null), false, "a run is one agent's");
});

test("a new link secret is 16 random bytes", () => {
  const s = newLinkSecret();
  assert.match(s, /^[A-Za-z0-9_-]{22}$/);
  assert.equal(b64urlDecode(s).length, 16);
  assert.notEqual(newLinkSecret(), s);
});

test("the scope body carries the proof fields as base64url, and nothing else", () => {
  const select = { scope: "TASK", scopeId: TASK, agents: null, runs: null, tables: null };
  assert.equal(scopeBody(select), JSON.stringify({ select }));
  const proof = {
    credentialId: new Uint8Array([1, 2]),
    authenticatorData: new Uint8Array([3]),
    clientDataJson: new Uint8Array([4]),
    signature: new Uint8Array([5]),
  };
  assert.deepEqual(JSON.parse(scopeBody(select, proof, "QEFCQ0RFRkdISUpLTE1OTw")), {
    select,
    proof: { credentialId: "AQI", authenticatorData: "Aw", clientDataJson: "BA", signature: "BQ" },
    newSecret: "QEFCQ0RFRkdISUpLTE1OTw",
  });
});

test("the catalog is checked before the page uses it", () => {
  const ok = {
    agents: [{ agent: "basalt_agent_bot", changes: 2 }],
    runs: [{ runId: TASK, agent: "basalt_agent_bot", startedAt: "2026-11-11T06:00:00Z", changes: 2 }],
    tables: [{ table: "public.leads", rows: 3 }],
  };
  const c = parseCatalog(ok);
  assert.equal(c.runs[0].startedAt.toISOString(), "2026-11-11T06:00:00.000Z");
  assert.equal(parseCatalog(undefined), null);
  assert.throws(() => parseCatalog({ ...ok, extra: 1 }), /catalog/);
  assert.throws(() => parseCatalog({ ...ok, runs: [{ ...ok.runs[0], runId: "x" }] }), /catalog/);
  assert.throws(() => parseCatalog({ ...ok, tables: [{ table: "public.leads", rows: -1 }] }), /catalog/);
  assert.equal(c.changeAgents, null, "a guard older than version 32 sends no map");

  const mapped = parseCatalog({ ...ok, changeAgents: { [TASK]: "basalt_agent_bot" } });
  assert.deepEqual([...mapped.changeAgents], [[TASK, "basalt_agent_bot"]]);
  assert.throws(() => parseCatalog({ ...ok, changeAgents: { "not-a-uuid": "basalt_agent_bot" } }), /catalog/);
  assert.throws(() => parseCatalog({ ...ok, changeAgents: { [TASK]: "" } }), /catalog/);
  assert.throws(() => parseCatalog({ ...ok, changeAgents: [] }), /catalog/);
  assert.throws(() => parseCatalog({ ...ok, changeAgents: null }), /catalog/);
});

// fakeEngine answers the scope route with answer(body) and records calls.
function fakeEngine(answer) {
  const calls = [];
  const fetchFn = async (path, init) => {
    calls.push({ path, init });
    const { status, body } = await answer(JSON.parse(init.body));
    return new Response(JSON.stringify(body), { status });
  };
  return { calls, fetchFn };
}

// fakePasskey signs whatever challenge it gets and records it.
function fakePasskey() {
  const seen = [];
  const get = async (options) => {
    seen.push(options);
    return {
      rawId: new Uint8Array([9, 9]).buffer,
      response: {
        authenticatorData: new Uint8Array([1]).buffer,
        clientDataJSON: new Uint8Array([2]).buffer,
        signature: new Uint8Array([3]).buffer,
      },
    };
  };
  return { seen, get };
}

const CATALOG = {
  agents: [{ agent: "basalt_agent_bot", changes: 2 }, { agent: "basalt_agent_sync", changes: 1 }],
  runs: [{ runId: TASK, agent: "basalt_agent_sync", startedAt: "2026-11-11T06:00:00Z", changes: 1 }],
  tables: [{ table: "public.leads", rows: 3 }],
};

test("a widen asks the passkey over the widen challenge, then posts the proof with the new secret to the engine only", async () => {
  const { obj, req } = await taskRequest();
  const engine = fakeEngine(async () => ({ status: 200, body: { request: { ...obj, rescopeNonce: "BBECAwQFBgcICQoLDA0ODw" }, catalog: CATALOG } }));
  const pk = fakePasskey();
  const out = await widen({ req, rpId: "localhost", secret: "oldSecret", session: sameOriginSession(engine.fetchFn), getAssertion: pk.get });

  assert.equal(pk.seen.length, 1);
  assert.equal(engine.calls.length, 1);
  const [call] = engine.calls;
  assert.equal(call.path, `/api/v1/reverts/${ID}/scope`);
  assert.equal(call.init.method, "POST");
  assert.equal(call.init.headers["basalt-link-secret"], "oldSecret", "the widen goes under the current link");
  const body = JSON.parse(call.init.body);
  assert.deepEqual(Object.keys(body), ["select", "proof", "newSecret"]);
  assert.equal(out.secret, body.newSecret, "the page continues under the new secret");
  assert.notEqual(out.secret, "oldSecret");

  // The passkey signed exactly the widen challenge for that secret.
  const key = await rescopeKey(b64urlDecode(body.newSecret));
  const want = await widenChallenge(ID, NONCE, key, selectText(widenSelect(req.binding)));
  assert.deepEqual(new Uint8Array(pk.seen[0].publicKey.challenge), want);
  assert.equal(pk.seen[0].publicKey.rpId, "localhost");
  assert.equal(pk.seen[0].publicKey.userVerification, "required");
  assert.equal(body.proof.credentialId, "CQk");

  // The new secret goes nowhere but that body: not the path, not a header,
  // not the passkey prompt.
  assert.ok(!call.path.includes(body.newSecret));
  assert.ok(!Object.values(call.init.headers).includes(body.newSecret));
  assert.ok(!JSON.stringify(pk.seen[0], (k, v) => (v instanceof ArrayBuffer || ArrayBuffer.isView(v) ? b64urlEncode(new Uint8Array(v.buffer ?? v)) : v)).includes(body.newSecret));

  assert.equal(out.req.rescopeNonce, "BBECAwQFBgcICQoLDA0ODw");
  assert.equal(out.catalog.agents.length, 2);
});

test("no passkey, no widen: a cancelled prompt sends nothing", async () => {
  const { req } = await taskRequest();
  const engine = fakeEngine(async () => ({ status: 200, body: {} }));
  const cancel = async () => {
    throw Object.assign(new Error("cancelled"), { name: "NotAllowedError" });
  };
  await assert.rejects(widen({ req, rpId: "localhost", secret: "s", session: sameOriginSession(engine.fetchFn), getAssertion: cancel }), { name: "NotAllowedError" });
  assert.equal(engine.calls.length, 0);
  // Nor without the nonce the proof must name.
  await assert.rejects(
    widen({ req: { ...req, rescopeNonce: null }, rpId: "localhost", secret: "s", session: sameOriginSession(engine.fetchFn), getAssertion: fakePasskey().get }),
    /nonce/,
  );
  assert.equal(engine.calls.length, 0);
});

test("a narrow posts only the select, never a proof or secret, under the current link", async () => {
  const { obj, req } = await taskRequest();
  const engine = fakeEngine(async () => ({ status: 200, body: { request: obj } }));
  const select = { ...widenSelect(req.binding), agents: ["basalt_agent_bot"], tables: ["public.leads"] };
  const out = await narrow({ req, secret: "s", session: sameOriginSession(engine.fetchFn), select });
  assert.equal(engine.calls.length, 1);
  assert.equal(engine.calls[0].init.headers["basalt-link-secret"], "s");
  assert.deepEqual(JSON.parse(engine.calls[0].init.body), { select });
  assert.equal(out.catalog, null);
  assert.equal(out.req.revertId, ID);
});

test("an answer for another revert, or one that does not hash, is refused", async () => {
  const { obj, req } = await taskRequest();
  const other = fakeEngine(async () => ({ status: 200, body: { request: { ...obj, binding: obj.binding.replace(ID, "0193a4c2-7d1e-7c3a-9f00-0000000000ff"), revertId: "0193a4c2-7d1e-7c3a-9f00-0000000000ff" } } }));
  await assert.rejects(narrow({ req, secret: "s", session: sameOriginSession(other.fetchFn), select: widenSelect(req.binding) }), /another revert/);
  const lines = [...obj.lines];
  lines[3] = lines[3].replace('"won"', '"lost"');
  const tampered = fakeEngine(async () => ({ status: 200, body: { request: { ...obj, lines } } }));
  await assert.rejects(narrow({ req, secret: "s", session: sameOriginSession(tampered.fetchFn), select: widenSelect(req.binding) }), /rowsHash/);
});

test("a refused scope comes back as the engine's error", async () => {
  const { req } = await taskRequest();
  const engine = fakeEngine(async () => ({
    status: 404,
    body: { code: "NOT_FOUND", reason: "LINK_RESET", message: "reset", personMessage: "The agent reset this revert to its own work." },
  }));
  await assert.rejects(narrow({ req, secret: "s", session: sameOriginSession(engine.fetchFn), select: widenSelect(req.binding) }), (err) => {
    assert.equal(err.reason, "LINK_RESET");
    return true;
  });
});
