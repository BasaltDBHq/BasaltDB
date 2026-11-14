// The DIRECT transport's choice of engine and what the page says when none
// opens a session. The session itself is channel.js's, run against the Go
// engine in internal/vault/direct_page_test.go; here a fake stands in.
import { test } from "node:test";
import assert from "node:assert/strict";
import { ChannelError } from "./channel.js";
import { directTransport, failure, policyAllows } from "./direct.js";
import { RelayError } from "./local.js";

const KEY_A = "A".repeat(122);
const KEY_B = "B".repeat(122);
const ID_A = "a".repeat(22);
const ID_B = "b".repeat(22);
const SECRET = "oo3hsfnTW0SXS80SkQL_vQ";

function pin(address, engineKey, engineId, lastUsedAt = null) {
  return { address, engineKey, engineId, addedAt: "2026-11-14T10:00:00Z", lastUsedAt };
}

function fakeStore(pins, inCookie = true) {
  const s = { pins, touched: [], synced: 0, cookieOk: inCookie };
  return Object.assign(s, {
    list: () => s.pins,
    touch: (a) => s.touched.push(a),
    inCookie: () => s.cookieOk,
    syncCookie: () => {
      s.synced++;
    },
  });
}

// fakeNet answers probes from answers (address -> engineKey, or a status)
// and records every probe and socket.
function fakeNet(answers) {
  const probes = [];
  const sockets = [];
  return {
    probes,
    sockets,
    fetchFn: async (url, init) => {
      probes.push({ url, init });
      const a = answers[new URL(url).origin];
      if (a === undefined) throw new TypeError("failed to fetch");
      if (typeof a === "number") return new Response("", { status: a });
      return new Response(JSON.stringify({ engineKey: a, engineId: "x" }), { status: 200 });
    },
    socket: (url) => {
      sockets.push(url);
      return {};
    },
  };
}

// fakeOpen opens a fake channel per address, or fails with the code given.
function fakeOpen(results) {
  const calls = [];
  const open = async (connect, opts) => {
    connect();
    calls.push(opts);
    const r = results.shift();
    if (typeof r === "string") throw new ChannelError(r);
    return r;
  };
  return { calls, open };
}

function fakeChannel() {
  const c = { sent: [], ended: null, closed: false };
  c.request = async (method, path, headers, body) => {
    c.sent.push({ method, path, headers, body });
    return { status: 200, headers: {}, body: "{}" };
  };
  c.close = () => {
    c.closed = true;
  };
  return c;
}

test("it probes the pin used last first, then opens its session with the pinned key", async () => {
  const store = fakeStore([pin("https://old.example.com", KEY_B, ID_B, "2026-11-01T00:00:00Z"), pin("https://new.example.com", KEY_A, ID_A, "2026-11-13T00:00:00Z")]);
  const net = fakeNet({ "https://new.example.com": KEY_A, "https://old.example.com": KEY_B });
  const ch = fakeChannel();
  const { calls, open } = fakeOpen([ch]);
  const t = directTransport({ store, fetchFn: net.fetchFn, socket: net.socket, open });
  const session = await t.open({ page: "approvals", id: "x", secret: SECRET });
  assert.equal(net.probes.length, 1);
  assert.equal(net.probes[0].url, "https://new.example.com/v1/engine");
  assert.equal(net.probes[0].init.credentials, "omit");
  assert.equal(net.probes[0].init.cache, "no-store");
  assert.deepEqual(net.sockets, ["wss://new.example.com/v1/session"]);
  assert.deepEqual(calls, [{ transport: "DIRECT", secret: SECRET, expectEngineId: ID_A }]);
  assert.deepEqual(store.touched, ["https://new.example.com"]);
  assert.deepEqual(session.engine, { address: "https://new.example.com", engineId: ID_A });

  const res = await session.request("GET", "/api/v1/approvals/x", { "basalt-link-secret": SECRET });
  assert.equal(res.status, 200);
  assert.deepEqual(ch.sent[0].headers, { "basalt-link-secret": SECRET, origin: "https://portal.basaltvault.app" });
  assert.equal(ch.sent[0].body, "");
});

test("an address that answers with another key is never connected to, and the page says so", async () => {
  const store = fakeStore([pin("https://engine.example.com", KEY_A, ID_A)]);
  const net = fakeNet({ "https://engine.example.com": KEY_B });
  const { calls, open } = fakeOpen([]);
  const t = directTransport({ store, fetchFn: net.fetchFn, socket: net.socket, open });
  await assert.rejects(t.open({ page: "approvals", id: "x", secret: SECRET }), (e) => {
    assert.ok(e instanceof RelayError);
    assert.equal(e.code, "UNAVAILABLE");
    assert.match(e.personMessage, /different engine than the one this device pinned/);
    assert.match(e.personMessage, /basalt engine list --admin/);
    return true;
  });
  assert.equal(calls.length, 0);
  assert.equal(net.sockets.length, 0);
});

test("a refused link or a revoked engine moves on to the next pin", async () => {
  const store = fakeStore([
    pin("https://a.example.com", KEY_A, ID_A, "2026-11-13T00:00:00Z"),
    pin("https://b.example.com", KEY_B, ID_B, "2026-11-12T00:00:00Z"),
    pin("https://c.example.com", KEY_B, ID_B, "2026-11-11T00:00:00Z"),
  ]);
  const net = fakeNet({ "https://a.example.com": KEY_A, "https://b.example.com": KEY_B, "https://c.example.com": KEY_B });
  const ch = fakeChannel();
  const { open } = fakeOpen(["LINK_REFUSED", "ENGINE_REVOKED", ch]);
  const t = directTransport({ store, fetchFn: net.fetchFn, socket: net.socket, open });
  const session = await t.open({ page: "reverts", id: "x", secret: SECRET });
  assert.equal(session.engine.address, "https://c.example.com");
});

test("when every pin refuses the link, it is gone: NOT_FOUND reason LINK", async () => {
  const store = fakeStore([pin("https://a.example.com", KEY_A, ID_A)]);
  const net = fakeNet({ "https://a.example.com": KEY_A });
  const { open } = fakeOpen(["LINK_REFUSED"]);
  const t = directTransport({ store, fetchFn: net.fetchFn, socket: net.socket, open });
  await assert.rejects(t.open({ page: "approvals", id: "x", secret: SECRET }), (e) => e.code === "NOT_FOUND" && e.reason === "LINK");
});

test("a revoked engine is reported, with its pin left as it is", async () => {
  const store = fakeStore([pin("https://a.example.com", KEY_A, ID_A)]);
  const net = fakeNet({ "https://a.example.com": KEY_A });
  const { open } = fakeOpen(["ENGINE_REVOKED"]);
  const t = directTransport({ store, fetchFn: net.fetchFn, socket: net.socket, open });
  await assert.rejects(t.open({ page: "approvals", id: "x", secret: SECRET }), (e) => /may have been revoked/.test(e.personMessage));
  assert.equal(store.pins.length, 1);
});

test("an address that does not answer, or not with a key, is skipped", async () => {
  const store = fakeStore([pin("https://a.example.com", KEY_A, ID_A), pin("https://b.example.com", KEY_B, ID_B)]);
  const net = fakeNet({ "https://b.example.com": 404 });
  const { open } = fakeOpen([]);
  const t = directTransport({ store, fetchFn: net.fetchFn, socket: net.socket, open });
  await assert.rejects(t.open({ page: "approvals", id: "x", secret: SECRET }), (e) => {
    assert.equal(e.code, "UNAVAILABLE");
    assert.match(e.personMessage, /could not reach your engine/);
    assert.match(e.personMessage, /https:\/\/portal\.basaltvault\.app\/engines\/add/);
    return true;
  });
  assert.equal(net.probes.length, 2);
});

test("a device with no pins is told how to go on", () => {
  const e = failure([], []);
  assert.match(e.personMessage, /has not pinned one yet/);
  assert.match(e.personMessage, /basalt approve or basalt revert/);
});

test("a stale pins cookie is rewritten and the page reloads before any probe", async () => {
  const store = fakeStore([pin("https://a.example.com", KEY_A, ID_A)], false);
  const net = fakeNet({ "https://a.example.com": KEY_A });
  const { open } = fakeOpen([fakeChannel()]);
  let reloads = 0;
  const t = directTransport({ store, fetchFn: net.fetchFn, socket: net.socket, open, onStaleCookie: () => ++reloads > 0 });
  const pending = t.open({ page: "approvals", id: "x", secret: SECRET });
  await new Promise((r) => setTimeout(r, 10));
  assert.equal(store.synced, 1);
  assert.equal(reloads, 1);
  assert.equal(net.probes.length, 0, "nothing reached the network while the page reloads");
  void pending;
});

test("a stale cookie that cannot reload goes on with the pins", async () => {
  const store = fakeStore([pin("https://a.example.com", KEY_A, ID_A)], false);
  const net = fakeNet({ "https://a.example.com": KEY_A });
  const { open } = fakeOpen([fakeChannel()]);
  const t = directTransport({ store, fetchFn: net.fetchFn, socket: net.socket, open, onStaleCookie: () => false });
  await t.open({ page: "approvals", id: "x", secret: SECRET });
  assert.equal(store.synced, 1);
});

test("an ended session reopens on the next request with the secret it carries", async () => {
  const store = fakeStore([pin("https://a.example.com", KEY_A, ID_A)]);
  const net = fakeNet({ "https://a.example.com": KEY_A });
  const first = fakeChannel();
  const second = fakeChannel();
  const { calls, open } = fakeOpen([first, second]);
  const t = directTransport({ store, fetchFn: net.fetchFn, socket: net.socket, open });
  const session = await t.open({ page: "reverts", id: "x", secret: SECRET });
  first.ended = new ChannelError("TIMEOUT");
  const widened = "AAAAAAAAAAAAAAAAAAAAAA";
  await session.request("POST", "/api/v1/reverts/x/apply", { "basalt-link-secret": widened, "content-type": "application/json" }, "{}");
  assert.equal(calls[1].secret, widened);
  assert.equal(second.sent.length, 1);
  assert.equal(net.probes.length, 1, "no new probe: the session goes back to the pin that opened it");
});

test("a session that cannot reopen because the link is gone is a final answer", async () => {
  const store = fakeStore([pin("https://a.example.com", KEY_A, ID_A)]);
  const net = fakeNet({ "https://a.example.com": KEY_A });
  const first = fakeChannel();
  const { open } = fakeOpen([first, "LINK_REFUSED"]);
  const t = directTransport({ store, fetchFn: net.fetchFn, socket: net.socket, open });
  const session = await t.open({ page: "approvals", id: "x", secret: SECRET });
  first.ended = new ChannelError("TIMEOUT");
  await assert.rejects(session.request("GET", "/api/v1/approvals/x", { "basalt-link-secret": SECRET }), (e) => e instanceof RelayError && e.code === "NOT_FOUND");
});

test("a page whose policy does not list the pins rewrites the cookie and reloads, even when the cookie looks right", async () => {
  const store = fakeStore([pin("https://a.example.com", KEY_A, ID_A)], true);
  const net = fakeNet({ "https://a.example.com": KEY_A });
  const { open } = fakeOpen([fakeChannel()]);
  let reloads = 0;
  const policy = "default-src 'none'; connect-src 'self'; base-uri 'none'";
  const t = directTransport({
    store,
    fetchFn: net.fetchFn,
    socket: net.socket,
    open,
    cspAllows: (a) => policyAllows(policy, a),
    onStaleCookie: () => ++reloads > 0,
  });
  void t.open({ page: "approvals", id: "x", secret: SECRET });
  await new Promise((r) => setTimeout(r, 10));
  assert.equal(store.synced, 1);
  assert.equal(reloads, 1);
  assert.equal(net.probes.length, 0);
});

test("policyAllows needs both the https and the wss origin of every pin", () => {
  const p = "default-src 'none'; connect-src 'self' https://a.example.com wss://a.example.com https://b.example.com; base-uri 'none'";
  assert.equal(policyAllows(p, ["https://a.example.com"]), true);
  assert.equal(policyAllows(p, ["https://a.example.com", "https://b.example.com"]), false);
  assert.equal(policyAllows("default-src 'self'", ["https://a.example.com"]), false);
  assert.equal(policyAllows(p, []), true);
});
