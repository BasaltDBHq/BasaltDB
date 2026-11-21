// Runs with `node --test web/lib/*.test.mjs` (make web-check). The RELAY
// transport (relay.js) the portal pages open a short link's session with:
// where its socket goes, what each way a session ends shows the person,
// and the session the pages use (one request in flight, headers, reopening,
// close). The whole session against an engine through the Go fake Vault is
// internal/engine's TestPortalChannelClientAgainstFakeVault.
import { test } from "node:test";
import assert from "node:assert/strict";

import { ChannelError, CLOSE, fingerprint, linkKeys, MAX_REQUESTS } from "./channel.js";
import { fetchRequest, postResponse, RelayError } from "./local.js";
import { BUSY, ENGINE_CHANGED, ENGINE_NOT_CONNECTED, linkSocketURL, relayTransport, VAULT_UNREACHABLE } from "./relay.js";
import { pageTransport } from "./transport.js";

const SECRET = "oo3hsfnTW0SXS80SkQL_vQ";
const OTHER_SECRET = "AAAAAAAAAAAAAAAAAAAAAA";
const ENGINE = "R68WFYxAcGgIjMENS5Oqrw";
const PATH = "/api/v1/approvals/0192f3a0-7c1e-7b2a-9c4d-5e6f708192a3";

// FakeSocket is a WebSocket the test closes before it opens.
class FakeSocket extends EventTarget {
  constructor(url) {
    super();
    this.url = url;
    this.sent = [];
  }

  send(data) {
    this.sent.push(data);
  }

  close() {}

  remoteClose(code) {
    const ev = new Event("close");
    ev.code = code;
    this.dispatchEvent(ev);
  }
}

// opening runs open(link) on a transport whose socket closes with code
// before it opens, and returns the error and the sockets made.
async function refusedWith(code) {
  const sockets = [];
  const transport = relayTransport({
    socket: (url) => {
      const ws = new FakeSocket(url);
      sockets.push(ws);
      setTimeout(() => ws.remoteClose(code), 0);
      return ws;
    },
    pageHide: () => {},
  });
  const err = await transport.open({ page: "approvals", id: "x", secret: SECRET }).then(
    () => assert.fail("opened"),
    (e) => e,
  );
  return { err, sockets };
}

test("the socket goes to the Vault's link path with the link token only", async () => {
  const { tokenText } = await linkKeys(SECRET);
  const { sockets } = await refusedWith(1006);
  assert.equal(sockets.length, 1);
  assert.equal(sockets[0].url, `wss://relay.basaltvault.app/v1/links/${tokenText}`);
  assert.equal(sockets[0].url, linkSocketURL(tokenText));
  assert.ok(!sockets[0].url.includes(SECRET), "never the secret");
  assert.equal(sockets[0].sent.length, 0, "nothing before the socket opens");
});

test("a link whose secret is not 16 bytes opens no socket", async () => {
  const sockets = [];
  const transport = relayTransport({ socket: (url) => sockets.push(url), pageHide: () => {} });
  await assert.rejects(transport.open({ page: "approvals", id: "x", secret: "short" }), (e) => e.code === "NOT_FOUND" && e.reason === "LINK");
  assert.equal(sockets.length, 0);
});

// What each end shows (CONTRACT.md, Close codes, "The page shows"); every
// one is a RelayError, so the pages' retry loop stops on it.
test("each way a session cannot open says what to do", async () => {
  const cases = [
    [CLOSE.LINK_REFUSED, "NOT_FOUND", ""],
    [CLOSE.LINK_UNKNOWN, "NOT_FOUND", ""],
    [CLOSE.ENGINE_OFFLINE, "UNAVAILABLE", ENGINE_NOT_CONNECTED],
    [CLOSE.ENGINE_SHUTDOWN, "UNAVAILABLE", ENGINE_NOT_CONNECTED],
    [CLOSE.ENGINE_REVOKED, "UNAVAILABLE", ENGINE_NOT_CONNECTED],
    [CLOSE.RATE_LIMITED, "UNAVAILABLE", BUSY],
    [CLOSE.SESSION_LIMIT, "UNAVAILABLE", BUSY],
    [CLOSE.TIMEOUT, "UNAVAILABLE", BUSY],
    [1006, "UNAVAILABLE", VAULT_UNREACHABLE],
    [CLOSE.PROTOCOL, "UNAVAILABLE", null],
    [CLOSE.HANDSHAKE_FAILED, "UNAVAILABLE", null],
  ];
  for (const [code, want, message] of cases) {
    const { err } = await refusedWith(code);
    assert.ok(err instanceof RelayError, String(code));
    assert.equal(err.code, want, String(code));
    if (want === "NOT_FOUND") assert.equal(err.reason, "LINK", String(code));
    if (message) assert.equal(err.personMessage, message, String(code));
    if (message === null) assert.match(err.personMessage, /Open the link again/, String(code));
    if (code === 1006) assert.match(err.personMessage, /long link/);
  }
});

// The whole portal path, with the browser's globals as the page has them:
// one socket to the Vault and no fetch, to localhost or anywhere.
test("on the portal no code path fetches or opens a socket to localhost", async () => {
  const sockets = [];
  const fetches = [];
  const saved = globalThis.window;
  globalThis.window = {
    location: { origin: "https://portal.basaltvault.app" },
    addEventListener: () => {},
    fetch: (...args) => {
      fetches.push(args);
      return Promise.reject(new TypeError("blocked"));
    },
    WebSocket: class extends FakeSocket {
      constructor(url) {
        super(url);
        sockets.push(url);
        setTimeout(() => this.remoteClose(1006), 0);
      }
    },
  };
  try {
    const transport = pageTransport();
    assert.equal(transport.kind, "RELAY");
    await assert.rejects(transport.open({ page: "approvals", id: "x", secret: SECRET }), RelayError);
  } finally {
    globalThis.window = saved;
  }
  assert.equal(fetches.length, 0);
  assert.equal(sockets.length, 1);
  const url = new URL(sockets[0]);
  assert.equal(url.origin, "wss://relay.basaltvault.app");
  for (const host of ["localhost", "127.0.0.1", "[::1]"]) assert.ok(!sockets[0].includes(host), host);
});

// fakeChannel is a channel.js session the test drives: requests resolve
// with answer(req) unless the test ended it.
function fakeChannel(engineId, answer) {
  const ch = {
    engineId,
    ended: null,
    nextId: 0,
    requests: [],
    closed: false,
    async request(method, path, headers, body) {
      if (ch.ended !== null) throw ch.ended;
      ch.nextId++;
      const req = { method, path, headers, body };
      ch.requests.push(req);
      return answer(req, ch);
    },
    close() {
      ch.closed = true;
      if (ch.ended === null) ch.ended = new ChannelError("CLOSED");
    },
  };
  return ch;
}

const ok = (body = "{}") => ({ status: 200, headers: { "content-type": "application/json" }, body });

// sessionWith opens a RELAY session whose channels come from make(secret).
async function sessionWith(make) {
  const opened = [];
  let hide = null;
  const transport = relayTransport({
    socket: () => assert.fail("no socket: open is faked"),
    open: async (_connect, { transport: t, secret }) => {
      assert.equal(t, "RELAY");
      const ch = await make(secret, opened.length);
      opened.push({ secret, ch });
      return ch;
    },
    pageHide: (fn) => (hide = fn),
  });
  const session = await transport.open({ page: "reverts", id: "x", secret: SECRET });
  return { session, opened, hide: () => hide() };
}

test("a request carries the contract's headers only, from the portal's origin", async () => {
  const { session, opened } = await sessionWith(() => fakeChannel(ENGINE, () => ok()));
  assert.equal(session.transport, "RELAY");
  await session.request("POST", PATH, { "basalt-link-secret": SECRET, "content-type": "application/json", accept: "*/*", cookie: "x" }, "{}");
  assert.deepEqual(opened[0].ch.requests[0], {
    method: "POST",
    path: PATH,
    headers: { "basalt-link-secret": SECRET, "content-type": "application/json", origin: "https://portal.basaltvault.app" },
    body: "{}",
  });
  await session.request("GET", PATH, { "basalt-link-secret": SECRET });
  assert.deepEqual(opened[0].ch.requests[1].headers, { "basalt-link-secret": SECRET, origin: "https://portal.basaltvault.app" });
  assert.equal(opened[0].ch.requests[1].body, "");
});

test("the session names the engine by the key it verified, with its fingerprint", async () => {
  const { session } = await sessionWith(() => fakeChannel(ENGINE, () => ok()));
  assert.deepEqual(session.engine, { engineId: ENGINE, fingerprint: "R68W FYxA cGgI jMEN" });
  assert.equal(session.engine.fingerprint, fingerprint(ENGINE));
});

test("one request is in flight at a time", async () => {
  let inFlight = 0;
  let most = 0;
  const { session } = await sessionWith(() =>
    fakeChannel(ENGINE, async () => {
      inFlight++;
      most = Math.max(most, inFlight);
      await new Promise((r) => setTimeout(r, 5));
      inFlight--;
      return ok();
    }),
  );
  await Promise.all([1, 2, 3].map(() => session.request("GET", PATH, { "basalt-link-secret": SECRET })));
  assert.equal(most, 1);
});

test("an HTTP refusal is an answer, not a failure", async () => {
  const { session } = await sessionWith(() => fakeChannel(ENGINE, () => ({ status: 404, headers: {}, body: '{"code":"NOT_FOUND"}' })));
  assert.equal((await session.request("GET", PATH, { "basalt-link-secret": SECRET })).status, 404);
});

test("a dropped session reopens before the next request, with that request's secret", async () => {
  const { session, opened } = await sessionWith(() => fakeChannel(ENGINE, () => ok()));
  opened[0].ch.ended = new ChannelError("TIMEOUT");
  // After a widen the revert's requests carry the new secret: that is the
  // one the new session opens with, never the link the page opened.
  await session.request("POST", PATH + "/scope", { "basalt-link-secret": OTHER_SECRET, "content-type": "application/json" }, "{}");
  assert.equal(opened.length, 2);
  assert.equal(opened[0].secret, SECRET);
  assert.equal(opened[1].secret, OTHER_SECRET);
  assert.equal(opened[1].ch.requests.length, 1);
});

test("a session that used its requests opens a new one before the next", async () => {
  const { session, opened } = await sessionWith(() => fakeChannel(ENGINE, () => ok()));
  opened[0].ch.nextId = MAX_REQUESTS;
  await session.request("GET", PATH, { "basalt-link-secret": SECRET });
  assert.equal(opened.length, 2);
  assert.ok(opened[0].ch.closed);
});

test("a POST that fails in flight is never sent again", async () => {
  const { session, opened } = await sessionWith(() =>
    fakeChannel(ENGINE, (_req, ch) => {
      ch.ended = new ChannelError("FRAME_INVALID");
      throw ch.ended;
    }),
  );
  await assert.rejects(postResponse(session, PATH + "/approve", SECRET, "{}"), RelayError);
  assert.equal(opened.length, 1);
  assert.equal(opened[0].ch.requests.length, 1);
});

test("a GET that fails in flight is read again over a new session", async () => {
  const { session, opened } = await sessionWith((_s, n) =>
    fakeChannel(ENGINE, (_req, ch) => {
      if (n === 0) {
        ch.ended = new ChannelError("FRAME_INVALID");
        throw ch.ended;
      }
      return ok('{"approvalId":"x"}');
    }),
  );
  const body = await fetchRequest(session, PATH, SECRET, async () => {});
  assert.deepEqual(body, { approvalId: "x" });
  assert.equal(opened.length, 2);
});

test("a link refused in flight stops the retries and reads as a link that is gone", async () => {
  const { session, opened } = await sessionWith(() =>
    fakeChannel(ENGINE, (_req, ch) => {
      ch.ended = new ChannelError("LINK_REFUSED");
      throw ch.ended;
    }),
  );
  await assert.rejects(fetchRequest(session, PATH, SECRET, async () => {}), (e) => e.code === "NOT_FOUND" && e.reason === "LINK");
  assert.equal(opened.length, 1);
});

test("a reopen that the Vault refuses stops the retries", async () => {
  const { session, opened } = await sessionWith((_s, n) => {
    if (n > 0) throw new ChannelError("ENGINE_OFFLINE");
    return fakeChannel(ENGINE, (_req, ch) => {
      ch.ended = new ChannelError("CONNECTION_FAILED");
      throw ch.ended;
    });
  });
  await assert.rejects(fetchRequest(session, PATH, SECRET, async () => {}), (e) => e.personMessage === ENGINE_NOT_CONNECTED);
  assert.equal(opened.length, 1, "the failed reopen made no channel");
});

test("a reopen that reaches another engine key is never used", async () => {
  const { session, opened } = await sessionWith((_s, n) => fakeChannel(n === 0 ? ENGINE : "AAAAAAAAAAAAAAAAAAAAAA", () => ok()));
  opened[0].ch.ended = new ChannelError("TIMEOUT");
  await assert.rejects(session.request("GET", PATH, { "basalt-link-secret": SECRET }), (e) => e.personMessage === ENGINE_CHANGED);
  assert.ok(opened[1].ch.closed);
  assert.equal(opened[1].ch.requests.length, 0);
});

test("a closed session sends nothing, and the pages do not retry it", async () => {
  const { session, opened } = await sessionWith(() => fakeChannel(ENGINE, () => ok()));
  session.close();
  assert.ok(opened[0].ch.closed);
  await assert.rejects(fetchRequest(session, PATH, SECRET, async () => {}), (e) => e instanceof RelayError && e.code === "CLOSED");
  assert.equal(opened.length, 1);
  assert.equal(opened[0].ch.requests.length, 0);
});

test("hiding the page ends its channel; a page shown again opens a new one", async () => {
  const { session, opened, hide } = await sessionWith(() => fakeChannel(ENGINE, () => ok()));
  hide();
  assert.ok(opened[0].ch.closed);
  assert.equal(opened.length, 1, "nothing is opened while the page is hidden");
  await session.request("GET", PATH, { "basalt-link-secret": SECRET });
  assert.equal(opened.length, 2);
  assert.equal(opened[0].ch.requests.length, 0);
});
