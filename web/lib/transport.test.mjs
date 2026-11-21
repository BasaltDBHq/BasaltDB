// Runs with `node --test web/lib/*.test.mjs` (make web-check). The seam the
// pages reach the engine through (design: vault channel, section 4.1): the
// same-origin transport the engine's local pages use, and the shape every
// transport gives the pages.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";

import { SAME_ORIGIN, UNAVAILABLE, UNREACHABLE, pageTransport, sameOriginSession, sameOriginTransport } from "./transport.js";

function recorder(answer) {
  const calls = [];
  const fetchFn = async (path, init) => {
    calls.push({ path, init });
    return answer(path, init);
  };
  return { calls, fetchFn };
}

test("open gives a session that sends the request as a same-origin fetch", async () => {
  const { calls, fetchFn } = recorder(() => new Response('{"status":"APPROVED"}', { status: 200, headers: { "Content-Type": "application/json" } }));
  const transport = sameOriginTransport(fetchFn);
  assert.equal(transport.kind, SAME_ORIGIN);
  const session = await transport.open({ page: "approvals", id: "x", secret: "s3cr3t" });
  assert.equal(session.transport, SAME_ORIGIN);
  const res = await session.request("POST", "/api/v1/approvals/x/approve", { "basalt-link-secret": "s3cr3t", "content-type": "application/json" }, "{}");
  assert.deepEqual(res, { status: 200, headers: { "content-type": "application/json" }, body: '{"status":"APPROVED"}' });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].path, "/api/v1/approvals/x/approve", "a path on the page's own origin, never another host");
  assert.deepEqual(calls[0].init, {
    method: "POST",
    headers: { accept: "application/json", "basalt-link-secret": "s3cr3t", "content-type": "application/json" },
    body: "{}",
    cache: "no-store",
    credentials: "omit",
  });
});

test("a GET carries no body, and any status is an answer, not a failure", async () => {
  const { calls, fetchFn } = recorder(() => new Response('{"code":"NOT_FOUND"}', { status: 404 }));
  const session = sameOriginSession(fetchFn);
  const res = await session.request("GET", "/api/v1/reverts/y", { "basalt-link-secret": "" });
  assert.equal(res.status, 404);
  assert.equal(res.body, '{"code":"NOT_FOUND"}');
  assert.equal("body" in calls[0].init, false);
  assert.equal(calls[0].init.method, "GET");
});

test("an engine that cannot be reached rejects the request", async () => {
  const session = sameOriginSession(async () => {
    throw new TypeError("fetch failed");
  });
  await assert.rejects(session.request("GET", "/x", {}), TypeError);
});

test("an unreadable body reads as empty", async () => {
  const session = sameOriginSession(async () => ({
    status: 502,
    headers: new Headers(),
    text: async () => {
      throw new TypeError("body stream broke");
    },
  }));
  assert.deepEqual(await session.request("GET", "/x", {}), { status: 502, headers: {}, body: "" });
});

test("a closed session sends nothing", async () => {
  const { calls, fetchFn } = recorder(() => new Response("{}"));
  const session = sameOriginSession(fetchFn);
  session.close();
  session.close();
  await assert.rejects(session.request("GET", "/x", {}), /closed/);
  assert.equal(calls.length, 0);
});

test("the pages use the same-origin transport", () => {
  assert.equal(pageTransport().kind, SAME_ORIGIN);
  assert.equal(pageTransport({ origin: "http://localhost:8787" }).kind, SAME_ORIGIN);
});

test("on the portal a short link reaches no engine and says to use the long link", async () => {
  const transport = pageTransport({ origin: "https://portal.basaltvault.app" });
  assert.equal(transport.kind, UNAVAILABLE);
  await assert.rejects(transport.open({ page: "approvals", id: "x", secret: "s" }), (err) => {
    assert.equal(err.name, "RelayError");
    assert.equal(err.code, "UNAVAILABLE");
    assert.equal(err.personMessage, UNREACHABLE);
    assert.match(err.personMessage, /long link/);
    return true;
  });
});

// The transports: transport.js holds the browser's network calls and hands
// them to the link session (channel.js), which takes them as arguments.
const TRANSPORTS = new Set(["transport.js", "channel.js"]);

test("no page reaches the engine except through the transport", () => {
  const dir = new URL("./", import.meta.url);
  for (const f of readdirSync(dir).filter((n) => n.endsWith(".js") && !TRANSPORTS.has(n))) {
    const src = readFileSync(new URL(f, dir), "utf8");
    assert.doesNotMatch(src, /\bfetch\s*\(|XMLHttpRequest|WebSocket|EventSource|sendBeacon/, `${f} calls the network itself`);
  }
});

test("only transport.js touches the browser's network globals", () => {
  const dir = new URL("./", import.meta.url);
  for (const f of readdirSync(dir).filter((n) => n.endsWith(".js") && n !== "transport.js")) {
    const src = readFileSync(new URL(f, dir), "utf8");
    assert.doesNotMatch(src, /window\.fetch|new\s+(window\.)?WebSocket\s*\(|globalThis\.fetch/, `${f} uses the browser's network itself`);
  }
});
