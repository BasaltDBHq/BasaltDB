// Runs with `node --test web/lib/*.test.mjs` (make web-check). The short-link
// pages against a fake engine: the request they read, the response they
// relay, and the errors they show.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { approvalResponseJSON, checkApprovalRequest, parseApprovalRequest } from "./codec.js";
import { REQUEST_ATTEMPTS, REQUEST_RETRY_MS, RelayError, SECRET_HEADER, fetchRequest, isLongLink, linkSecret, pageId, postResponse, relayPaths, revertDone, shortLinkId } from "./local.js";
import { sameOriginSession } from "./transport.js";
import { linkFailure, personText, APPROVE_REOPEN } from "./page.js";

const fixtures = JSON.parse(
  readFileSync(new URL("../../internal/core/approval/testdata/fixtures.json", import.meta.url), "utf8"),
);
const id = fixtures.request.approvalId;

// fakeEngine answers like the engine's pages handler and records calls.
function fakeEngine(routes) {
  const calls = [];
  const fetchFn = async (path, init = {}) => {
    calls.push({ path, init });
    const r = routes[`${init.method ?? "GET"} ${path}`];
    if (!r) return new Response(JSON.stringify({ code: "NOT_FOUND", message: "no such route" }), { status: 404 });
    return new Response(JSON.stringify(r.body), { status: r.status ?? 200 });
  };
  return { calls, fetchFn };
}

// The request object the engine serves is the JSON the long link carries.
// requestObject is the request JSON the engine serves for the fixture.
async function requestObject() {
  const { approvalId, binding, lines, credentialIds } = fixtures.request;
  return { approvalId, binding, lines, credentialIds };
}

test("a short link's id comes from its path", () => {
  assert.equal(shortLinkId(`/approvals/${id}`, "approvals"), id);
  assert.equal(shortLinkId(`/approvals/${id}/`, "approvals"), id);
  assert.equal(shortLinkId("/approvals/", "approvals"), null);
  assert.equal(shortLinkId(`/reverts/${id}`, "approvals"), null);
  assert.equal(shortLinkId(`/approve/${id}`, "approvals"), null);
  assert.equal(shortLinkId("/approvals/not-an-id", "approvals"), null);
  assert.equal(pageId(`/approvals/${id}`, "approvals"), id);
  assert.equal(pageId(`/reverts/${id}/`, "reverts"), id);
  // A long link's request takes its id from its binding (format 2), so a
  // page without an id in its path has nothing to check it against.
  assert.throws(() => pageId("/approvals/", "approvals"), /no approval id in its path/);
  assert.throws(() => pageId("/approve/index.html", "approvals"), /no approval id/);
  assert.throws(() => pageId(`/approvals/${id}`, "reverts"), /no revert id/);
  assert.deepEqual(relayPaths("approvals", id), { request: `/api/v1/approvals/${id}`, relay: `/api/v1/approvals/${id}/approve` });
  assert.deepEqual(relayPaths("reverts", id), { request: `/api/v1/reverts/${id}`, relay: `/api/v1/reverts/${id}/apply` });
});

test("the request read from the engine passes the same checks as the long link", async () => {
  const obj = await requestObject();
  const { fetchFn, calls } = fakeEngine({ [`GET /api/v1/approvals/${id}`]: { body: obj } });
  const req = await checkApprovalRequest(await fetchRequest(sameOriginSession(fetchFn), relayPaths("approvals", id).request, "s3cr3t"));
  const fromLink = await parseApprovalRequest("#" + fixtures.request.fragment);
  assert.equal(req.bindingText, fromLink.bindingText);
  assert.deepEqual(req.challenge, fromLink.challenge);
  assert.equal(calls[0].init.credentials, "omit");
  assert.equal(calls[0].init.headers[SECRET_HEADER], "s3cr3t", "the secret goes in a header, never in the URL");
  assert.ok(!calls[0].path.includes("s3cr3t"));

  // A request the engine altered fails the rowsHash check, as a bad link does.
  const tampered = { ...obj, lines: [...obj.lines].reverse() };
  await assert.rejects(checkApprovalRequest(tampered), /rowsHash/);
});

test("the signed response is posted as JSON to the relay", async () => {
  const response = {
    approvalId: id,
    credentialId: new Uint8Array([1, 2]),
    authenticatorData: new Uint8Array([3]),
    clientDataJson: new Uint8Array([4]),
    signature: new Uint8Array([5]),
  };
  const path = relayPaths("approvals", id).relay;
  const { fetchFn, calls } = fakeEngine({ [`POST ${path}`]: { body: { approvalId: id, status: "APPROVED" } } });
  const out = await postResponse(sameOriginSession(fetchFn), path, "s3cr3t", approvalResponseJSON(response));
  assert.equal(out.status, "APPROVED");
  assert.equal(calls[0].init.method, "POST");
  assert.equal(calls[0].init.headers["content-type"], "application/json");
  assert.equal(calls[0].init.headers[SECRET_HEADER], "s3cr3t");
  assert.deepEqual(Object.keys(JSON.parse(calls[0].init.body)), ["approvalId", "credentialId", "authenticatorData", "clientDataJson", "signature"]);
});

test("engine errors carry the person's message and steps, and the page shows them", async () => {
  const { fetchFn } = fakeEngine({
    [`GET /api/v1/reverts/${id}`]: {
      status: 410,
      body: {
        code: "REVERT_EXPIRED",
        message: "revert expired",
        reason: "NOT_SIGNED",
        personMessage: "The revert of run r1 was not signed within an hour, so it expired.",
        nextSteps: [{ actor: "PERSON", action: "RUN_COMMAND", text: "Prepare it again.", command: "basalt revert --agent bot --run r1 --open" }],
      },
    },
    [`GET /api/v1/approvals/${id}`]: {
      status: 404,
      body: { code: "NOT_FOUND", message: "no such link", reason: "LINK", personMessage: "This link is incomplete, expired or was replaced.", nextSteps: [] },
    },
  });
  const err = await fetchRequest(sameOriginSession(fetchFn), `/api/v1/reverts/${id}`, "s3cr3t").catch((e) => e);
  assert.equal(err.reason, "NOT_SIGNED");
  assert.equal(err.personMessage, "The revert of run r1 was not signed within an hour, so it expired.");
  assert.equal(err.nextSteps.length, 1);
  assert.equal(
    linkFailure(err, "revert", "reopen it"),
    "The revert of run r1 was not signed within an hour, so it expired.\nPrepare it again. Run: basalt revert --agent bot --run r1 --open",
  );

  const link = await fetchRequest(sameOriginSession(fetchFn), `/api/v1/approvals/${id}`, "").catch((e) => e);
  assert.equal(linkFailure(link, "approval", APPROVE_REOPEN), "This link is incomplete, expired or was replaced.\nOr " + APPROVE_REOPEN + ".");

  const bare = new RelayError("plain");
  assert.deepEqual(bare.nextSteps, []);
  assert.equal(personText(bare), "", "an error without the person's message shows its own text");
});

test("engine errors come back with their code and message", async () => {
  const { fetchFn } = fakeEngine({
    [`GET /api/v1/approvals/${id}`]: { status: 410, body: { code: "APPROVAL_EXPIRED", message: "this approval expired" } },
  });
  const err = await fetchRequest(sameOriginSession(fetchFn), `/api/v1/approvals/${id}`, "s3cr3t").catch((e) => e);
  assert.ok(err instanceof RelayError);
  assert.equal(err.code, "APPROVAL_EXPIRED");
  assert.equal(err.status, 410);
  assert.equal(linkFailure(err, "approval", APPROVE_REOPEN), "This approval cannot be shown: this approval expired");

  const unknown = await fetchRequest(sameOriginSession(fetchFn), "/api/v1/approvals/x", "").catch((e) => e);
  assert.equal(unknown.code, "NOT_FOUND");
  assert.match(linkFailure(unknown, "approval", APPROVE_REOPEN), /^This approval link is incomplete, was replaced by a newer one/);

  const waited = [];
  let calls = 0;
  const down = await fetchRequest(
    sameOriginSession(async () => {
      calls++;
      throw new TypeError("fetch failed");
    }),
    "/x",
    "",
    async (ms) => waited.push(ms),
  ).catch((e) => e);
  assert.match(down.message, /cannot reach the BasaltDB engine/);
  assert.equal(calls, REQUEST_ATTEMPTS, "it tries again before giving up");
  assert.deepEqual(waited, Array(REQUEST_ATTEMPTS - 1).fill(REQUEST_RETRY_MS));
  assert.ok((REQUEST_ATTEMPTS - 1) * REQUEST_RETRY_MS <= 5000, "about 5 seconds at most");
});

test("reading the request waits out an engine restart", async () => {
  const { fetchFn } = fakeEngine({
    [`GET /api/v1/approvals/${id}`]: { status: 410, body: { code: "APPROVAL_EXPIRED", message: "this approval expired" } },
  });
  let calls = 0;
  const restarting = async (...args) => {
    calls++;
    if (calls < 3) {
      throw new TypeError("fetch failed");
    }
    return fetchFn(...args);
  };
  const waited = [];
  const err = await fetchRequest(sameOriginSession(restarting), `/api/v1/approvals/${id}`, "s3cr3t", async (ms) => waited.push(ms)).catch((e) => e);
  assert.equal(calls, 3);
  assert.equal(waited.length, 2);
  assert.equal(err.code, "APPROVAL_EXPIRED", "an engine answer is not retried");
});

test("the relay is never retried", async () => {
  let calls = 0;
  const err = await postResponse(sameOriginSession(async () => {
    calls++;
    throw new TypeError("fetch failed");
  }), "/x", "", "{}").catch((e) => e);
  assert.match(err.message, /cannot reach the BasaltDB engine/);
  assert.equal(calls, 1);
});

test("a relayed revert says what it did", () => {
  assert.equal(revertDone({ rows: 31, skipped: 1 }), "Reverted: 31 rows restored, 1 left as they are.");
  assert.match(revertDone({ batched: true, pending: 1200 }), /restores the 1200 remaining rows in batches/);
});

test("a short link's secret comes from its fragment", () => {
  assert.equal(linkSecret("#s=c2VjcmV0LXNlY3JldC0xMg"), "c2VjcmV0LXNlY3JldC0xMg");
  assert.equal(linkSecret("s=abc_-"), "abc_-");
  assert.equal(linkSecret(""), "");
  assert.equal(linkSecret("#1.abc"), "");
  assert.equal(linkSecret("#s=bad secret"), "");
  assert.ok(isLongLink("#1.abc"));
  assert.ok(isLongLink("#2.abc"));
  assert.ok(!isLongLink("#3.abc"));
  assert.ok(!isLongLink("#s=abc"));
  assert.ok(!isLongLink(""));
});
