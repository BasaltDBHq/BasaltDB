// Runs with `node --test web/lib/*.test.mjs` (make web-check). The short-link
// pages against a fake engine: the request they read, the response they
// relay, and the errors they show.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { approvalResponseJSON, b64urlDecode, checkApprovalRequest, parseApprovalRequest } from "./codec.js";
import { RelayError, fetchRequest, postResponse, relayPaths, revertDone, shortLinkId } from "./local.js";
import { linkFailure, APPROVE_REOPEN } from "./page.js";

const fixtures = JSON.parse(
  readFileSync(new URL("../../internal/approval/testdata/fixtures.json", import.meta.url), "utf8"),
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
async function requestObject() {
  const { inflateRawSync } = await import("node:zlib");
  const bytes = b64urlDecode(fixtures.request.fragment.slice(2));
  return JSON.parse(inflateRawSync(bytes).toString("utf8"));
}

test("a short link's id comes from its path", () => {
  assert.equal(shortLinkId(`/approve/${id}`, "approve"), id);
  assert.equal(shortLinkId(`/approve/${id}/`, "approve"), id);
  assert.equal(shortLinkId("/approve/", "approve"), null);
  assert.equal(shortLinkId(`/revert/${id}`, "approve"), null);
  assert.equal(shortLinkId("/approve/not-an-id", "approve"), null);
  assert.deepEqual(relayPaths("approve", id), { request: `/api/v1/approvals/${id}`, relay: `/api/v1/approvals/${id}/approve` });
  assert.deepEqual(relayPaths("revert", id), { request: `/api/v1/reverts/${id}`, relay: `/api/v1/reverts/${id}/apply` });
});

test("the request read from the engine passes the same checks as the long link", async () => {
  const obj = await requestObject();
  const { fetchFn, calls } = fakeEngine({ [`GET /api/v1/approvals/${id}`]: { body: obj } });
  const req = await checkApprovalRequest(await fetchRequest(fetchFn, relayPaths("approve", id).request));
  const fromLink = await parseApprovalRequest("#" + fixtures.request.fragment);
  assert.equal(req.bindingText, fromLink.bindingText);
  assert.deepEqual(req.challenge, fromLink.challenge);
  assert.equal(calls[0].init.credentials, "omit");

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
  const path = relayPaths("approve", id).relay;
  const { fetchFn, calls } = fakeEngine({ [`POST ${path}`]: { body: { approvalId: id, status: "APPROVED" } } });
  const out = await postResponse(fetchFn, path, approvalResponseJSON(response));
  assert.equal(out.status, "APPROVED");
  assert.equal(calls[0].init.method, "POST");
  assert.equal(calls[0].init.headers["Content-Type"], "application/json");
  assert.deepEqual(Object.keys(JSON.parse(calls[0].init.body)), ["approvalId", "credentialId", "authenticatorData", "clientDataJson", "signature"]);
});

test("engine errors come back with their code and message", async () => {
  const { fetchFn } = fakeEngine({
    [`GET /api/v1/approvals/${id}`]: { status: 410, body: { code: "APPROVAL_EXPIRED", message: "this approval expired" } },
  });
  const err = await fetchRequest(fetchFn, `/api/v1/approvals/${id}`).catch((e) => e);
  assert.ok(err instanceof RelayError);
  assert.equal(err.code, "APPROVAL_EXPIRED");
  assert.equal(err.status, 410);
  assert.equal(linkFailure(err, "approval", APPROVE_REOPEN), "This approval cannot be shown: this approval expired");

  const unknown = await fetchRequest(fetchFn, "/api/v1/approvals/x").catch((e) => e);
  assert.equal(unknown.code, "NOT_FOUND");

  const down = await fetchRequest(async () => {
    throw new TypeError("fetch failed");
  }, "/x").catch((e) => e);
  assert.match(down.message, /cannot reach the BasaltDB engine/);
});

test("a relayed revert says what it did", () => {
  assert.equal(revertDone({ rows: 31, skipped: 1 }), "Reverted: 31 rows restored, 1 left as they are.");
  assert.match(revertDone({ batched: true, pending: 1200 }), /restores the 1200 remaining rows in batches/);
});
