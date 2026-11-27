// Runs with `node --test web/lib/*.test.mjs` (make web-check). The approval
// and revert pages over RELAY read the same as on the engine's own pages:
// every engine answer gives the same error and the same sentence through
// either transport, and a request the engine altered is refused before
// anything is signed.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { checkApprovalRequest, parseApprovalRequest } from "./codec.js";
import { fetchRequest, postResponse, relayPaths } from "./local.js";
import { APPROVE_REOPEN, linkFailure, personText, REVERT_REOPEN, withdrawnText } from "./page.js";
import { relayTransport } from "./relay.js";
import { sameOriginSession } from "./transport.js";

const fixtures = JSON.parse(readFileSync(new URL("../../internal/core/approval/testdata/fixtures.json", import.meta.url), "utf8"));
const id = fixtures.request.approvalId;
const SECRET = "oo3hsfnTW0SXS80SkQL_vQ";
const ENGINE = "R68WFYxAcGgIjMENS5Oqrw";

function requestObject() {
  const { approvalId, binding, lines, credentialIds } = fixtures.request;
  return { approvalId, binding, lines, credentialIds };
}

// both runs call(session) over a same-origin session and a RELAY session
// whose engine answers every request with status and body.
async function both(status, body, call) {
  const text = JSON.stringify(body);
  const loopback = sameOriginSession(async () => new Response(text, { status, headers: { "content-type": "application/json" } }));
  const transport = relayTransport({
    socket: () => assert.fail("no socket"),
    pageHide: () => {},
    open: async () => ({
      engineId: ENGINE,
      engineKey: "k",
      ended: null,
      nextId: 0,
      async request() {
        this.nextId++;
        return { status, headers: { "content-type": "application/json" }, body: text };
      },
      close() {},
    }),
  });
  const relay = await transport.open({ page: "approvals", id, secret: SECRET });
  const outcome = async (session) => {
    try {
      return { ok: await call(session) };
    } catch (err) {
      return { name: err.name, code: err.code, status: err.status, reason: err.reason, message: err.message, personMessage: err.personMessage, err };
    }
  };
  return [await outcome(loopback), await outcome(relay)];
}

const answers = [
  [404, { code: "NOT_FOUND", message: "no such approval", reason: "LINK" }],
  [410, { code: "APPROVAL_EXPIRED", message: "this approval expired" }],
  [409, { code: "APPROVAL_INVALID", message: "this approval was already used" }],
  [400, { code: "INVALID_ARGUMENT", message: "bad body" }],
  [413, { code: "INVALID_ARGUMENT", message: "the body is over 16 KiB" }],
  [415, { code: "INVALID_ARGUMENT", message: "content-type must be application/json" }],
  [403, { code: "INVALID_ARGUMENT", message: "a request from another origin" }],
  [504, { code: "QUERY_TIMEOUT", reason: "TIME_LIMIT", message: "the rescope ran over 100 seconds", personMessage: "Narrow the scope and try again." }],
  [409, { code: "APPROVAL_INVALID", reason: "WITHDRAWN", message: "approval withdrawn by the agent", personMessage: "The agent withdrew this request: wrong rows. Nothing changed." }],
];

test("every engine answer reads the same over the relay as on the engine's own pages", async () => {
  for (const [status, body] of answers) {
    for (const [call, kind, reopen] of [
      [(s) => fetchRequest(s, relayPaths("approvals", id).request, SECRET, async () => {}), "approval", APPROVE_REOPEN],
      [(s) => postResponse(s, relayPaths("reverts", id).relay, SECRET, "{}"), "revert", REVERT_REOPEN],
    ]) {
      const [loop, relay] = await both(status, body, call);
      for (const k of ["name", "code", "status", "reason", "message", "personMessage"]) assert.equal(relay[k], loop[k], `${status} ${k}`);
      assert.equal(relay.name, "RelayError", String(status));
      assert.equal(linkFailure(relay.err, kind, reopen), linkFailure(loop.err, kind, reopen), String(status));
      assert.equal(personText(relay.err), personText(loop.err), String(status));
      assert.equal(withdrawnText(relay.err), withdrawnText(loop.err), String(status));
    }
  }
});

test("a request the engine altered is refused over the relay as on loopback, before anything is signed", async () => {
  const obj = requestObject();
  const fromLink = await parseApprovalRequest("#" + fixtures.request.fragment);
  const [, good] = await both(200, obj, (s) => fetchRequest(s, relayPaths("approvals", id).request, SECRET, async () => {}));
  assert.equal((await checkApprovalRequest(good.ok)).bindingText, fromLink.bindingText);
  for (const [tampered, why] of [
    [{ ...obj, lines: [...obj.lines].reverse() }, /rowsHash/],
    [{ ...obj, lines: [obj.lines[0], obj.lines[0], obj.lines[2]] }, /rowsHash/],
    [{ ...obj, lines: obj.lines.slice(1) }, /lines, binding/],
  ]) {
    const [loop, relay] = await both(200, tampered, (s) => fetchRequest(s, relayPaths("approvals", id).request, SECRET, async () => {}));
    await assert.rejects(checkApprovalRequest(loop.ok), why);
    await assert.rejects(checkApprovalRequest(relay.ok), why);
  }
});

test("no approval or revert page falls back to a code to paste", async () => {
  const { relayRetry, NO_CARRIER, RELAY_NO_ANSWER, RELAY_REFUSED } = await import("./page.js");
  for (const text of [RELAY_REFUSED, RELAY_NO_ANSWER, NO_CARRIER]) assert.doesNotMatch(text, /paste|basalt approve|basalt revert/i);
  for (const f of ["approve.js", "revert.js"]) {
    const src = readFileSync(new URL(`./${f}`, import.meta.url), "utf8");
    // A failed relay, on the engine's own pages or through the Vault, says
    // so and stops: no code to finish by hand.
    // A request the agent withdrew meanwhile is shown withdrawn first.
    assert.match(src, /\} catch \(err\) \{\n(\s+if \(withdrawnNow\(relay, err\)\) return;\n)?\s+showRelayFailed\(relayFailure\(err, "(approval|revert)"\)\);/, f);
    assert.doesNotMatch(src, /showCode|encode(Approval|Revert)Response|basalt approve|basalt revert/, f);
    // A long link has no engine to send a signature to: no passkey prompt,
    // the page says why.
    assert.match(src, /NO_CARRIER/, f);
  }
  const approveSrc = readFileSync(new URL("./approve.js", import.meta.url), "utf8");
  assert.match(approveSrc, /if \(relay === null\) \{\n\s+\$\("approve"\)\.disabled = true;\n\s+\$\("status"\)\.textContent = NO_CARRIER;\n\s+return;/);
  const revertSrc = readFileSync(new URL("./revert.js", import.meta.url), "utf8");
  assert.match(revertSrc, /if \(expired \|\| relay === null\) return;\n\s+\$\("sign"\)\.addEventListener/);
  for (const f of ["approve", "revert"]) {
    const html = readFileSync(new URL(`../${f}/index.html`, import.meta.url), "utf8");
    assert.doesNotMatch(html, /id="code"|basalt approve|basalt revert/, f);
  }

  // Only an answer from the engine says nothing was signed: a refusal with
  // its HTTP status. A session that dropped after the request went out may
  // have been applied, and the page says it cannot tell.
  for (const [status, body] of [[409, { code: "APPROVAL_INVALID", message: "used" }], [410, { code: "APPROVAL_EXPIRED", message: "expired" }], [400, { code: "INVALID_ARGUMENT", message: "bad" }]]) {
    const [, relay] = await both(status, body, (s) => postResponse(s, relayPaths("approvals", id).relay, SECRET, "{}"));
    assert.equal(relayRetry(relay.err), RELAY_REFUSED, String(status));
  }
  const dropped = relayTransport({
    socket: () => assert.fail("no socket"),
    pageHide: () => {},
    open: async () => ({
      engineId: ENGINE,
      engineKey: "k",
      ended: null,
      nextId: 0,
      async request() {
        this.ended = Object.assign(new Error("dropped"), { name: "ChannelError", code: "CONNECTION_FAILED" });
        throw this.ended;
      },
      close() {},
    }),
  });
  const session = await dropped.open({ page: "approvals", id, secret: SECRET });
  const err = await postResponse(session, relayPaths("approvals", id).relay, SECRET, "{}").then(
    () => assert.fail("posted"),
    (e) => e,
  );
  assert.equal(relayRetry(err), RELAY_NO_ANSWER);
  const { relayFailure } = await import("./page.js");
  assert.equal(relayFailure(err, "approval"), RELAY_NO_ANSWER, "no answer never says the engine did not take it");
  const [, refused] = await both(409, { code: "APPROVAL_INVALID", message: "this approval was already used" }, (s) => postResponse(s, relayPaths("approvals", id).relay, SECRET, "{}"));
  assert.equal(relayFailure(refused.err, "approval"), `The engine did not take the approval: this approval was already used. ${RELAY_REFUSED}`);
  assert.match(RELAY_NO_ANSWER, /cannot tell whether the signature went through/);
  assert.match(RELAY_NO_ANSWER, /Open the link again: it shows whether it was signed/);
});

test("registration never uses the relay", () => {
  for (const f of ["register.js"]) {
    const src = readFileSync(new URL(`./${f}`, import.meta.url), "utf8");
    assert.doesNotMatch(src, /pageTransport|relay\.js|relayTransport/, f);
  }
});

test("each page shows the receipt against the item and the binding it signed", () => {
  for (const [f, kind, idField] of [["approve.js", "APPROVAL", "approvalId"], ["revert.js", "REVERT", "revertId"]]) {
    const src = readFileSync(new URL(`./${f}`, import.meta.url), "utf8");
    assert.ok(src.includes(`await showReceipt(result, relay.session, { kind: "${kind}", itemId: response.${idField}, rowsHash: binding.rowsHash });`), f);
    assert.match(src, /async function finish\(response, relay, binding\)/, f);
  }
});
