// The pages' Show values (CONTRACT.md, Rows hidden from the agent): when
// the page offers it, what it posts, how it checks the answer, and what it
// says when the engine refuses. Runs with `node --test web/lib/*.test.mjs`.
import { test } from "node:test";
import assert from "node:assert/strict";

import { b64urlDecode, hex, KIND_APPROVE, KIND_REVERT, sha256, utf8 } from "./codec.js";
import { RelayError } from "./local.js";
import { applyReveal, canReveal, clearReveal, notChecked, reveal, revealBody, revealedLine, RevealError, revealFailure, revealPath, SECRET_VALUE } from "./reveal.js";

const ID = "0193a3f0-0000-7000-8000-000000000001";
const NONCE = "ZGVmZ2hpamtsbW5vcHFycw";
const ROW = `[{"id": 39}, {"id": 39, "note": "note 39", "lead_id": 20}, null]`;
const SECRET_ROW = `[{"id": 40}, {"id": 40, "note": null, "lead_id": 20}, null]`;

async function request() {
  const rowHash = hex(await sha256(utf8(ROW)));
  const secretHash = hex(await sha256(utf8(`[{"id": 40}, {"id": 40, "note": "note 40", "lead_id": 20}, null]`)));
  return {
    approvalId: ID,
    revealNonce: NONCE,
    credentialIds: [new Uint8Array([1, 2, 3]), new Uint8Array([4, 5])],
    binding: { rowsHash: "ab".repeat(32) },
    lines: [
      { op: "DELETE", table: "public.leads", redacted: false, key: { id: 20 }, old: { id: 20 }, set: null, texts: {} },
      { op: "DELETE", table: "public.lead_notes", cascaded: true, redacted: true, rowHash },
      { op: "DELETE", table: "public.lead_notes", cascaded: true, redacted: true, rowHash: secretHash },
    ],
  };
}

const assertion = {
  rawId: new Uint8Array([1]).buffer,
  response: { authenticatorData: new Uint8Array([2]).buffer, clientDataJSON: new Uint8Array([3]).buffer, signature: new Uint8Array([4]).buffer },
};

function engine(status, body, seen) {
  return async (path, init) => {
    seen.push({ path, init });
    return { ok: status === 200, status, json: async () => body };
  };
}

test("Show values is offered only from the engine, with a nonce and a hidden row", async () => {
  const req = await request();
  const relay = { secret: "s" };
  assert.equal(canReveal(req, relay), true);
  assert.equal(canReveal(req, null), false, "a long link has no engine");
  assert.equal(canReveal({ ...req, revealNonce: null }, relay), false, "no nonce, no proof");
  assert.equal(canReveal({ ...req, lines: [req.lines[0]] }, relay), false, "nothing hidden");
  assert.equal(revealPath("reverts", ID), `/api/v1/reverts/${ID}/reveal`);
});

test("the reveal body carries the proof and the reveal secret, nothing else", () => {
  const body = JSON.parse(revealBody({ credentialId: new Uint8Array([1]), authenticatorData: new Uint8Array([2]), clientDataJson: new Uint8Array([3]), signature: new Uint8Array([4]) }, new Uint8Array(16)));
  assert.deepEqual(Object.keys(body).sort(), ["proof", "revealSecret"]);
  assert.deepEqual(Object.keys(body.proof).sort(), ["authenticatorData", "clientDataJson", "credentialId", "signature"]);
  assert.equal(b64urlDecode(body.revealSecret).length, 16);
});

test("one prompt shows every hidden row; a secret row is unchecked", async () => {
  const req = await request();
  const seen = [];
  let options;
  const shown = await reveal({
    kind: KIND_APPROVE, id: ID, req, rpId: "localhost", path: revealPath("approvals", ID), secret: "link-secret",
    fetchFn: engine(200, { rows: [{ line: 1, row: ROW }, { line: 2, row: SECRET_ROW, secretColumns: ["note"] }] }, seen),
    getAssertion: async (o) => { options = o; return assertion; },
  });
  assert.equal(seen.length, 1, "one post");
  assert.equal(seen[0].init.headers["basalt-link-secret"], "link-secret");
  assert.equal(options.publicKey.userVerification, "required");
  assert.deepEqual(
    options.publicKey.allowCredentials,
    [{ type: "public-key", id: new Uint8Array([1, 2, 3]) }, { type: "public-key", id: new Uint8Array([4, 5]) }],
    "only this database's passkeys are offered",
  );
  assert.equal(shown.get(1).checked, true);
  assert.equal(shown.get(2).checked, false);
  const line = revealedLine(req.lines[2], shown.get(2), "old");
  assert.equal(line.redacted, false);
  assert.equal(line.texts.old.get("note"), SECRET_VALUE, "a secret column says Postgres withholds it");
  assert.equal(SECRET_VALUE, "secret \u00b7 not shown");
  assert.equal(line.texts.old.get("lead_id"), "20");
  assert.equal(notChecked("Row id = 8"), "Row id = 8 has a secret column, so this page can't check it against what you sign.");
});

test("a row that does not hash to its line shows nothing at all", async () => {
  const req = await request();
  await assert.rejects(
    reveal({
      kind: KIND_APPROVE, id: ID, req, rpId: "localhost", path: "/x", secret: "s",
      fetchFn: engine(200, { rows: [{ line: 1, row: ROW.replace("note 39", "forged") }] }, []),
      getAssertion: async () => assertion,
    }),
    (err) => err instanceof RevealError && err.final,
  );
  await assert.rejects(
    reveal({
      kind: KIND_APPROVE, id: ID, req, rpId: "localhost", path: "/x", secret: "s",
      fetchFn: engine(200, { rows: [{ line: 1, row: SECRET_ROW, secretColumns: ["ssn"] }] }, []),
      getAssertion: async () => assertion,
    }),
    RevealError,
    "secretColumns naming a column the row does not have",
  );
});

test("the page says what a refused reveal and changed rows mean", () => {
  const refused = revealFailure(new RelayError("refused", "APPROVAL_INVALID", 409, { reason: "REVEAL_REFUSED", personMessage: "Your passkey didn't confirm. Nothing was shown; try again." }), KIND_APPROVE);
  assert.deepEqual(refused, { text: "Your passkey didn't confirm. Nothing was shown; try again.", final: false });
  const bare = revealFailure(new RelayError("refused", "APPROVAL_INVALID", 409, { reason: "REVEAL_REFUSED" }), KIND_APPROVE);
  assert.equal(bare.text, "Your passkey didn't confirm. Nothing was shown; try again.");
  const changed = revealFailure(new RelayError("changed", "APPROVAL_INVALID", 409, { reason: "ROWS_CHANGED" }), KIND_APPROVE);
  assert.equal(changed.text, "These rows changed since the agent asked. This approval can no longer apply; ask the agent to try the write again.");
  assert.equal(changed.final, true);
  const revertChanged = revealFailure(new RelayError("changed", "REVERT_INVALID", 409, { reason: "ROWS_CHANGED" }), KIND_REVERT);
  assert.match(revertChanged.text, /prepare it again\.$/);
  assert.equal(revealFailure(new Error("other"), KIND_APPROVE), null);
});

test("a rescope during a reveal shows nothing of the old rows; a rescope clears what was shown", async () => {
  const old = await request();
  const state = { req: old, shown: new Map(), revealDone: false };
  let answer;
  const pending = reveal({
    kind: KIND_APPROVE, id: ID, req: old, rpId: "localhost", path: "/x", secret: "s",
    fetchFn: async () => {
      await new Promise((resolve) => { answer = resolve; });
      return { ok: true, status: 200, json: async () => ({ rows: [{ line: 1, row: ROW }] }) };
    },
    getAssertion: async () => assertion,
  });
  // The person rescopes while the reveal is in flight.
  const fresh = { ...(await request()) };
  state.req = fresh;
  clearReveal(state);
  while (answer === undefined) await new Promise((resolve) => setTimeout(resolve, 1));
  answer();
  const shown = await pending;
  assert.equal(applyReveal(state, old, shown), false, "the old request's rows are dropped");
  assert.equal(state.shown.size, 0);
  assert.equal(state.revealDone, false);

  state.valuesHidden = true;
  assert.equal(applyReveal(state, fresh, shown), true);
  assert.equal(state.shown.size, 1);
  assert.equal(state.valuesHidden, false, "a new reveal shows its values");
  state.valuesHidden = true;
  clearReveal(state);
  assert.equal(state.shown.size, 0, "a rescope clears what was shown");
  assert.equal(state.revealDone, false);
  assert.equal(state.valuesHidden, false, "and the Hide values toggle");
});
