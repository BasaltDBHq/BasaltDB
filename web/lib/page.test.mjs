// Runs with `node --test web/lib/*.test.mjs` (make web-check). The message a
// page shows when its link was cut short on the way from the terminal or a
// chat to the browser.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { CodeError, TruncatedLinkError, parseApprovalRequest, parseRevertRequest } from "./codec.js";
import { APPROVE_REOPEN, REVERT_REOPEN, linkFailure, webauthnError, whenText } from "./page.js";

const approvalFragment = JSON.parse(
  readFileSync(new URL("../../internal/approval/testdata/fixtures.json", import.meta.url), "utf8"),
).request.fragment;
const revertFragment = JSON.parse(
  readFileSync(new URL("../../internal/revert/testdata/fixtures.json", import.meta.url), "utf8"),
).request.fragment;

async function failure(parse, fragment) {
  try {
    await parse(fragment);
  } catch (err) {
    return err;
  }
  assert.fail(`fragment of ${fragment.length} characters decoded`);
}

test("an approval link cut short anywhere says so and says to ask the agent for a new link", async () => {
  // Every cut a terminal wrap or a chat could make, including right after '#'.
  const cuts = [0, 1, 2, 3, 10, Math.floor(approvalFragment.length / 2), approvalFragment.length - 1];
  for (const n of cuts) {
    const err = await failure(parseApprovalRequest, "#" + approvalFragment.slice(0, n));
    assert.ok(err instanceof TruncatedLinkError, `cut at ${n}: ${err.name}: ${err.message}`);
    const msg = linkFailure(err, "approval", APPROVE_REOPEN);
    assert.match(msg, /^This approval link looks cut short \(/);
    assert.match(msg, /Ask the agent for a new link to this approval\.$/);
    assert.doesNotMatch(msg, /basalt|paste|code/);
    assert.doesNotMatch(msg, /cannot be used/);
  }
});

test("a revert link cut short says so and says to ask the agent for a new link", async () => {
  const err = await failure(parseRevertRequest, "#" + revertFragment.slice(0, revertFragment.length - 7));
  assert.ok(err instanceof TruncatedLinkError, `${err.name}: ${err.message}`);
  const msg = linkFailure(err, "revert", REVERT_REOPEN);
  assert.match(msg, /^This revert link looks cut short \(/);
  assert.match(msg, /Ask the agent for a new link to this revert\.$/);
  assert.doesNotMatch(msg, /basalt|paste|code/);
});

test("a link that decodes but is wrong is not called cut short", async () => {
  const err = await failure(parseApprovalRequest, "#2." + approvalFragment.slice(2));
  assert.ok(err instanceof CodeError);
  assert.ok(!(err instanceof TruncatedLinkError));
  assert.equal(linkFailure(err, "approval", APPROVE_REOPEN), `This approval link cannot be used: ${err.message}`);
});

test("a pill's time shows its date when it is not today", () => {
  const now = new Date(2026, 10, 13, 9, 5);
  assert.equal(whenText(new Date(2026, 10, 13, 17, 37), now), "17:37");
  assert.equal(whenText(new Date(2026, 10, 14, 7, 3), now), "14 Nov 07:03");
  assert.equal(whenText(new Date(2027, 10, 13, 17, 37), now), "13 Nov 17:37");
});

test("a prompt that offered this database's passkeys says this device may have none of them", () => {
  const cancelled = { name: "NotAllowedError" };
  assert.equal(webauthnError(cancelled), "The passkey prompt was cancelled or timed out. Nothing was signed.");
  assert.match(webauthnError(cancelled, 2), /this device has none of this database's passkeys/);
});
