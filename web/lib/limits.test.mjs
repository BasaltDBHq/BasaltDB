// Runs with `node --test web/lib/*.test.mjs` (make web-check). Checks the
// limits the pages enforce against api/mcp/pages/limits.json, which a Go
// test (api/mcp/page_limits_test.go) checks against the engine's constants.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  b64urlEncode,
  CHALLENGE_BYTES,
  MAX_FRAGMENT_LENGTH,
  MAX_INFLATED_BYTES,
  MAX_LABEL_BYTES,
  MAX_REVERT_BATCH,
  MAX_REVERT_LINES,
  MAX_ROWS,
  REVERT_APPLY_HOURS,
  USER_ID_BYTES,
  utf8,
} from "./codec.js";
import { parseSetupLink } from "./setup.js";

const limits = JSON.parse(readFileSync(new URL("../../api/mcp/pages/limits.json", import.meta.url), "utf8"));

test("the fixture names exactly the limits this test checks", () => {
  assert.deepEqual(Object.keys(limits).sort(), ["agentName", "approval", "links", "passkey", "revert"]);
  assert.deepEqual(Object.keys(limits.approval).sort(), ["maxRows"]);
  assert.deepEqual(Object.keys(limits.revert).sort(), ["applyHours", "maxBatch", "maxLines"]);
  assert.deepEqual(Object.keys(limits.links).sort(), ["maxFragmentLength", "maxInflatedBytes"]);
  assert.deepEqual(Object.keys(limits.passkey).sort(), ["challengeBytes", "maxLabelBytes", "userIdBytes"]);
  assert.deepEqual(Object.keys(limits.agentName).sort(), ["accepted", "maxLength", "refused"]);
});

test("the pages' limits are the engine's", () => {
  assert.equal(MAX_ROWS, limits.approval.maxRows);
  assert.equal(MAX_REVERT_LINES, limits.revert.maxLines);
  assert.equal(MAX_REVERT_BATCH, limits.revert.maxBatch);
  assert.equal(REVERT_APPLY_HOURS, limits.revert.applyHours);
  assert.equal(MAX_FRAGMENT_LENGTH, limits.links.maxFragmentLength);
  assert.equal(MAX_INFLATED_BYTES, limits.links.maxInflatedBytes);
  assert.equal(CHALLENGE_BYTES, limits.passkey.challengeBytes);
  assert.equal(USER_ID_BYTES, limits.passkey.userIdBytes);
  assert.equal(MAX_LABEL_BYTES, limits.passkey.maxLabelBytes);
});

const setupLink = (agent) => "#1." + b64urlEncode(utf8(JSON.stringify({ job: "INSTALL", agent, osUser: "person", demo: false })));

test("the setup page accepts the agent names the engine accepts, and refuses the rest", () => {
  const { maxLength, accepted, refused } = limits.agentName;
  assert.ok(accepted.includes("a".repeat(maxLength)), "the fixture probes the longest name");
  assert.ok(refused.includes("a".repeat(maxLength + 1)), "the fixture probes one past the longest name");
  for (const agent of accepted) {
    assert.equal(parseSetupLink(setupLink(agent)).agent, agent, `refused ${JSON.stringify(agent)}`);
  }
  for (const agent of refused) {
    assert.throws(() => parseSetupLink(setupLink(agent)), /agent whose name cannot be used/, `accepted ${JSON.stringify(agent)}`);
  }
});
