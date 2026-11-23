// Runs with `node --test web/lib/*.test.mjs` (make web-check). The headline
// cases come from the Go tests (internal/core/approval/summary_test.go), so the
// page and the engine's headline say the same thing.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { parseApprovalRequest, parseLine } from "./codec.js";
import { canStartPasskey, cascadeConfirmation, headline, summarize } from "./summary.js";

const fixtures = JSON.parse(
  readFileSync(new URL("../../internal/core/approval/testdata/fixtures.json", import.meta.url), "utf8"),
);

function summaryOf(name) {
  const c = fixtures.summaries.find((s) => s.name === name);
  assert.ok(c, name);
  return summarize(c.lines.map(parseLine));
}

test("headline matches Go for every case", () => {
  assert.ok(fixtures.summaries.length >= 5);
  for (const c of fixtures.summaries) {
    const s = summarize(c.lines.map(parseLine));
    assert.equal(headline(s), c.headline, c.name);
    assert.equal(s.cascadedRows, c.cascadedRows, c.name);
  }
});

test("headline of the request in the approval link counts redacted rows", async () => {
  const req = await parseApprovalRequest("#" + fixtures.request.fragment);
  assert.equal(
    headline(summarize(req.lines)),
    "Delete 1 row in public.leads + 2 cascaded rows (public.lead_notes 1, public.note_tags 1 [values hidden])",
  );
});

test("cascade confirmation names the rows and tables", () => {
  assert.equal(cascadeConfirmation(summaryOf("no cascade")), null);
  assert.equal(
    cascadeConfirmation(summaryOf("cascades, one table hidden")),
    "I understand this also deletes 30 cascaded rows in public.invoices and public.payments.",
  );
  assert.equal(
    cascadeConfirmation(summaryOf("a cascade of another operation")),
    "I understand this also changes 1 cascaded row in public.lead_owner.",
  );
  const three = summarize(
    ["public.a", "public.b", "public.c", "public.leads"].map((table, i) =>
      parseLine(JSON.stringify({ op: "DELETE", key: { id: i }, old: { id: i }, set: null, table, cascaded: table !== "public.leads" })),
    ),
  );
  assert.equal(cascadeConfirmation(three), "I understand this also deletes 3 cascaded rows in public.a, public.b and public.c.");
});

test("the passkey prompt waits for the cascade confirmation", () => {
  const plain = summaryOf("no cascade");
  const cascade = summaryOf("cascades, one table hidden");
  assert.equal(canStartPasskey({ summary: plain, confirmed: false, expired: false }), true);
  assert.equal(canStartPasskey({ summary: cascade, confirmed: false, expired: false }), false);
  assert.equal(canStartPasskey({ summary: cascade, confirmed: true, expired: false }), true);
  assert.equal(canStartPasskey({ summary: plain, confirmed: false, expired: true }), false);
  assert.equal(canStartPasskey({ summary: cascade, confirmed: true, expired: true }), false);
});
