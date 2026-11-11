// Runs with `node --test web/lib/*.test.mjs` (make web-check). The cases are
// the shared vectors the Go reference runs too (api/mcp/links/link-repair.json).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { isLongLink } from "./local.js";
import { readPaste, repairFragment, repairHash } from "./repair.js";

const vectors = JSON.parse(readFileSync(new URL("../../api/mcp/links/link-repair.json", import.meta.url), "utf8"));

for (const c of vectors.fragments) {
  test(`repairFragment: ${c.name}`, () => {
    assert.equal(repairFragment(c.input), c.want);
  });
}

for (const c of vectors.pastes) {
  test(`readPaste: ${c.name}`, () => {
    assert.equal(readPaste(c.input), c.want);
  });
}

test("a repaired or pasted format 2 fragment is a long link", () => {
  assert.equal(isLongLink(repairHash("#2.AbC\n  -d_9.")), true);
  assert.equal(isLongLink(`#${readPaste("Open https://h/approvals/x#2.AbC\n  Def\n\nbye")}`), true);
  assert.equal(isLongLink(repairHash("#s=q3Jv8sLk2mT0xYp1aBcD9w")), false);
});

test("repairHash takes the text after the first # and repairs it", () => {
  assert.equal(repairHash("#2.AbC\n -d_9."), "#2.AbC-d_9");
  assert.equal(repairHash(""), "#");
  assert.equal(repairHash("#2.a#b"), "#2.a");
});
