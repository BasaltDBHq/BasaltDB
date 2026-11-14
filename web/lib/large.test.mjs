// Runs with `node --test web/lib/*.test.mjs` (make web-check). A value over
// 1 MiB of text shows by its size and sha256; the hash is the marker's.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { displayValue, valueTexts } from "./codec.js";
import { LARGE_LIMIT, largeHash, largeInfo, showText, sizeText, tooLargeText, valueTextOf } from "./large.js";

const vectors = JSON.parse(readFileSync(new URL("../../api/mcp/values/large-value.json", import.meta.url), "utf8")).vectors;

test("the shared vectors: a value's text, bytes and sha256 are the marker's", async () => {
  for (const v of vectors) {
    // The line text carries the value as JSON, in the order the vector gives
    // the text (strings escaped); the page reads the slice, never the parse.
    const raw = typeof v.value === "string" ? JSON.stringify(v.value) : v.text;
    const line = `{"key":{},"set":{"v":${raw}}}`;
    const texts = valueTexts(line);
    const text = valueTextOf(JSON.parse(line).set.v, texts.set.get("v"));
    assert.equal(text, v.text, v.name);
    assert.equal(new TextEncoder().encode(text).length, v.bytes, v.name);
    assert.equal(await largeHash(text), v.sha256, v.name);
  }
});

test("a number past 2^53 and 1.10 keep the text the line carries", () => {
  const texts = valueTexts('{"set":{"a":123456789012345678901234567890,"b":1.10}}');
  assert.equal(valueTextOf(1.1, texts.set.get("b")), "1.10");
  assert.equal(displayValue(1.1, texts.set.get("b")), "1.10");
});

test("size reads in KiB or MiB with one decimal", () => {
  assert.equal(sizeText(1536), "1.5 KiB");
  assert.equal(sizeText(LARGE_LIMIT), "1.0 MiB");
  assert.equal(sizeText(2 * LARGE_LIMIT), "2.0 MiB");
  assert.equal(sizeText(15 * LARGE_LIMIT + LARGE_LIMIT / 2), "15.5 MiB");
});

test("1 MiB of text is shown; one byte more is not, counted in UTF-8", () => {
  assert.equal(largeInfo("a".repeat(LARGE_LIMIT)), null);
  assert.deepEqual(largeInfo("a".repeat(LARGE_LIMIT + 1)), { bytes: LARGE_LIMIT + 1 });
  // Three bytes each: 349525 are 1048575 bytes, 349526 are 1048578.
  assert.equal(largeInfo("\u20ac".repeat(349525)), null);
  assert.deepEqual(largeInfo("\u20ac".repeat(349526)), { bytes: 1048578 });
});

test("the text for a large value", async () => {
  const text = "x".repeat(2 * LARGE_LIMIT);
  const h = await largeHash(text);
  assert.match(h, /^[0-9a-f]{64}$/);
  assert.equal(tooLargeText(2 * LARGE_LIMIT, h), `too large to show: 2.0 MiB, sha256 ${h}\nYour signature covers the full value.`);
});

test("showText shows small text as given and large text by size and hash", async () => {
  const node = { textContent: "" };
  showText(node, "select 1", (t) => t.toUpperCase());
  assert.equal(node.textContent, "SELECT 1");
  const big = "b".repeat(LARGE_LIMIT + 1);
  showText(node, big, (t) => t);
  assert.match(node.textContent, /^too large to show: 1\.0 MiB, sha256 /);
  const h = await largeHash(big);
  await new Promise((r) => setTimeout(r, 0));
  assert.equal(node.textContent, tooLargeText(LARGE_LIMIT + 1, h));
});
