// Runs with `node --test web/lib/*.test.mjs` (make web-check).
import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { constants, deflateRawSync } from "node:zlib";

import { parseApprovalRequest } from "./codec.js";
import { DeflateError, deflateEnd } from "./deflate.js";

const vectors = JSON.parse(
  readFileSync(new URL("../../api/mcp/links/compact-request.json", import.meta.url), "utf8"),
);

// Text, incompressible bytes and their mix cover stored, fixed and dynamic
// blocks at every level.
const inputs = [
  Buffer.from(""),
  Buffer.from("a"),
  Buffer.from(JSON.stringify(vectors).repeat(3)),
  randomBytes(70_000),
  Buffer.concat([randomBytes(500), Buffer.from("x".repeat(5000))]),
];

test("deflateEnd finds the end of every stream zlib writes", () => {
  for (const input of inputs) {
    for (const level of [0, 1, 6, 9]) {
      for (const strategy of [constants.Z_DEFAULT_STRATEGY, constants.Z_FIXED, constants.Z_HUFFMAN_ONLY]) {
        const stream = deflateRawSync(input, { level, strategy });
        assert.equal(deflateEnd(stream), stream.length, `level ${level}, strategy ${strategy}, ${input.length} bytes`);
        assert.equal(deflateEnd(Buffer.concat([stream, Buffer.from("junk")])), stream.length);
      }
    }
  }
});

test("deflateEnd refuses a cut or broken stream", () => {
  const stream = deflateRawSync(Buffer.from(JSON.stringify(vectors)));
  assert.throws(() => deflateEnd(stream.subarray(0, stream.length - 3)), DeflateError);
  assert.throws(() => deflateEnd(new Uint8Array([0x07])), DeflateError, "block type 3");
  assert.throws(() => deflateEnd(new Uint8Array([0x01, 0x05, 0x00, 0x00, 0x00])), DeflateError, "stored length and complement differ");
  assert.throws(() => deflateEnd(new Uint8Array([])), DeflateError);
});

test("the page refuses bytes after the deflate stream itself", async () => {
  const [v] = vectors.valid;
  const payload = Buffer.from(JSON.stringify(v.payload));
  const fragment = "2." + Buffer.concat([deflateRawSync(payload), Buffer.from([0])]).toString("base64url");
  await assert.rejects(parseApprovalRequest(fragment), /after the end of its deflate stream/);
});
