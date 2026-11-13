// Runs with `node --test web/lib/*.test.mjs` (make web-check). The pairing
// code the registration page shows, against the cases Go's internal/passkey
// tests run (api/mcp/passkey/pairing-code.json).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { b64urlDecode } from "./codec.js";
import { normalizePairingCode, pairingCode } from "./pairing.js";

const vectors = JSON.parse(readFileSync(new URL("../../api/mcp/passkey/pairing-code.json", import.meta.url), "utf8"));

test("the pairing code matches the shared vectors", async () => {
  assert.ok(vectors.codes.length >= 3);
  for (const c of vectors.codes) {
    const got = await pairingCode(b64urlDecode(c.challenge), b64urlDecode(c.credentialId), b64urlDecode(c.x), b64urlDecode(c.y));
    assert.equal(got, c.code, c.name);
    assert.match(got, /^[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}$/);
  }
});

test("a typed pairing code normalises as Go reads it", () => {
  for (const c of vectors.normalise) {
    assert.equal(normalizePairingCode(c.input), c.code, JSON.stringify(c.input));
  }
});
