// Runs with `node --test web/lib/*.test.mjs` (make web-check). Reads the
// fixtures the Go tests write, so the page and internal/approval agree.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { deflateRawSync } from "node:zlib";

import {
  CodeError,
  b64urlDecode,
  b64urlEncode,
  encodeApprovalResponse,
  encodeRegistrationResponse,
  parseApprovalRequest,
  parseBinding,
  parseLine,
  parseRegistrationRequest,
  relyingParty,
  rowsHash,
  utf8,
} from "./codec.js";

const fixtures = JSON.parse(
  readFileSync(new URL("../../internal/approval/testdata/fixtures.json", import.meta.url), "utf8"),
);

function requestFragment(obj) {
  return "1." + b64urlEncode(deflateRawSync(Buffer.from(JSON.stringify(obj))));
}

test("approval request from Go decodes and checks", async () => {
  const f = fixtures.request;
  const req = await parseApprovalRequest("#" + f.fragment);
  assert.equal(req.approvalId, f.approvalId);
  assert.equal(req.bindingText, f.binding);
  assert.equal(req.binding.rows, 3);
  assert.equal(req.binding.statement, "DELETE FROM public.leads WHERE id = $1");
  assert.equal(req.binding.expiresAt.toISOString(), "2026-11-12T06:02:11.123Z");
  assert.equal(b64urlEncode(req.challenge), f.challenge);
  assert.deepEqual(req.credentialIds.map(b64urlEncode), f.credentialIds);
  assert.equal(await rowsHash(f.lines), f.rowsHash);

  assert.equal(req.lines[0].op, "DELETE");
  assert.equal(req.lines[0].old.name, "Café ✓ lead");
  assert.equal(req.lines[1].cascaded, true);
  assert.equal(req.lines[1].old.note, "note 5 — 日本 🚀");
  assert.equal(req.lines[2].redacted, true);
  assert.equal(req.lines[2].old, null);
});

test("approval request refuses anything that does not match the binding", async () => {
  const f = fixtures.request;
  const base = { approvalId: f.approvalId, binding: f.binding, lines: f.lines };
  const changed = [...f.lines];
  changed[0] = changed[0].replace('"open"', '"won"');
  const cases = [
    ["a line changed", { ...base, lines: changed }, /rowsHash/],
    ["a line dropped", { ...base, lines: f.lines.slice(0, 2) }, /2 lines, binding 3/],
    ["lines reordered", { ...base, lines: [f.lines[1], f.lines[0], f.lines[2]] }, /rowsHash/],
    ["another approval", { ...base, approvalId: "0193a4c2-7d1e-7c3a-9f00-0000000000b2" }, /binding for/],
    ["unknown field", { ...base, extra: 1 }, /unknown field/],
    ["binding kind", { ...base, binding: f.binding.replace("APPROVE", "REVERT") }, /kind/],
  ];
  for (const [name, obj, want] of cases) {
    await assert.rejects(parseApprovalRequest(requestFragment(obj)), (err) => {
      assert.ok(err instanceof CodeError, name);
      assert.match(err.message, want, name);
      return true;
    });
  }
  await assert.rejects(parseApprovalRequest("2." + f.fragment.slice(2)), /must start with/);
  await assert.rejects(parseApprovalRequest("1." + b64urlEncode(utf8("plain"))), /deflate-raw/);
  await assert.rejects(parseApprovalRequest("1.@@"), /base64url/);
});

test("approval request refuses an inflation bomb", async () => {
  const bomb = "1." + b64urlEncode(deflateRawSync(Buffer.alloc(2 << 20, 0x20)));
  await assert.rejects(parseApprovalRequest(bomb), /inflates too far/);
});

test("approval response matches Go byte for byte", () => {
  const f = fixtures.response;
  const code = encodeApprovalResponse({
    approvalId: f.approvalId,
    credentialId: b64urlDecode(f.credentialId),
    authenticatorData: b64urlDecode(f.authenticatorData),
    clientDataJson: b64urlDecode(f.clientDataJson),
    signature: b64urlDecode(f.signature),
  });
  assert.equal(code, f.code);
});

test("registration request from Go decodes", () => {
  const f = fixtures.registrationRequest;
  const req = parseRegistrationRequest("#" + f.fragment);
  assert.equal(b64urlEncode(req.challenge), f.challenge);
  assert.equal(b64urlEncode(req.userId), f.userId);
  assert.equal(req.userName, f.userName);
  assert.equal(req.displayName, f.displayName);

  const short = "1." + b64urlEncode(utf8(JSON.stringify({ challenge: "AA", userId: f.userId, userName: "a", displayName: "a" })));
  assert.throws(() => parseRegistrationRequest(short), /32-byte challenge/);
  const empty = "1." + b64urlEncode(utf8(JSON.stringify({ challenge: f.challenge, userId: f.userId, userName: "", displayName: "a" })));
  assert.throws(() => parseRegistrationRequest(empty), /userName/);
});

test("registration response matches Go byte for byte", () => {
  const f = fixtures.registrationResponse;
  const fields = {
    credentialId: b64urlDecode(f.credentialId),
    clientDataJson: b64urlDecode(f.clientDataJson),
    authenticatorData: b64urlDecode(f.authenticatorData),
    publicKey: b64urlDecode(f.publicKey),
    publicKeyAlgorithm: f.publicKeyAlgorithm,
  };
  assert.equal(encodeRegistrationResponse(fields), f.code);
  assert.throws(() => encodeRegistrationResponse({ ...fields, publicKeyAlgorithm: -257 }), /ES256/);
});

test("base64url is strict", () => {
  assert.deepEqual([...b64urlDecode("-_8")], [0xfb, 0xff]);
  for (const bad of ["-_8=", "+/8", "A", "AB C", "AAB"]) {
    assert.throws(() => b64urlDecode(bad), CodeError, bad);
  }
});

test("binding and lines", () => {
  assert.throws(() => parseBinding(fixtures.request.binding.replace('"rows": 3', '"rows": 51')), /out of 1..50/);
  assert.throws(() => parseLine('{"op": "MERGE", "key": null, "old": null, "set": null, "table": "t", "cascaded": false}'), /op/);
  assert.throws(() => parseLine('{"op": "DELETE", "table": "t", "cascaded": false}'), /missing/);
  const insert = parseLine('{"op": "INSERT", "key": null, "old": null, "set": {"name": "x"}, "table": "public.leads", "cascaded": false}');
  assert.deepEqual(insert.set, { name: "x" });
});

test("relying party", () => {
  assert.deepEqual(relyingParty({ protocol: "https:", hostname: "console.basaltvault.app", port: "" }), {
    rpId: "basaltvault.app",
    origin: "https://console.basaltvault.app",
  });
  assert.deepEqual(relyingParty({ protocol: "http:", hostname: "localhost", port: "8787" }), {
    rpId: "localhost",
    origin: "http://localhost:8787",
  });
  for (const loc of [
    { protocol: "https:", hostname: "evil.example", port: "" },
    { protocol: "http:", hostname: "basaltvault.app", port: "" },
    { protocol: "https:", hostname: "console.basaltvault.app", port: "8443" },
    { protocol: "https:", hostname: "basaltvault.app", port: "" },
    { protocol: "http:", hostname: "console.basaltvault.app", port: "" },
    { protocol: "http:", hostname: "127.0.0.1", port: "8787" },
  ]) {
    assert.throws(() => relyingParty(loc), CodeError);
  }
});
