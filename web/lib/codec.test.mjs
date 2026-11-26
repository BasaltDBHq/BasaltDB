// Runs with `node --test web/lib/*.test.mjs` (make web-check). Reads the
// fixtures the Go tests write, so the page and internal/core/approval agree.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { deflateRawSync } from "node:zlib";

import {
  CodeError,
  b64urlDecode,
  b64urlEncode,
  checkApprovalRequest,
  checkRevealAnswer,
  checkRevealedRow,
  hex,
  newRevealSecret,
  revealChallenge,
  revealKey,
  approvalResponseJSON,
  encodeRegistrationResponse,
  parseApprovalRequest,
  parseBinding,
  parseLine,
  parseRegistrationRequest,
  registrationResponseJson,
  relyingParty,
  rowsHash,
  signingRefusal,
  storeName,
  storeText,
  utf8,
} from "./codec.js";
import { blocked, restoreNote } from "./revert.js";
import { linesNote } from "./approve.js";

const fixtures = JSON.parse(
  readFileSync(new URL("../../internal/core/approval/testdata/fixtures.json", import.meta.url), "utf8"),
);


test("approval request from Go decodes and checks", async () => {
  const f = fixtures.request;
  const req = await parseApprovalRequest("#" + f.fragment);
  assert.equal(req.approvalId, f.approvalId);
  assert.equal(req.bindingText, f.binding);
  assert.equal(req.binding.rows, 3);
  assert.equal(req.binding.request.statement, "DELETE FROM public.leads WHERE id = $1");
  assert.equal(req.binding.agent, "agent:bot");
  assert.equal(req.lines[0].resource, "public.leads");
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
    await assert.rejects(checkApprovalRequest(obj), (err) => {
      assert.ok(err instanceof CodeError, name);
      assert.match(err.message, want, name);
      return true;
    });
  }
  await assert.rejects(parseApprovalRequest("3." + f.fragment.slice(2)), /must start with/);
  await assert.rejects(parseApprovalRequest("2." + b64urlEncode(utf8("plain"))), /deflate-raw/);
  await assert.rejects(parseApprovalRequest("2.@@"), /base64url/);
  // Format 1 is no longer read (clean state).
  const format1 = "1." + b64urlEncode(deflateRawSync(Buffer.from(JSON.stringify(base))));
  await assert.rejects(parseApprovalRequest(format1), /must start with "2\."/);
});

test("approval request refuses an inflation bomb", async () => {
  const bomb = "2." + b64urlEncode(deflateRawSync(Buffer.alloc(2 << 20, 0x20)));
  await assert.rejects(parseApprovalRequest(bomb), /inflates too far/);
});

test("approval response matches Go byte for byte", () => {
  const f = fixtures.response;
  const body = approvalResponseJSON({
    approvalId: f.approvalId,
    credentialId: b64urlDecode(f.credentialId),
    authenticatorData: b64urlDecode(f.authenticatorData),
    clientDataJson: b64urlDecode(f.clientDataJson),
    signature: b64urlDecode(f.signature),
  });
  assert.equal(body, f.json, "the page posts the JSON the engine decodes");
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

test("registration request refuses a field it does not know", () => {
  const f = fixtures.registrationRequest;
  const encode = (extra) =>
    "1." + b64urlEncode(utf8(JSON.stringify({ challenge: f.challenge, userId: f.userId, userName: "a", displayName: "a", ...extra })));
  assert.equal(parseRegistrationRequest(encode({})).userName, "a");
  assert.throws(() => parseRegistrationRequest(encode({ handBack: "A".repeat(21) + "_" })), /unknown field/);
  assert.throws(() => parseRegistrationRequest(encode({ other: 1 })), /unknown field/);
});

test("registration response JSON is what the code carries", () => {
  const fields = {
    credentialId: new Uint8Array([1, 2]),
    clientDataJson: new Uint8Array([3]),
    authenticatorData: new Uint8Array([4]),
    publicKey: new Uint8Array([5]),
    publicKeyAlgorithm: -7,
  };
  const json = registrationResponseJson(fields);
  assert.deepEqual(JSON.parse(json), { credentialId: "AQI", clientDataJson: "Aw", authenticatorData: "BA", publicKey: "BQ", publicKeyAlgorithm: -7 });
  assert.equal(encodeRegistrationResponse(fields), "basalt-passkey.1." + b64urlEncode(utf8(json)));
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
  const store = '"shape": "RECORD", "store": {"kind": "POSTGRES", "verb": "INSERT"}';
  assert.throws(() => parseLine(`{"op": "MERGE", "key": null, "old": null, "set": null, ${store}, "cascaded": false, "resource": "t"}`), /op/);
  assert.throws(() => parseLine(`{"op": "DELETE", ${store}, "cascaded": false, "resource": "t"}`), /missing/);
  assert.throws(() => parseLine('{"op": "INSERT", "key": null, "old": null, "set": {"name": "x"}, "table": "public.leads", "cascaded": false}'), /unknown field "table"/, "the old form is not read");
  assert.throws(() => parseLine(`{"op": "INSERT", "key": null, "old": null, "set": null, "shape": "RECORD", "store": {"kind": "POSTGRES"}, "cascaded": false, "resource": "t"}`), /missing "verb"/);
  const insert = parseLine(`{"op": "INSERT", "key": null, "old": null, "set": {"name": "x"}, ${store}, "cascaded": false, "resource": "public.leads"}`);
  assert.deepEqual(insert.set, { name: "x" });
  assert.equal(insert.resource, "public.leads");
  assert.deepEqual(insert.store, { kind: "POSTGRES", verb: "INSERT" });
  assert.throws(() => parseBinding(fixtures.request.binding.replace('"agent": "agent:bot"', '"agent": "basalt_agent_bot"')), /agent/);
  assert.throws(() => parseBinding(fixtures.request.binding.replace('.123456Z"', '.123456+00:00"')), /expiresAt/);
});

test("relying party", () => {
  assert.deepEqual(relyingParty({ protocol: "https:", hostname: "portal.basaltvault.app", port: "" }), {
    rpId: "basaltvault.app",
    origin: "https://portal.basaltvault.app",
  });
  assert.deepEqual(relyingParty({ protocol: "http:", hostname: "localhost", port: "8787" }), {
    rpId: "localhost",
    origin: "http://localhost:8787",
  });
  for (const loc of [
    { protocol: "https:", hostname: "evil.example", port: "" },
    { protocol: "http:", hostname: "basaltvault.app", port: "" },
    { protocol: "https:", hostname: "portal.basaltvault.app", port: "8443" },
    { protocol: "https:", hostname: "basaltvault.app", port: "" },
    { protocol: "http:", hostname: "portal.basaltvault.app", port: "" },
    { protocol: "http:", hostname: "127.0.0.1", port: "8787" },
    { protocol: "https:", hostname: "basalt-portal.pages.dev", port: "" },
    { protocol: "https:", hostname: "abc123.basalt-portal.pages.dev", port: "" },
    { protocol: "https:", hostname: "console.basaltvault.app", port: "" },
  ]) {
    assert.throws(() => relyingParty(loc), CodeError);
  }
});

test("registration response carries prfSupported only when true", () => {
  const f = fixtures.registrationResponse;
  const fields = {
    credentialId: b64urlDecode(f.credentialId),
    clientDataJson: b64urlDecode(f.clientDataJson),
    authenticatorData: b64urlDecode(f.authenticatorData),
    publicKey: b64urlDecode(f.publicKey),
    publicKeyAlgorithm: f.publicKeyAlgorithm,
  };
  assert.equal(encodeRegistrationResponse({ ...fields, prfSupported: false }), f.code);
  const json = (code) => JSON.parse(new TextDecoder().decode(b64urlDecode(code.split(".").pop())));
  assert.equal(json(encodeRegistrationResponse({ ...fields, prfSupported: true })).prfSupported, true);
  assert.equal("prfSupported" in json(encodeRegistrationResponse(fields)), false);
});

// Rows hidden from the agent: the same vectors internal/core/approval checks.
const reveal = JSON.parse(
  readFileSync(new URL("../../internal/core/approval/testdata/reveal.json", import.meta.url), "utf8"),
);

test("the reveal key and challenge match Go's for the shared vectors", async () => {
  assert.ok(reveal.challenges.some((c) => c.kind === "REVERT"), "a revert vector, with a large plan's rowsHash");
  for (const c of reveal.challenges) {
    const key = await revealKey(b64urlDecode(c.revealSecret));
    assert.equal(hex(key), c.revealKey, c.name);
    const challenge = await revealChallenge(c.kind, c.id, c.nonce, key, c.rowsHash);
    assert.equal(b64urlEncode(challenge), c.challenge, c.name);
  }
});

test("the reveal challenge refuses a bad kind, nonce, key or rowsHash", async () => {
  const c = reveal.challenges[0];
  const key = await revealKey(b64urlDecode(c.revealSecret));
  await assert.rejects(revealChallenge("APPLY", c.id, c.nonce, key, c.rowsHash), CodeError);
  await assert.rejects(revealChallenge(c.kind, c.id.toUpperCase(), c.nonce, key, c.rowsHash), CodeError);
  await assert.rejects(revealChallenge(c.kind, c.id, c.nonce.slice(1), key, c.rowsHash), CodeError);
  await assert.rejects(revealChallenge(c.kind, c.id, c.nonce, key.slice(1), c.rowsHash), CodeError);
  await assert.rejects(revealChallenge(c.kind, c.id, c.nonce, key, c.rowsHash.toUpperCase()), CodeError);
  await assert.rejects(revealKey(new Uint8Array(15)), CodeError);
  assert.equal(newRevealSecret().length, 16);
});

test("a revealed row is checked, unverified or refused exactly as in Go", async () => {
  for (const v of reveal.rows) {
    if (v.result === "REFUSED") {
      await assert.rejects(checkRevealedRow(v.line, v.row), CodeError, v.name);
      continue;
    }
    const got = await checkRevealedRow(v.line, v.row);
    assert.equal(got.checked, v.result === "CHECKED", v.name);
  }
});

test("a reveal answer covers redacted lines in order, once each", async () => {
  const ok = reveal.rows.find((v) => v.result === "CHECKED" && v.line.includes('"op": "DELETE"'));
  const visible = '{"op": "DELETE", "key": {"id": 4}, "old": {"id": 4}, "set": null, "table": "public.leads", "cascaded": false}';
  const lines = [ok.line, visible, ok.line];
  const row = (line) => ({ ...ok.row, line });
  const got = await checkRevealAnswer(lines, { rows: [row(0), row(2)] });
  assert.deepEqual(got.map((r) => [r.line, r.checked]), [[0, true], [2, true]]);
  for (const rows of [[row(3)], [row(-1)], [row(1)], [row(0), row(0)], [row(2), row(0)], [{ ...row(0), extra: 1 }]]) {
    await assert.rejects(checkRevealAnswer(lines, { rows }), CodeError, JSON.stringify(rows.map((r) => r.line)));
  }
  await assert.rejects(checkRevealAnswer(lines, { rows: [], more: 1 }), CodeError);
  await assert.rejects(checkRevealedRow(ok.line, { ...ok.row, secretColumns: [] }), CodeError, "an empty secretColumns");
});

test("the engine's request may carry revealNonce; a bad one is refused", async () => {
  const { approvalId, binding, lines } = fixtures.request;
  const req = { approvalId, binding, lines };
  const nonce = reveal.challenges[0].nonce;
  const got = await checkApprovalRequest({ ...req, revealNonce: nonce });
  assert.equal(got.revealNonce, nonce);
  assert.equal((await checkApprovalRequest(req)).revealNonce, null);
  await assert.rejects(checkApprovalRequest({ ...req, revealNonce: "short" }), CodeError);
  // 22 characters, but not canonical: the last one carries bits past the 16th byte.
  await assert.rejects(checkApprovalRequest({ ...req, revealNonce: nonce.slice(0, 21) + "B" }), CodeError);
});

test("the engine's request may carry the field order, for display only, each name once", async () => {
  const { approvalId, binding, lines } = fixtures.request;
  const req = { approvalId, binding, lines };
  const got = await checkApprovalRequest({ ...req, fields: { "public.leads": ["id", "name", "id", "status"] } });
  assert.deepEqual([...got.fields], [["public.leads", ["id", "name", "status"]]]);
  const bare = await checkApprovalRequest(req);
  assert.equal(bare.fields.size, 0);
  for (const fields of [[], null, { t: "id" }, { t: [""] }, { t: [1] }]) {
    await assert.rejects(checkApprovalRequest({ ...req, fields }), CodeError, JSON.stringify(fields));
  }
  await assert.rejects(checkApprovalRequest({ ...req, columns: { "public.leads": ["id"] } }), CodeError, "the old name columns is refused");
  await assert.rejects(checkApprovalRequest({ ...req, agentName: "bot" }), CodeError, "no agentName: the page derives it from the signed role");
});

test("a long link carries no fields: format 2 has no place for them", async () => {
  const req = await parseApprovalRequest(fixtures.request.fragment);
  assert.equal(req.fields.size, 0);
});

// rehashed is the fixture's approval request with its lines and binding
// edited, the binding's rowsHash recomputed so every other check passes.
async function rehashed(editLine, editBinding = (b) => b) {
  const f = fixtures.request;
  const lines = f.lines.map(editLine);
  const binding = editBinding(f.binding.replace(f.rowsHash, await rowsHash(lines)));
  return checkApprovalRequest({ approvalId: f.approvalId, binding, lines });
}

test("a page draws RECORD rows and SQL requests and signs them", async () => {
  const req = await rehashed((l) => l);
  assert.equal(signingRefusal(req), null);
});

test("a row of shape OBJECT, or of a shape the page does not know, is not offered for signing", async () => {
  for (const shape of ["OBJECT", "GRAPH"]) {
    const req = await rehashed((l, i) => (i === 0 ? l.replace('"shape": "RECORD"', `"shape": "${shape}"`) : l));
    assert.equal(req.lines[0].shape, shape, "the page reads it");
    assert.match(signingRefusal(req), new RegExp(`cannot show rows of shape ${shape}, so it cannot offer them for signing`));
  }
});

test("a request of a family the page has no view for is not offered for signing", async () => {
  const req = await rehashed((l) => l, (b) => b.replace(/"request": \{"kind": "SQL", [^}]*\}/, '"request": {"kind": "DOCUMENT", "filter": {"_id": 3}}'));
  assert.equal(req.binding.request.kind, "DOCUMENT");
  assert.match(signingRefusal(req), /cannot show a DOCUMENT request, so it cannot offer it for signing/);
});

test("store.kind is a label only: a store the page has never heard of still signs, and names itself", async () => {
  const req = await rehashed(
    (l) => l.replaceAll('"kind": "POSTGRES"', '"kind": "MONGO_DB"'),
    (b) => b.replace('"kind": "POSTGRES"', '"kind": "MONGO_DB"'),
  );
  assert.equal(signingRefusal(req), null);
  assert.equal(storeName("POSTGRES"), "Postgres");
  assert.equal(storeName("MONGO_DB"), "Mongo db");
  assert.equal(storeText(req.binding.store), "Mongo db \u00b7 app");
  assert.match(linesNote("MONGO_DB"), /Mongo db checks these exact rows again/);
  assert.match(linesNote("POSTGRES"), /Postgres checks these exact rows again/);
  assert.match(restoreNote("POSTGRES"), /Postgres checks these exact rows again before the revert runs/);
});

test("the revert page keeps Sign off for a row it cannot draw", async () => {
  const revert = JSON.parse(readFileSync(new URL("../../internal/core/revert/testdata/fixtures.json", import.meta.url), "utf8")).request;
  const { checkRevertRequest } = await import("./codec.js");
  const lines = revert.lines.map((l, i) => (i === 2 ? l.replace('"shape": "RECORD"', '"shape": "OBJECT"') : l));
  const binding = revert.binding.replace(revert.rowsHash, await rowsHash(lines));
  const req = await checkRevertRequest({ revertId: revert.revertId, binding, lines });
  assert.match(blocked(req), /cannot show rows of shape OBJECT/);
  const ok = await checkRevertRequest({ revertId: revert.revertId, binding: revert.binding, lines: revert.lines });
  assert.equal(blocked(ok), null);
});
