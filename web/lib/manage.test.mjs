// Runs with `node --test web/lib/*.test.mjs` (make web-check).
import { test } from "node:test";
import assert from "node:assert/strict";

import { CodeError, b64urlDecode, b64urlEncode, hex, utf8 } from "./codec.js";
import {
  CHECK_RESPONSE_PREFIX,
  checkChallenge,
  encodeCheckResponse,
  modeForPath,
  parseManageRequest,
  sendForgetSignals,
  signalSupport,
} from "./manage.js";

const CHALLENGE = "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI"; // 32 bytes of 0x42
// The same vector as internal/passkey TestCheckChallengeVector.
const CHECK_CHALLENGE_HEX = "da15f26856ebfb64b0b6e248d91c0969cc1724c608287249425d9d06c4e4ced6";

function fragment(obj) {
  return "#1." + b64urlEncode(utf8(JSON.stringify(obj)));
}

const check = { mode: "CHECK", challenge: CHALLENGE, credentials: [{ credentialId: "AQID", label: "laptop" }] };
const forget = {
  mode: "FORGET",
  removed: [{ credentialId: "AQID", label: "old phone", userHandle: "BAUG" }],
  accepted: ["BwgJ"],
};

test("parses a check request", () => {
  const req = parseManageRequest(fragment(check));
  assert.equal(req.mode, "CHECK");
  assert.equal(req.challenge, CHALLENGE);
  assert.deepEqual([...req.credentials[0].id], [1, 2, 3]);
  assert.equal(req.credentials[0].label, "laptop");
});

test("parses a forget request, user handle optional", () => {
  const req = parseManageRequest(fragment(forget));
  assert.equal(req.mode, "FORGET");
  assert.equal(req.removed[0].userHandle, "BAUG");
  const without = parseManageRequest(fragment({ ...forget, removed: [{ credentialId: "AQID", label: "x" }] }));
  assert.equal(without.removed[0].userHandle, undefined);
});

test("refuses bad requests", () => {
  const bad = [
    "#2.e30",
    "#1.not json",
    fragment({ mode: "APPROVE" }),
    fragment({ ...check, challenge: "AQID" }),
    fragment({ ...check, credentials: [] }),
    fragment({ ...check, extra: 1 }),
    fragment({ ...check, credentials: [{ credentialId: "AQID", label: "" }] }),
    fragment({ ...forget, removed: [] }),
    fragment({ ...forget, removed: [{ credentialId: "AQ==", label: "x" }] }),
  ];
  for (const f of bad) assert.throws(() => parseManageRequest(f), CodeError, f);
});

test("the check challenge has its own prefix and matches the Go vector", async () => {
  assert.equal(hex(await checkChallenge(CHALLENGE)), CHECK_CHALLENGE_HEX);
});

test("encodes the check response the CLI reads", () => {
  const code = encodeCheckResponse({
    challenge: CHALLENGE,
    found: [{ credentialId: new Uint8Array([1]), authenticatorData: new Uint8Array([2]), clientDataJson: new Uint8Array([3]), signature: new Uint8Array([4]) }],
    missing: ["BwgJ"],
  });
  assert.ok(code.startsWith(CHECK_RESPONSE_PREFIX));
  const body = JSON.parse(new TextDecoder().decode(b64urlDecode(code.slice(CHECK_RESPONSE_PREFIX.length))));
  assert.deepEqual(body, {
    challenge: CHALLENGE,
    found: [{ credentialId: "AQ", authenticatorData: "Ag", clientDataJson: "Aw", signature: "BA" }],
    missing: ["BwgJ"],
  });
});

test("signal support is feature-detected", () => {
  assert.deepEqual(signalSupport(undefined), { unknownCredential: false, allAcceptedCredentials: false });
  assert.deepEqual(signalSupport({}), { unknownCredential: false, allAcceptedCredentials: false });
  assert.deepEqual(signalSupport({ signalUnknownCredential: async () => {} }), { unknownCredential: true, allAcceptedCredentials: false });
  assert.deepEqual(
    signalSupport({ signalUnknownCredential: async () => {}, signalAllAcceptedCredentials: async () => {} }),
    { unknownCredential: true, allAcceptedCredentials: true },
  );
});

function fakePKC({ unknown = true, all = true, failAll = false } = {}) {
  const calls = [];
  const pkc = {};
  if (unknown) pkc.signalUnknownCredential = async (args) => calls.push(["unknown", args]);
  if (all) {
    pkc.signalAllAcceptedCredentials = async (args) => {
      calls.push(["all", args]);
      if (failAll) throw new Error("not allowed");
    };
  }
  return { pkc, calls };
}

test("forget is a no-op where the browser has no Signal API", async () => {
  const out = await sendForgetSignals(undefined, "localhost", parseManageRequest(fragment(forget)));
  assert.deepEqual(out, { supported: false, outcomes: [] });
  const out2 = await sendForgetSignals({}, "localhost", parseManageRequest(fragment(forget)));
  assert.equal(out2.supported, false);
});

test("forget signals the unknown credential and, with a user handle, the accepted list", async () => {
  const { pkc, calls } = fakePKC();
  const out = await sendForgetSignals(pkc, "basaltvault.app", parseManageRequest(fragment(forget)));
  assert.equal(out.supported, true);
  assert.deepEqual(calls, [
    ["unknown", { rpId: "basaltvault.app", credentialId: "AQID" }],
    ["all", { rpId: "basaltvault.app", userId: "BAUG", allAcceptedCredentialIds: ["BwgJ"] }],
  ]);
  assert.ok(out.outcomes.every((o) => o.ok));
});

test("forget skips the accepted list without a user handle, and reports failures without throwing", async () => {
  const noHandle = { ...forget, removed: [{ credentialId: "AQID", label: "x" }] };
  const a = fakePKC();
  await sendForgetSignals(a.pkc, "localhost", parseManageRequest(fragment(noHandle)));
  assert.deepEqual(a.calls.map((c) => c[0]), ["unknown"]);

  const b = fakePKC({ unknown: false, failAll: true });
  const out = await sendForgetSignals(b.pkc, "localhost", parseManageRequest(fragment(forget)));
  assert.equal(out.supported, true);
  assert.deepEqual(out.outcomes, [{ label: "old phone", call: "signalAllAcceptedCredentials", ok: false, error: "not allowed" }]);
});

test("the path names the mode", () => {
  assert.equal(modeForPath("/passkeys/check"), "CHECK");
  assert.equal(modeForPath("/passkeys/forget"), "FORGET");
  for (const p of ["/passkeys/", "/passkeys/register", "/passkeys/check/", "/approvals/x"]) {
    assert.throws(() => modeForPath(p), CodeError, p);
  }
});
