// Runs with `node --test web/lib/*.test.mjs` (make web-check). The connect
// page against a fake of the connect service's three calls: the fixed
// order, the requests it sends, what it shows, and that the admin
// connection string goes only into the two request bodies.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { b64urlDecode, b64urlEncode } from "./codec.js";
// Imported before any document exists, so the page does not start itself.
import {
  CONNECT_SERVICE,
  Flow,
  LAPTOP_COMMAND,
  SERVICE_PATH,
  call,
  compareCheckCodes,
  passkeyCheckCode,
  readCode,
  refusalFrom,
  refusalText,
  start,
} from "./connect.js";

const PORTAL = "https://portal.basaltvault.app";
// Built in parts so no whole credential-shaped URL sits in the source.
const MARKER = ["postgresql://admin", "Marker-7f3a9c-secret@db.example.com:5432/app"].join(":");
const CODE = "basalt-setup.1.eyJmb3JtYXQiOjF9.AbCdEf";

// The P-256 base point, the contract's check code vector.
const X = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
const Y = "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
const BASE_POINT_CODE = "dbf5 ff76 2025 209d d866";
const fromHex = (h) => Uint8Array.from(h.match(/../g), (b) => parseInt(b, 16));
const SPKI = new Uint8Array([
  0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
  ...fromHex(X),
  ...fromHex(Y),
]);

// ---- A small DOM: what the page uses of it, nothing more. ----

class Node {
  constructor(tag, id = "") {
    this.tagName = tag.toUpperCase();
    this.id = id;
    this.children = [];
    this.hidden = false;
    this.disabled = false;
    this.value = "";
    this.checked = false;
    this.className = "";
    this.dataset = {};
    this.handlers = {};
    this._text = "";
  }
  get textContent() {
    return this._text + this.children.map((c) => c.textContent).join("");
  }
  set textContent(v) {
    this.children = [];
    this._text = String(v);
  }
  get firstChild() {
    return this.children[0] ?? null;
  }
  appendChild(c) {
    this.children.push(c);
    return c;
  }
  removeChild(c) {
    this.children = this.children.filter((x) => x !== c);
    return c;
  }
  addEventListener(type, fn) {
    this.handlers[type] = fn;
  }
  click() {
    return this.handlers.click?.();
  }
  *walk() {
    yield this;
    for (const c of this.children) yield* c.walk();
  }
  querySelector(sel) {
    const m = /^input\[name="([^"]+)"\]:checked$/.exec(sel);
    assert.ok(m, `unsupported selector ${sel}`);
    for (const n of this.walk()) if (n.tagName === "INPUT" && n.name === m[1] && n.checked) return n;
    return null;
  }
}

const IDS = [
  "error", "error-text", "main", "host", "code-box", "code-paste", "code-read", "code-status",
  "summary", "kind", "summary-lines", "facts", "fingerprint",
  "passkey", "passkey-lead", "passkey-go", "passkey-skip", "passkey-status",
  "paste", "database-url", "check", "check-status",
  "review", "notes", "questions", "passkey-now", "approve", "approve-status",
  "result", "result-text", "warnings", "check-code-box", "check-code", "check-problem", "done",
];
const HIDDEN = new Set(["error", "main", "code-box", "summary", "passkey", "passkey-skip", "paste", "review", "passkey-now", "result", "warnings", "check-code-box", "check-problem", "done"]);

// The fake document is the real page's: the same ids, hidden the same way.
test("the fake document has the page's ids and initial hidden states", () => {
  const html = readFileSync(new URL("../connect/index.html", import.meta.url), "utf8");
  const body = html.slice(html.indexOf("<body>"));
  const page = new Map();
  for (const m of body.matchAll(/<[a-z0-9]+ id="([^"]+)"([^>]*)>/g)) page.set(m[1], /\shidden(\s|>|$)/.test(m[2] + ">"));
  assert.deepEqual([...page.keys()].sort(), [...IDS].sort());
  for (const [id, hidden] of page) assert.equal(hidden, HIDDEN.has(id), id);
});

function fakeDocument() {
  const nodes = {};
  for (const id of IDS) {
    nodes[id] = new Node(id === "database-url" ? "input" : "div", id);
    nodes[id].hidden = HIDDEN.has(id);
  }
  globalThis.document = {
    getElementById: (id) => {
      assert.ok(nodes[id], `no element ${id}`);
      return nodes[id];
    },
    createElement: (tag) => new Node(tag),
  };
  return nodes;
}

// everything is every text and value on the page.
function everything(nodes) {
  const out = [];
  for (const root of Object.values(nodes)) for (const n of root.walk()) out.push(n._text, String(n.value));
  return out.join("\n");
}

// ---- A fake connect service. ----

function challenge() {
  return {
    challenge: b64urlEncode(new Uint8Array(32).fill(7)),
    userId: b64urlEncode(new Uint8Array(16).fill(9)),
    userName: "bot@db.example.com",
    displayName: "Basalt approvals",
    expiresAt: "2026-11-20T10:15:00Z",
    mac: "opaque-mac",
  };
}

function summary(kind) {
  return {
    setupId: "0199c0de-0000-7000-8000-000000000001",
    kind,
    agent: kind === "UPGRADE" ? "" : "bot",
    role: kind === "UPGRADE" ? "" : "basalt_agent_bot",
    prefix: "basalt",
    target: { host: "db.example.com", port: 5432, database: "app" },
    write: ["public.leads"],
    read: ["public.notes"],
    expiresAt: "2026-11-21T10:00:00Z",
    fingerprint: "3f9a 21c0 7d44 e1b2 90ac",
    lines: ["This creates the agent bot (role basalt_agent_bot).", "Setup fingerprint: 3f9a 21c0 7d44 e1b2 90ac. Check that bot shows the same fingerprint."],
  };
}

function refusalBody(code, reason, message, retryAfterSeconds) {
  const debug = { reason, message };
  if (retryAfterSeconds) debug.retryAfterSeconds = retryAfterSeconds;
  return JSON.stringify({ code, message, details: [{ type: "basalt.connect.v1.Refusal", value: "AAAA", debug }] });
}

// service answers each method with its handler's { status, body } and
// keeps every call: the method and the request body as sent.
function service(handlers) {
  const calls = [];
  const fetchFn = async (url, init) => {
    assert.ok(url.startsWith(CONNECT_SERVICE + SERVICE_PATH), url);
    const method = url.slice((CONNECT_SERVICE + SERVICE_PATH).length);
    calls.push({ method, url, init, body: JSON.parse(init.body), raw: init.body });
    const h = handlers[method];
    assert.ok(h, `unexpected call ${method}`);
    const { status = 200, body } = await h(JSON.parse(init.body));
    return new Response(typeof body === "string" ? body : JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
  };
  return { calls, fetchFn };
}

function credentials() {
  const log = [];
  return {
    log,
    create: async (opts) => {
      log.push({ op: "create", opts });
      return {
        rawId: new Uint8Array([1, 2, 3, 4]).buffer,
        response: {
          clientDataJSON: new Uint8Array([123, 125]).buffer,
          getPublicKey: () => SPKI.buffer.slice(0),
          getAuthenticatorData: () => new Uint8Array(37).buffer,
          getPublicKeyAlgorithm: () => -7,
        },
        getClientExtensionResults: () => ({ prf: { enabled: true } }),
      };
    },
    get: async (opts) => {
      log.push({ op: "get", opts });
      return {};
    },
  };
}

const CRED_ID = b64urlEncode(new Uint8Array([1, 2, 3, 4]));

// A storage that fails the test if the page touches it.
function guardStorage() {
  const trap = new Proxy({}, { get: () => assert.fail("the page used web storage") });
  globalThis.localStorage = trap;
  globalThis.sessionStorage = trap;
}

function location(hash = "") {
  return { origin: PORTAL, hash };
}

// ---- Units ----

test("the check code of the P-256 base point is the contract's", async () => {
  assert.equal(await passkeyCheckCode(SPKI), BASE_POINT_CODE);
});

test("the setup code is read from a fragment or a whole pasted message", () => {
  assert.equal(readCode(CODE), CODE);
  assert.equal(readCode(`Open https://portal.basaltvault.app/connect#${CODE} and check the fingerprint.`), CODE);
  assert.equal(readCode(`basalt-setup.1.eyJmb3Jt\n  YXQiOjF9.AbCdEf`), CODE, "a wrapped copy still works");
  for (const bad of ["", "hello", "basalt-setup.1.", "basalt-setup.2.abc.def", `basalt-setup.1.${"a".repeat(1600)}.AbCdEf`, "x".repeat(20001)]) {
    assert.equal(readCode(bad), null, bad.slice(0, 40));
  }
});

test("a refusal is read from its detail's debug form", () => {
  const r = refusalFrom(400, refusalBody("failed_precondition", "LOGIN_FAILED", "The database refused the login."));
  assert.equal(r.reason, "LOGIN_FAILED");
  assert.equal(r.message, "The database refused the login.");
  assert.equal(refusalText(r), `The database refused the login.\nOr run the setup on your own computer instead, with no hosted service: ${LAPTOP_COMMAND}`);
  const limited = refusalFrom(429, refusalBody("resource_exhausted", "RATE_LIMITED", "Too many requests.", 60));
  assert.equal(refusalText(limited), "Too many requests.\nTry again in 60 seconds.");
  const busy = refusalFrom(429, refusalBody("resource_exhausted", "BUSY", "Busy.", 5));
  assert.doesNotMatch(refusalText(busy), /basalt init/);
  assert.equal(refusalFrom(502, "<html>bad gateway</html>").message, "The connect service answered with an error (HTTP 502).");
  assert.equal(refusalFrom(400, JSON.stringify({ code: "invalid_argument", message: "raw" })).message, "The connect service answered with an error (invalid_argument).");
  assert.equal(refusalFrom(400, JSON.stringify({ details: [{ type: "basalt.connect.v1.Refusal", debug: { reason: "<b>", message: "m" } }] })).reason, "UNKNOWN");
});

test("a call is one JSON POST to the service, without cookies, referrer, cache or redirects", async () => {
  const { calls, fetchFn } = service({ DescribeSetup: () => ({ body: { ok: true } }) });
  assert.deepEqual(await call(fetchFn, "DescribeSetup", { code: CODE }), { ok: true });
  const c = calls[0];
  assert.equal(c.url, "https://connect.basaltvault.app/basalt.connect.v1.SetupService/DescribeSetup");
  assert.equal(c.init.method, "POST");
  assert.equal(c.init.headers["Content-Type"], "application/json");
  assert.deepEqual(Object.keys(c.init.headers), ["Content-Type"], "only the header the contract names");
  assert.equal(c.init.credentials, "omit");
  assert.equal(c.init.cache, "no-store");
  assert.equal(c.init.redirect, "error");
  assert.equal(c.init.referrerPolicy, "no-referrer");
  assert.deepEqual(c.body, { code: CODE });
});

test("a network failure says only that the service could not be reached", async () => {
  const fetchFn = async (_url, init) => {
    throw new TypeError(`Failed to fetch ${init.body}`);
  };
  await assert.rejects(call(fetchFn, "CheckSetup", { databaseUrl: MARKER }), (err) => {
    assert.equal(err.reason, "UNREACHABLE");
    assert.doesNotMatch(err.message, /Marker/);
    return true;
  });
});

test("check codes: the page's own passkey with the same code, and nothing else", () => {
  const mine = { credentialId: CRED_ID, checkCode: BASE_POINT_CODE };
  assert.equal(compareCheckCodes(mine, [{ credentialId: CRED_ID, label: "", checkCode: BASE_POINT_CODE }]), "");
  assert.match(compareCheckCodes(mine, [{ credentialId: CRED_ID, checkCode: "0000 0000 0000 0000 0000" }]), /different check code/);
  assert.match(compareCheckCodes(mine, [{ credentialId: CRED_ID, checkCode: BASE_POINT_CODE }, { credentialId: "other", checkCode: "x" }]), /did not create/);
  assert.match(compareCheckCodes(mine, []), /does not report the passkey/);
  assert.equal(compareCheckCodes(null, []), "");
  assert.match(compareCheckCodes(null, [{ credentialId: "other" }]), /did not create/);
});

test("the flow refuses a step out of order", async () => {
  const flow = new Flow({ fetch: async () => assert.fail("no call out of order"), credentials: credentials() });
  await assert.rejects(flow.checkSetup(MARKER), /not at the paste step/);
  await assert.rejects(flow.runSetup([]), /not at the approve step/);
  await assert.rejects(flow.createPasskey(), /not at the passkey step/);
  assert.equal(flow.holdsConnectionString, false);
});

// ---- The page ----

test("the page runs only at the portal", async () => {
  const nodes = fakeDocument();
  const out = start({ location: { origin: "https://portal.basaltvault.app.evil.example", hash: `#${CODE}` }, fetch: async () => assert.fail("no call"), credentials: credentials() });
  assert.equal(out, null);
  assert.equal(nodes.error.hidden, false);
  assert.match(nodes["error-text"].textContent, /only runs at https:\/\/portal\.basaltvault\.app/);
  assert.equal(nodes.main.hidden, true);
});

test("an INSTALL runs in the fixed order, and the connection string goes only into the two request bodies", async () => {
  guardStorage();
  const nodes = fakeDocument();
  const ch = challenge();
  const { calls, fetchFn } = service({
    DescribeSetup: () => ({ body: { summary: summary("INSTALL"), challenge: ch } }),
    CheckSetup: () => ({
      body: {
        questions: [{ kind: "ROW_LEVEL_SECURITY", table: "public.leads", text: "public.leads hides its rows with row-level security. Let bot see all 30 rows of this table?", choices: ["ALL_ROWS", "NONE"] }],
        passkeyNeeded: true,
        notes: ["Statement timeout now in force: 5000 ms."],
      },
    }),
    RunSetup: () => ({ body: { warnings: ["row-level security still hides public.notes from basalt_agent_bot"], passkeys: [{ credentialId: CRED_ID, label: "", checkCode: BASE_POINT_CODE }] } }),
  });
  const creds = credentials();
  const loc = location(`#${CODE}`);
  const { flow, ready } = start({ location: loc, fetch: fetchFn, credentials: creds });
  await ready;

  // 1-2: the code was read and described; the host and fingerprint shown.
  assert.deepEqual(calls.map((c) => c.method), ["DescribeSetup"]);
  assert.deepEqual(calls[0].body, { code: CODE });
  assert.equal(nodes.host.textContent, "portal.basaltvault.app");
  assert.equal(nodes.fingerprint.textContent, "3f9a 21c0 7d44 e1b2 90ac");
  assert.match(nodes["summary-lines"].textContent, /This creates the agent bot/);
  assert.match(nodes.facts.textContent, /database app of db\.example\.com:5432/);
  assert.equal(nodes.summary.hidden, false);
  // 3: the passkey step, and nowhere to paste yet.
  assert.equal(nodes.passkey.hidden, false);
  assert.equal(nodes.paste.hidden, true, "nothing is pasted before the passkey step");
  assert.equal(nodes["passkey-go"].textContent, "Create passkey");
  await nodes["passkey-go"].click();
  assert.equal(creds.log.length, 1);
  const pk = creds.log[0].opts.publicKey;
  assert.equal(creds.log[0].op, "create");
  assert.deepEqual(pk.challenge, b64urlDecode(ch.challenge));
  assert.deepEqual(pk.user.id, b64urlDecode(ch.userId));
  assert.equal(pk.rp.id, "basaltvault.app");
  assert.equal(pk.authenticatorSelection.userVerification, "required");
  // 4: the paste box, only now.
  assert.equal(nodes.paste.hidden, false);
  nodes["database-url"].value = MARKER;
  await nodes.check.click();
  assert.equal(nodes["database-url"].value, "", "the box is emptied as soon as it is read");
  assert.deepEqual(calls.map((c) => c.method), ["DescribeSetup", "CheckSetup"]);
  assert.deepEqual(calls[1].body, { code: CODE, databaseUrl: MARKER });
  assert.equal(flow.holdsConnectionString, true);
  // 5: the notes and the questions; the passkey exists, so Approve is on.
  assert.equal(nodes.review.hidden, false);
  assert.equal(nodes.paste.hidden, true);
  assert.match(nodes.notes.textContent, /Statement timeout now in force/);
  assert.match(nodes.questions.textContent, /Let bot see all 30 rows/);
  assert.equal(nodes["passkey-now"].hidden, true);
  assert.equal(nodes.approve.disabled, false);
  // Approve without an answer asks for one and sends nothing.
  await nodes.approve.click();
  assert.match(nodes["approve-status"].textContent, /Answer every question/);
  assert.equal(calls.length, 2);
  const yes = [...nodes.questions.walk()].find((n) => n.tagName === "INPUT" && n.value === "ALL_ROWS");
  yes.checked = true;
  // 6: Approve runs the setup.
  await nodes.approve.click();
  assert.deepEqual(calls.map((c) => c.method), ["DescribeSetup", "CheckSetup", "RunSetup"]);
  const run = calls[2].body;
  assert.equal(run.code, CODE);
  assert.equal(run.databaseUrl, MARKER);
  assert.deepEqual(run.answers, [{ kind: "ROW_LEVEL_SECURITY", table: "public.leads", choice: "ALL_ROWS" }]);
  assert.deepEqual(run.challenge, ch, "the challenge goes back unchanged");
  assert.equal(run.passkey.credentialId, CRED_ID);
  assert.equal(run.passkey.publicKey, b64urlEncode(SPKI));
  assert.equal(run.passkey.publicKeyAlgorithm, -7);
  assert.equal(run.passkey.prfSupported, true);
  assert.equal(flow.holdsConnectionString, false, "cleared after RunSetup");
  // The result, the warnings, the page's own check code, then "done".
  assert.equal(nodes.result.hidden, false);
  assert.match(nodes.warnings.textContent, /row-level security still hides/);
  assert.equal(nodes["check-code"].textContent, BASE_POINT_CODE);
  assert.equal(nodes["check-problem"].hidden, true);
  assert.equal(nodes.done.hidden, false);

  // The connection string is in the two request bodies and nowhere else.
  assert.equal(calls.filter((c) => c.raw.includes(MARKER)).length, 2);
  assert.ok(!calls[0].raw.includes(MARKER));
  for (const c of calls) assert.ok(!c.url.includes("Marker"));
  assert.doesNotMatch(everything(nodes), /Marker-7f3a9c/);
  assert.equal(loc.hash, `#${CODE}`, "the address is not changed");
});

test("a later code signs with the existing passkey, sends nothing of it, and creates one only when the database needs it", async () => {
  const nodes = fakeDocument();
  const { calls, fetchFn } = service({
    DescribeSetup: () => ({ body: { summary: summary("AGENT"), challenge: challenge() } }),
    CheckSetup: () => ({ body: { passkeyNeeded: true } }),
    RunSetup: () => ({ body: { passkeys: [{ credentialId: CRED_ID, checkCode: BASE_POINT_CODE }] } }),
  });
  const creds = credentials();
  const { ready } = start({ location: location(`#${CODE}`), fetch: fetchFn, credentials: creds });
  await ready;
  assert.equal(nodes["passkey-go"].textContent, "Sign with your passkey");
  assert.equal(nodes.paste.hidden, true);
  await nodes["passkey-go"].click();
  assert.equal(creds.log[0].op, "get");
  assert.equal(creds.log[0].opts.publicKey.rpId, "basaltvault.app");
  assert.equal(creds.log[0].opts.publicKey.challenge.length, 32);
  assert.equal(nodes.paste.hidden, false);
  nodes["database-url"].value = MARKER;
  await nodes.check.click();
  // The database has no passkey: one is created before Approve.
  assert.equal(nodes["passkey-now"].hidden, false);
  assert.equal(nodes.approve.disabled, true);
  await nodes["passkey-now"].click();
  assert.equal(creds.log[1].op, "create");
  assert.equal(nodes.approve.disabled, false);
  await nodes.approve.click();
  assert.equal(calls[2].method, "RunSetup");
  assert.equal(calls[2].body.passkey.credentialId, CRED_ID);
  assert.deepEqual(calls[2].body.answers, []);
  assert.equal(nodes["check-code"].textContent, BASE_POINT_CODE);
  assert.equal(nodes.done.hidden, false);
});

test("a later code without a passkey on this device can go on, after a warning; nothing is registered", async () => {
  const nodes = fakeDocument();
  const { calls, fetchFn } = service({
    DescribeSetup: () => ({ body: { summary: summary("UPGRADE"), challenge: challenge() } }),
    CheckSetup: () => ({ body: { notes: ["nothing to upgrade"], nothingToDo: true } }),
    RunSetup: () => ({ body: { nothingToDo: true } }),
  });
  const creds = credentials();
  creds.get = async () => {
    throw Object.assign(new Error("cancelled"), { name: "NotAllowedError" });
  };
  const { ready } = start({ location: location(`#${CODE}`), fetch: fetchFn, credentials: creds });
  await ready;
  await nodes["passkey-go"].click();
  assert.equal(nodes.paste.hidden, true, "a failed sign does not open the paste box");
  assert.equal(nodes["passkey-skip"].hidden, false);
  nodes["passkey-skip"].click();
  assert.match(nodes["passkey-status"].textContent, /may not be the real site/);
  assert.equal(nodes.paste.hidden, false);
  nodes["database-url"].value = MARKER;
  await nodes.check.click();
  await nodes.approve.click();
  assert.equal(calls[2].body.passkey, undefined);
  assert.equal(calls[2].body.challenge, undefined);
  assert.match(nodes["result-text"].textContent, /Nothing to do/);
  assert.equal(nodes["check-code-box"].hidden, true);
  assert.equal(nodes["check-problem"].hidden, true);
});

test("an INSTALL cannot skip the passkey", async () => {
  const nodes = fakeDocument();
  const { fetchFn } = service({ DescribeSetup: () => ({ body: { summary: summary("INSTALL"), challenge: challenge() } }) });
  const creds = credentials();
  creds.create = async () => {
    throw Object.assign(new Error("cancelled"), { name: "NotAllowedError" });
  };
  const { flow, ready } = start({ location: location(`#${CODE}`), fetch: fetchFn, credentials: creds });
  await ready;
  await nodes["passkey-go"].click();
  assert.equal(nodes["passkey-skip"].hidden, true);
  assert.equal(nodes.paste.hidden, true);
  assert.throws(() => flow.skipSign(), /not at the passkey step/);
});

test("refusals show the service's message and the laptop command, and drop the connection string", async () => {
  const nodes = fakeDocument();
  let checks = 0;
  const { calls, fetchFn } = service({
    DescribeSetup: () => ({ body: { summary: summary("INSTALL"), challenge: challenge() } }),
    CheckSetup: () => (++checks === 1
      ? { status: 400, body: refusalBody("failed_precondition", "LOGIN_FAILED", "The database refused the login.") }
      : { body: {} }),
    RunSetup: () => ({ status: 400, body: refusalBody("failed_precondition", "SETUP_FAILED", "The admin role lacks a privilege. Nothing changed.") }),
  });
  const { flow, ready } = start({ location: location(`#${CODE}`), fetch: fetchFn, credentials: credentials() });
  await ready;
  await nodes["passkey-go"].click();
  nodes["database-url"].value = MARKER;
  await nodes.check.click();
  assert.match(nodes["check-status"].textContent, /The database refused the login\./);
  assert.match(nodes["check-status"].textContent, /basalt init --setup-code/);
  assert.equal(flow.holdsConnectionString, false);
  assert.equal(nodes.review.hidden, true);
  assert.equal(nodes.paste.hidden, false, "paste again");
  nodes["database-url"].value = MARKER;
  await nodes.check.click();
  await nodes.approve.click();
  assert.equal(calls.at(-1).method, "RunSetup");
  assert.match(nodes["check-status"].textContent, /lacks a privilege/);
  assert.match(nodes["check-status"].textContent, /Paste the connection string again/);
  assert.equal(nodes.paste.hidden, false);
  assert.equal(nodes.review.hidden, true);
  assert.equal(nodes.done.hidden, true);
  assert.equal(flow.holdsConnectionString, false);
  assert.doesNotMatch(everything(nodes), /Marker-7f3a9c/);
});

test("an expired challenge sends the person back to the link", async () => {
  const nodes = fakeDocument();
  const { fetchFn } = service({
    DescribeSetup: () => ({ body: { summary: summary("INSTALL"), challenge: challenge() } }),
    CheckSetup: () => ({ body: {} }),
    RunSetup: () => ({ status: 400, body: refusalBody("invalid_argument", "CHALLENGE_EXPIRED", "The passkey challenge expired.") }),
  });
  const { flow, ready } = start({ location: location(`#${CODE}`), fetch: fetchFn, credentials: credentials() });
  await ready;
  await nodes["passkey-go"].click();
  nodes["database-url"].value = MARKER;
  await nodes.check.click();
  await nodes.approve.click();
  assert.equal(nodes.error.hidden, false);
  assert.match(nodes["error-text"].textContent, /Open the link from your bot again/);
  assert.equal(flow.holdsConnectionString, false);
});

test("a substituted passkey is called out", async () => {
  const nodes = fakeDocument();
  const { fetchFn } = service({
    DescribeSetup: () => ({ body: { summary: summary("INSTALL"), challenge: challenge() } }),
    CheckSetup: () => ({ body: {} }),
    RunSetup: () => ({ body: { passkeys: [{ credentialId: CRED_ID, checkCode: "0000 0000 0000 0000 0000" }] } }),
  });
  const { ready } = start({ location: location(`#${CODE}`), fetch: fetchFn, credentials: credentials() });
  await ready;
  await nodes["passkey-go"].click();
  nodes["database-url"].value = MARKER;
  await nodes.check.click();
  await nodes.approve.click();
  assert.equal(nodes["check-code"].textContent, BASE_POINT_CODE, "the page's own code, never the service's");
  assert.equal(nodes["check-problem"].hidden, false);
  assert.match(nodes["check-problem"].textContent, /different check code/);
});

test("without a code in the link, the paste box reads one; a bad code shows the refusal", async () => {
  const nodes = fakeDocument();
  let describes = 0;
  const { calls, fetchFn } = service({
    DescribeSetup: (req) => (++describes === 1
      ? { status: 400, body: refusalBody("invalid_argument", "DAMAGED", "This setup code is damaged; copy it again.") }
      : { body: { summary: summary("INSTALL"), challenge: challenge(), echo: req } }),
  });
  const { ready } = start({ location: location(""), fetch: fetchFn, credentials: credentials() });
  await ready;
  assert.equal(calls.length, 0);
  assert.equal(nodes["code-box"].hidden, false);
  nodes["code-paste"].value = "no code here";
  await nodes["code-read"].click();
  assert.equal(calls.length, 0);
  assert.match(nodes["code-status"].textContent, /No setup code found/);
  nodes["code-paste"].value = `Here it is: ${CODE}`;
  await nodes["code-read"].click();
  assert.match(nodes["code-status"].textContent, /damaged; copy it again/);
  assert.equal(nodes.passkey.hidden, true);
  nodes["code-paste"].value = CODE;
  await nodes["code-read"].click();
  assert.equal(nodes.passkey.hidden, false);
  assert.equal(nodes["code-box"].hidden, true);
  assert.deepEqual(calls.map((c) => c.body), [{ code: CODE }, { code: CODE }]);
});


test("a refused passkey sends the person back to the link, never in a loop", async () => {
  const nodes = fakeDocument();
  const { calls, fetchFn } = service({
    DescribeSetup: () => ({ body: { summary: summary("INSTALL"), challenge: challenge() } }),
    CheckSetup: () => ({ body: {} }),
    RunSetup: () => ({ status: 400, body: refusalBody("invalid_argument", "PASSKEY_INVALID", "The passkey registration was refused.") }),
  });
  const { flow, ready } = start({ location: location(`#${CODE}`), fetch: fetchFn, credentials: credentials() });
  await ready;
  await nodes["passkey-go"].click();
  nodes["database-url"].value = MARKER;
  await nodes.check.click();
  await nodes.approve.click();
  assert.equal(nodes.error.hidden, false);
  assert.match(nodes["error-text"].textContent, /Open the link from your bot again/);
  assert.equal(nodes.paste.hidden, true, "no retry with the same registration");
  assert.equal(calls.filter((c) => c.method === "RunSetup").length, 1);
  assert.equal(flow.holdsConnectionString, false);
});

test("a RunSetup answer that never arrives shows the page's own check code and sends the person to the bot", async () => {
  const nodes = fakeDocument();
  const { fetchFn } = service({
    DescribeSetup: () => ({ body: { summary: summary("INSTALL"), challenge: challenge() } }),
    CheckSetup: () => ({ body: {} }),
    RunSetup: () => {
      throw new TypeError("Failed to fetch");
    },
  });
  const { flow, ready } = start({ location: location(`#${CODE}`), fetch: fetchFn, credentials: credentials() });
  await ready;
  await nodes["passkey-go"].click();
  nodes["database-url"].value = MARKER;
  await nodes.check.click();
  await nodes.approve.click();
  assert.match(nodes["error-text"].textContent, /cannot tell whether the setup ran/);
  assert.match(nodes["error-text"].textContent, /Tell your bot "done"/);
  assert.equal(nodes.paste.hidden, true);
  assert.equal(nodes["check-code"].textContent, BASE_POINT_CODE);
  assert.equal(nodes.result.hidden, false);
  assert.equal(nodes.done.hidden, true);
  assert.equal(flow.holdsConnectionString, false);
  assert.doesNotMatch(everything(nodes), /Marker-7f3a9c/);
});
