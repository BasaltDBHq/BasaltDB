// Runs with `node --test web/lib/*.test.mjs` (make web-check). The connect
// page against a fake of the connect service: the fixed order, the screens,
// the requests it sends, what it shows, and that the admin connection
// string goes only into the CheckSetup and RunSetup bodies.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { b64urlDecode, b64urlEncode } from "./codec.js";
// Loaded before any document exists, so the page does not start itself.
import {
  CONNECT_SERVICE,
  Flow,
  LAPTOP_COMMAND,
  LATE_MS,
  Labels,
  MAX_LABELS,
  NOT_POSTGRES,
  SERVICE_PATH,
  WAITLIST,
  answersFor,
  call,
  compareCheckCodes,
  databaseView,
  passkeyCheckCode,
  readCode,
  refusalFrom,
  refusalText,
  restQuestion,
  start,
  tableRows,
} from "./connect.js";

const PORTAL = "https://portal.basaltvault.app";
// Built in parts so no whole credential-shaped URL sits in the source.
const MARKER = ["postgresql://admin", "Marker-7f3a9c-secret@db.example.com:5432/app"].join(":");
const CODE = "basalt-setup.1.eyJmb3JtYXQiOjF9.AbCdEf";
const HTML = readFileSync(new URL("../connect/index.html", import.meta.url), "utf8");

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
    this.attrs = {};
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
  setAttribute(k, v) {
    this.attrs[k] = String(v);
  }
  getAttribute(k) {
    return this.attrs[k] ?? null;
  }
  addEventListener(type, fn) {
    this.handlers[type] = fn;
  }
  click() {
    return this.handlers.click?.();
  }
  fire(type) {
    return this.handlers[type]?.();
  }
  *walk() {
    yield this;
    for (const c of this.children) yield* c.walk();
  }
}

// The page's elements with an id, their tag and whether they start hidden,
// read from the real page.
const PAGE = (() => {
  const body = HTML.slice(HTML.indexOf("<body"));
  const out = new Map();
  for (const m of body.matchAll(/<([a-z0-9]+) id="([^"]+)"([^>]*)>/g)) out.set(m[2], { tag: m[1], hidden: /\shidden(\s|>|$)/.test(m[3] + ">") });
  return out;
})();

test("every element with an id names it first, so the fake document has them all", () => {
  const ids = [...HTML.matchAll(/\sid="([^"]+)"/g)].map((m) => m[1]);
  assert.deepEqual([...PAGE.keys()].sort(), [...new Set(ids)].sort());
  assert.equal(ids.length, new Set(ids).size, "no id twice");
});

function fakeDocument() {
  const nodes = {};
  for (const [id, { tag, hidden }] of PAGE) {
    nodes[id] = new Node(tag, id);
    nodes[id].hidden = hidden;
  }
  nodes["database-url"].type = "password";
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
  for (const root of Object.values(nodes)) for (const n of root.walk()) out.push(n._text, String(n.value), ...Object.values(n.attrs));
  return out.join("\n");
}

// shown is the one screen that is not hidden.
function shown(nodes) {
  const on = [...PAGE.keys()].filter((id) => id.startsWith("s-") && !nodes[id].hidden);
  assert.equal(on.length, 1, `screens shown: ${on}`);
  return on[0];
}

function find(root, pred) {
  for (const n of root.walk()) if (pred(n)) return n;
  return null;
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

// summary is a code with a target and write/read lists; connectOnly is a
// connect-only code with allTables.
function summary(kind) {
  return {
    setupId: "0199c0de-0000-7000-8000-000000000001",
    kind,
    agent: kind === "UPGRADE" ? "" : "familite-bot",
    role: kind === "UPGRADE" ? "" : "basalt_agent_familite_bot",
    prefix: "basalt",
    target: { host: "db.example.com", port: 5432, database: "app" },
    write: ["public.leads"],
    read: ["public.notes"],
    expiresAt: "2026-11-21T10:00:00Z",
    fingerprint: "3f9a 21c0 7d44 e1b2 90ac",
    lines: ["This creates the agent familite-bot (role basalt_agent_familite_bot)."],
  };
}

function connectOnly(kind = "INSTALL") {
  const s = summary(kind);
  delete s.target;
  delete s.write;
  delete s.read;
  s.allTablesSchemas = ["public"];
  return s;
}

const SUPABASE = { host: "aws-0-eu-central-1.pooler.supabase.com", port: 5432, database: "postgres", supabaseRef: "abcdwxyzqrst" };
const PREVIEW_TICKET = "preview-ticket-Q7x";
const SETUP_TICKET = "setup-ticket-Z9k";

function connectOnlyCheck(extra = {}) {
  return {
    questions: [
      { kind: "ROW_LEVEL_SECURITY", table: "public.users", text: "q1", choices: ["ALL_ROWS", "NONE"] },
      { kind: "ROW_LEVEL_SECURITY", table: "public.payments", text: "q2", choices: ["ALL_ROWS", "NONE"] },
    ],
    passkeyNeeded: true,
    notes: ["Statement timeout now in force: 5000 ms."],
    database: SUPABASE,
    tables: ["public.logs", "public.payments", "public.users"],
    readOnly: ["public.logs"],
    excluded: [{ table: "public.audit", owner: "supabase_admin" }],
    columns: [
      { table: "public.users", column: "email" },
      { table: "public.users", column: "phone" },
      { table: "public.users", column: "password_hash", class: "SECRET" },
      { table: "public.users", column: "created_at", class: "PUBLIC" },
      { table: "public.payments", column: "card_last4" },
      { table: "public.logs", column: "line", class: "FREE_TEXT" },
      { table: "public.logs", column: "at" },
    ],
    ticket: PREVIEW_TICKET,
    ...extra,
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
  return { calls, fetchFn, methods: () => calls.map((c) => c.method) };
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

// clock is a fake time: sleep moves it on at once.
function clock() {
  const c = { t: 0, slept: 0 };
  c.sleep = async (ms) => {
    c.t += ms;
    c.slept++;
  };
  c.now = () => c.t;
  return c;
}

function env(fetchFn, creds = credentials(), hash = `#${CODE}`) {
  const c = clock();
  return { location: { origin: PORTAL, hash }, fetch: fetchFn, credentials: creds, sleep: c.sleep, now: c.now, clock: c };
}

// through takes the page from the link to the paste step.
async function toPaste(nodes, e) {
  const out = start(e);
  await out.ready;
  assert.equal(shown(nodes), "s-bot");
  await nodes["same-code"].click();
  assert.equal(shown(nodes), "s-passkey");
  await nodes["passkey-go"].click();
  assert.equal(shown(nodes), "s-paste");
  return out;
}

async function paste(nodes, value = MARKER) {
  nodes["database-url"].value = value;
  await nodes.check.click();
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

test("a refusal is read from its detail's debug form, with the other way for the kind of code", () => {
  const r = refusalFrom(400, refusalBody("failed_precondition", "LOGIN_FAILED", "The database refused the login."));
  assert.equal(r.reason, "LOGIN_FAILED");
  assert.equal(r.message, "The database refused the login.");
  assert.equal(refusalText(r), `The database refused the login.\nOr run the setup on your own computer instead, with no hosted service: ${LAPTOP_COMMAND}`);
  assert.equal(refusalText(r, true), "The database refused the login.\nOr ask your bot for a new setup code made with --database-url.");
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

test("a database is named by its Supabase project or its host", () => {
  assert.deepEqual(databaseView(SUPABASE), { big: "abcdwxyzqrst", sub: "Supabase project · database postgres", line: "Supabase project abcdwxyzqrst, database postgres" });
  assert.deepEqual(databaseView({ host: "db.example.com", port: 6543, database: "app" }), { big: "db.example.com", sub: "Port 6543 · database app", line: "db.example.com:6543, database app" });
  assert.equal(databaseView(null), null);
});

test("tables get ticks only for an allTables INSTALL that has not run", () => {
  const all = tableRows(connectOnly(), connectOnlyCheck());
  assert.equal(all.ticks, true);
  assert.deepEqual(all.rows, [{ name: "public.logs", access: "noKey" }, { name: "public.payments", access: "write" }, { name: "public.users", access: "write" }]);
  assert.equal(tableRows(connectOnly("AGENT"), connectOnlyCheck()).ticks, false, "a recovery code keeps its tables");
  assert.equal(tableRows(connectOnly(), connectOnlyCheck({ alreadyRan: true })).ticks, false);
  const listed = tableRows(summary("INSTALL"), {});
  assert.equal(listed.ticks, false);
  assert.deepEqual(listed.rows, [{ name: "public.leads", access: "write" }, { name: "public.notes", access: "read" }]);
});

test("row-level security questions are answered all rows for the included tables only", () => {
  const qs = connectOnlyCheck().questions;
  assert.deepEqual(answersFor(qs, ["public.users"]), [{ kind: "ROW_LEVEL_SECURITY", table: "public.users", choice: "ALL_ROWS" }]);
  assert.equal(answersFor(qs, null).length, 2);
});

test("labels: only the changes, each with the class it had, and the rest as PUBLIC or restPublic", () => {
  const l = new Labels(connectOnlyCheck().columns);
  const both = ["public.users", "public.payments"];
  assert.deepEqual(l.request(both, "changes"), {}, "no change, no entry");
  l.set("public.users", "email", { class: "IDENTIFIER", entityType: "EMAIL" });
  l.set("public.users", "password_hash", { class: "SECRET" }); // as it was: no entry
  l.set("public.users", "created_at", { class: "IDENTIFIER", entityType: "OTHER" });
  l.set("public.payments", "card_last4", { class: "SECRET" });
  assert.deepEqual(l.request(["public.users"], "changes").columnClasses, [
    { table: "public.users", column: "email", class: "IDENTIFIER", entityType: "EMAIL", was: { class: "UNCLASSIFIED" } },
    { table: "public.users", column: "created_at", class: "IDENTIFIER", entityType: "OTHER", was: { class: "PUBLIC" } },
  ], "an unticked table's labels are dropped");
  assert.deepEqual(l.request(both, "skip"), {});
  assert.deepEqual(l.unlabeled(both).map((c) => c.column), ["phone"]);
  const rest = l.request(both, "rest");
  assert.equal(rest.restPublic, undefined);
  assert.deepEqual(rest.columnClasses.at(-1), { table: "public.users", column: "phone", class: "PUBLIC", was: { class: "UNCLASSIFIED" } });
  l.set("public.users", "phone", { class: "IDENTIFIER", entityType: "PHONE", phoneRegion: "" });
  assert.match(l.problem(both), /country of the phone numbers in users\.phone/);
  l.set("public.users", "phone", { class: "IDENTIFIER", entityType: "PHONE", phoneRegion: "DE" });
  assert.equal(l.problem(both), "");
  assert.deepEqual(l.request(both, "changes").columnClasses.find((e) => e.column === "phone"), { table: "public.users", column: "phone", class: "IDENTIFIER", entityType: "PHONE", phoneRegion: "DE", was: { class: "UNCLASSIFIED" } });

  const many = new Labels(Array.from({ length: MAX_LABELS + 1 }, (_, i) => ({ table: "public.t", column: `c${i}` })));
  many.set("public.t", "c0", { class: "SECRET" });
  const over = many.request(["public.t"], "rest");
  assert.equal(over.restPublic, true, "over 500 entries, the rest goes as one flag");
  assert.deepEqual(over.columnClasses, [{ table: "public.t", column: "c0", class: "SECRET", was: { class: "UNCLASSIFIED" } }]);
  assert.equal(restQuestion(many.unlabeled(["public.t"])), "Mark 500 columns in 1 table as not personal?");
});

test("the flow refuses a step out of order", async () => {
  const flow = new Flow({ fetch: async () => assert.fail("no call out of order"), credentials: credentials() });
  await assert.rejects(flow.checkSetup(MARKER), /not at the paste step/);
  await assert.rejects(flow.runSetup([]), /not at the approve step/);
  await assert.rejects(flow.createPasskey(), /not at the passkey step/);
  assert.throws(() => flow.confirmBot(), /not at the code check/);
  assert.equal(flow.holdsConnectionString, false);
});

test("the page names no connection as made and links the waitlist plainly", () => {
  const text = HTML.replace(/<[^>]+>/g, " ");
  assert.doesNotMatch(text, /\bconnected\b/i);
  assert.match(HTML, new RegExp(`<a href="${WAITLIST.replace(/[.#/]/g, "\\$&")}" target="_blank" rel="noopener noreferrer">Join the list</a>`));
  assert.equal((HTML.match(/<a /g) ?? []).length, 1, "one link, the waitlist");
  assert.doesNotMatch(HTML, /<form|<iframe|style="/);
  assert.match(HTML, /<input id="database-url" class="text" type="password" autocomplete="off"/);
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

test("a connect-only INSTALL: the code, the passkey, the reach check, ticks, labels, approval and the pick-up", async () => {
  guardStorage();
  const nodes = fakeDocument();
  const ch = challenge();
  let polls = 0;
  let watches = 0;
  const { calls, fetchFn, methods } = service({
    DescribeSetup: () => ({ body: { summary: connectOnly(), challenge: ch } }),
    CheckSetup: () => ({ body: connectOnlyCheck() }),
    HandoffStatus: (req) => {
      if (req.ticket.startsWith("preview")) {
        polls++;
        return { body: { state: "HELD", phase: "PREVIEW", ticket: `${PREVIEW_TICKET}${polls}`, reach: polls < 2 ? undefined : { result: "REACHABLE", reportedAt: "2026-11-20T10:00:15Z" } } };
      }
      watches++;
      return { body: watches < 3 ? { state: "HELD", phase: "SET_UP", ticket: `${SETUP_TICKET}${watches}` } : { state: "COLLECTED", phase: "SET_UP", collectedAt: "2026-11-20T10:01:00Z", ticket: `${SETUP_TICKET}${watches}` } };
    },
    RunSetup: () => ({ body: { passkeys: [{ credentialId: CRED_ID, label: "", checkCode: BASE_POINT_CODE }], ticket: SETUP_TICKET } }),
  });
  const creds = credentials();
  const e = env(fetchFn, creds);
  const { flow, ready } = start(e);
  await ready;

  // 1: the bot, the full code, two buttons; nothing to paste yet.
  assert.deepEqual(methods(), ["DescribeSetup"]);
  assert.equal(shown(nodes), "s-bot");
  assert.equal(nodes["addr-warn"].hidden, false);
  assert.equal(nodes.host.textContent, "portal.basaltvault.app");
  assert.equal(nodes["bot-name"].textContent, "familite-bot");
  assert.equal(nodes.avatar.textContent, "F");
  assert.equal(nodes["bot-wants"].textContent, "wants access to your database");
  assert.equal(nodes.fingerprint.textContent, "3f9a 21c0 7d44 e1b2 90ac");
  assert.match(nodes.facts.textContent, /Database: the one you paste below/);
  assert.equal(nodes.back.hidden, true);
  await nodes["same-code"].click();

  // 2: create the passkey.
  assert.equal(shown(nodes), "s-passkey");
  assert.equal(nodes["passkey-title"].textContent, "Create your approval passkey");
  assert.equal(nodes["passkey-existing"].hidden, false, "Already have one? Use it");
  await nodes["passkey-go"].click();
  const pk = creds.log[0].opts.publicKey;
  assert.equal(creds.log[0].op, "create");
  assert.deepEqual(pk.challenge, b64urlDecode(ch.challenge));
  assert.deepEqual(pk.user.id, b64urlDecode(ch.userId));
  assert.equal(pk.rp.id, "basaltvault.app");

  // 3: the string, hidden by default; the toggle shows it and a new paste
  // hides it again. Something that is not Postgres is refused here.
  assert.equal(shown(nodes), "s-paste");
  assert.match(nodes.disclosure.textContent, /while your bot tests that its server can reach it, without signing in/);
  assert.equal(nodes["database-url"].type, "password");
  await nodes.reveal.click();
  assert.equal(nodes["database-url"].type, "text");
  assert.equal(nodes.reveal.getAttribute("aria-pressed"), "true");
  assert.equal(nodes.reveal.getAttribute("aria-label"), "Hide connection string");
  nodes["database-url"].fire("paste");
  assert.equal(nodes["database-url"].type, "password");
  assert.equal(nodes.reveal.getAttribute("aria-label"), "Show connection string");
  await paste(nodes, "mysql://root:pw@db.example.com/app");
  assert.deepEqual(methods(), ["DescribeSetup"], "refused on the page, before any call");
  assert.equal(nodes["paste-error"].textContent, NOT_POSTGRES);
  await nodes.reveal.click();
  await paste(nodes);
  assert.equal(nodes["database-url"].value, "", "the box is emptied as soon as it is read");
  assert.equal(nodes["database-url"].type, "password");

  // 3b: CheckSetup, then HandoffStatus with the newest ticket until the
  // engine's report, then screen 4.
  assert.deepEqual(methods(), ["DescribeSetup", "CheckSetup", "HandoffStatus", "HandoffStatus"]);
  assert.deepEqual(calls[1].body, { code: CODE, databaseUrl: MARKER });
  assert.deepEqual(calls[2].body, { ticket: PREVIEW_TICKET });
  assert.deepEqual(calls[3].body, { ticket: `${PREVIEW_TICKET}1` }, "the newest ticket");
  assert.equal(nodes["chk-login"].textContent, "Signed in to the database");
  assert.equal(nodes["chk-tables"].textContent, "Found 3 tables");
  assert.equal(nodes["chk-reach"].textContent, "familite-bot can reach it");

  // 4: the database large, its tables ticked, one read only, one not
  // offered. Unticking one changes the count; none at all is refused.
  assert.equal(shown(nodes), "s-tables");
  assert.equal(nodes["db-name"].textContent, "abcdwxyzqrst");
  assert.equal(nodes["db-sub"].textContent, "Supabase project · database postgres");
  assert.equal(nodes["db-label"].textContent, "This is the database familite-bot will use");
  assert.equal(nodes["db-reach"].hidden, false);
  assert.equal(nodes["tables-count"].textContent, "3 of 3");
  assert.match(nodes.tables.textContent, /logsread only \(no row ID\)/);
  assert.equal(nodes.excluded.textContent, "Not offered: audit (owned by another role)");
  assert.match(nodes["tables-note"].textContent, /every row of the ticked tables, and can't see the unticked ones/);
  const boxes = [...nodes.tables.walk()].filter((n) => n.tagName === "INPUT");
  assert.equal(boxes.length, 3);
  for (const b of boxes) {
    b.checked = false;
    b.fire("change");
  }
  assert.equal(nodes["tables-next"].disabled, true);
  assert.match(nodes["tables-error"].textContent, /Tick at least one table/);
  for (const b of boxes.filter((x) => x.value !== "public.payments")) {
    b.checked = true;
    b.fire("change");
  }
  assert.equal(nodes["tables-count"].textContent, "2 of 3");
  await nodes["tables-next"].click();

  // 5: the labels of the ticked tables, the first folded open. A classed
  // column offers no blank; PUBLIC and FREE_TEXT show fixed with change.
  assert.equal(shown(nodes), "s-labels");
  const tables = nodes["label-tables"].children;
  assert.deepEqual(tables.map((d) => d.children[0].textContent), ["users 4 columns", "logs 2 columns"], "in CheckSetup's order");
  assert.deepEqual(tables.map((d) => d.open), [true, false]);
  const select = (name) => find(nodes["label-tables"], (n) => n.tagName === "SELECT" && n.getAttribute("aria-label") === `Label for ${name}`);
  const hasBlank = (s) => s.children.some((o) => o.tagName === "OPTION" && o.value === "" && !o.disabled);
  assert.equal(hasBlank(select("users.email")), true);
  assert.equal(hasBlank(select("users.password_hash")), false, "never erases a class");
  assert.equal(select("users.password_hash").value, "SECRET");
  assert.equal(select("users.created_at").hidden, true);
  assert.match(nodes["label-tables"].textContent, /Not personal/);
  assert.match(nodes["unlabeled-warn"].textContent, /They'll be blocked once PII protection ships, until you label them\./);
  select("users.email").value = "IDENTIFIER:EMAIL";
  select("users.email").fire("change");
  select("users.phone").value = "IDENTIFIER:PHONE";
  select("users.phone").fire("change");
  await nodes["labels-rest"].click();
  assert.match(nodes["labels-error"].textContent, /country of the phone numbers in users\.phone/);
  const region = find(nodes["label-tables"], (n) => n.tagName === "INPUT" && /users\.phone/.test(n.getAttribute("aria-label") ?? ""));
  assert.equal(region.hidden, false);
  region.value = "de";
  region.fire("input");
  // Mark the rest: the count first (logs.at, in a folded table), then the
  // approval.
  await nodes["labels-rest"].click();
  assert.equal(nodes["rest-confirm"].hidden, false);
  assert.equal(nodes["rest-question"].textContent, "Mark 1 column in 1 table as not personal?");
  await nodes["rest-yes"].click();

  // 6: approve.
  assert.equal(shown(nodes), "s-approve");
  assert.equal(nodes["ap-db"].textContent, "abcdwxyzqrst");
  assert.equal(nodes["ap-counts"].textContent, "2 tables · 2 columns marked · the rest not personal");
  assert.equal(nodes["ap-limits"].hidden, false);
  assert.match(HTML, /<button id="approve" type="button">Approve with passkey<\/button>/);
  assert.equal(flow.holdsConnectionString, true);
  await nodes.approve.click();
  const run = calls.find((c) => c.method === "RunSetup").body;
  assert.equal(run.code, CODE);
  assert.equal(run.databaseUrl, MARKER);
  assert.deepEqual(run.includedTables, ["public.logs", "public.users"]);
  assert.deepEqual(run.answers, [{ kind: "ROW_LEVEL_SECURITY", table: "public.users", choice: "ALL_ROWS" }], "no answer for the unticked table");
  assert.deepEqual(run.columnClasses, [
    { table: "public.users", column: "email", class: "IDENTIFIER", entityType: "EMAIL", was: { class: "UNCLASSIFIED" } },
    { table: "public.users", column: "phone", class: "IDENTIFIER", entityType: "PHONE", phoneRegion: "DE", was: { class: "UNCLASSIFIED" } },
    { table: "public.logs", column: "at", class: "PUBLIC", was: { class: "UNCLASSIFIED" } },
  ]);
  assert.equal(run.restPublic, undefined);
  assert.deepEqual(run.challenge, ch, "the challenge goes back unchanged");
  assert.equal(run.passkey.credentialId, CRED_ID);
  assert.equal(run.passkey.publicKey, b64urlEncode(SPKI));
  assert.equal(flow.holdsConnectionString, false, "cleared after RunSetup");

  // 7: set up, the pick-up watched with the set-up ticket, the check code.
  assert.equal(shown(nodes), "s-done");
  assert.equal(nodes["addr-warn"].hidden, true);
  assert.equal(nodes["done-title"].textContent, "✓ Set up: one step left in the chat");
  const watched = calls.filter((c) => c.method === "HandoffStatus").slice(2).map((c) => c.body.ticket);
  assert.deepEqual(watched, [SETUP_TICKET, `${SETUP_TICKET}1`, `${SETUP_TICKET}2`]);
  assert.equal(nodes["done-pickup"].className, "check ok");
  assert.equal(nodes["pickup-text"].textContent, "Your bot picked up the address of Supabase project abcdwxyzqrst, database postgres. It will ask you in the chat to confirm this database.");
  assert.equal(nodes["chat-text"].textContent, "familite-bot will ask you to confirm the database and show this passkey code:");
  assert.equal(nodes["check-code"].textContent, BASE_POINT_CODE);
  assert.equal(nodes["check-code"].hidden, false);
  assert.equal(nodes["check-problem"].hidden, true);
  assert.equal(nodes.waitlist.hidden, false);

  // The connection string is in two request bodies and nowhere else; the
  // tickets never reach the page.
  assert.deepEqual(calls.filter((c) => c.raw.includes("Marker-7f3a9c")).map((c) => c.method), ["CheckSetup", "RunSetup"]);
  for (const c of calls) assert.ok(!c.url.includes("Marker"));
  const all = everything(nodes);
  assert.doesNotMatch(all, /Marker-7f3a9c/);
  assert.doesNotMatch(all, /ticket/i);
  assert.doesNotMatch(all, /\bconnected\b/i);
  assert.equal(e.location.hash, `#${CODE}`, "the address is not changed");
});

test("a bot that can't reach the database: the reason's advice, and another string from scratch", async () => {
  const nodes = fakeDocument();
  const { calls, fetchFn, methods } = service({
    DescribeSetup: () => ({ body: { summary: connectOnly(), challenge: challenge() } }),
    CheckSetup: () => ({ body: connectOnlyCheck() }),
    HandoffStatus: () => ({ body: { state: "COLLECTED", phase: "PREVIEW", reach: { result: "UNREACHABLE", reason: "TLS_NOT_VERIFIED" } } }),
  });
  const { flow } = await toPaste(nodes, env(fetchFn));
  await paste(nodes);
  assert.equal(shown(nodes), "s-unreach");
  assert.equal(nodes["unreach-title"].textContent, "familite-bot can't reach this database");
  assert.match(nodes["unreach-text"].textContent, /certificate could not be verified from familite-bot's server/);
  await nodes["paste-again"].click();
  assert.equal(shown(nodes), "s-paste");
  assert.equal(flow.holdsConnectionString, false);
  assert.equal(flow.holdsTicket, false);
  assert.equal(nodes["paste-error"].hidden, true);
  assert.equal(calls.length, 3);
  assert.deepEqual(methods(), ["DescribeSetup", "CheckSetup", "HandoffStatus"]);
});

test("no report within a minute: OfferAddress once, then retry or go on anyway", async () => {
  const nodes = fakeDocument();
  const { calls, fetchFn, methods } = service({
    DescribeSetup: () => ({ body: { summary: connectOnly(), challenge: challenge() } }),
    CheckSetup: () => ({ body: connectOnlyCheck() }),
    HandoffStatus: () => ({ body: { state: "UNKNOWN" } }),
    OfferAddress: () => ({ body: { state: "HELD" } }),
  });
  const e = env(fetchFn);
  await toPaste(nodes, e);
  await paste(nodes);
  assert.equal(shown(nodes), "s-checking");
  assert.equal(nodes.nocheck.hidden, false);
  assert.equal(nodes["nocheck-text"].textContent, 'Couldn\'t check whether familite-bot can reach it. Tell familite-bot "check your status" in the chat, then retry.');
  assert.equal(methods().filter((m) => m === "OfferAddress").length, 1, "once per check");
  assert.equal(e.clock.t, 60000, "a minute");
  await nodes["retry-reach"].click();
  assert.equal(methods().filter((m) => m === "OfferAddress").length, 2, "once more for the retry");
  assert.equal(methods().filter((m) => m === "CheckSetup").length, 1, "the ticket is still there");
  await nodes["go-on"].click();
  assert.equal(shown(nodes), "s-tables");
  assert.equal(nodes["db-reach"].hidden, true);
  for (const c of calls.filter((x) => x.method !== "CheckSetup")) assert.doesNotMatch(c.raw, /Marker/);
});

test("no preview ticket (the service's caps): couldn't check at once, and Retry asks CheckSetup again", async () => {
  const nodes = fakeDocument();
  let checks = 0;
  const { fetchFn, methods } = service({
    DescribeSetup: () => ({ body: { summary: connectOnly(), challenge: challenge() } }),
    CheckSetup: () => ({ body: connectOnlyCheck({ ticket: ++checks === 1 ? "" : PREVIEW_TICKET }) }),
    HandoffStatus: () => ({ body: { state: "HELD", phase: "PREVIEW", reach: { result: "REACHABLE" } } }),
  });
  const { flow } = await toPaste(nodes, env(fetchFn));
  await paste(nodes);
  assert.equal(nodes.nocheck.hidden, false);
  assert.deepEqual(methods(), ["DescribeSetup", "CheckSetup"]);
  await nodes["retry-reach"].click();
  assert.deepEqual(methods(), ["DescribeSetup", "CheckSetup", "CheckSetup", "HandoffStatus"]);
  assert.equal(shown(nodes), "s-tables");
  assert.equal(flow.holdsConnectionString, true);
});

test("a refused string: the message with the connect-only way, the string dropped and the box hidden again", async () => {
  const nodes = fakeDocument();
  let checks = 0;
  const { fetchFn } = service({
    DescribeSetup: () => ({ body: { summary: connectOnly(), challenge: challenge() } }),
    CheckSetup: () => (++checks === 1
      ? { status: 400, body: refusalBody("failed_precondition", "LOGIN_FAILED", "The database refused the login.") }
      : { body: connectOnlyCheck({ ticket: "" }) }),
  });
  const { flow } = await toPaste(nodes, env(fetchFn));
  await nodes.reveal.click();
  await paste(nodes);
  assert.equal(shown(nodes), "s-paste");
  assert.equal(nodes["paste-error"].textContent, "The database refused the login.\nOr ask your bot for a new setup code made with --database-url.");
  assert.equal(nodes["database-url"].type, "password", "hidden again after a refusal");
  assert.equal(flow.holdsConnectionString, false);
  assert.doesNotMatch(everything(nodes), /Marker-7f3a9c/);
});

test("a code with a target: no reach check, the code's tables without ticks, and 'done' in the chat", async () => {
  guardStorage();
  const nodes = fakeDocument();
  const { calls, fetchFn, methods } = service({
    DescribeSetup: () => ({ body: { summary: summary("INSTALL"), challenge: challenge() } }),
    CheckSetup: () => ({
      body: {
        questions: [{ kind: "ROW_LEVEL_SECURITY", table: "public.leads", text: "q", choices: ["ALL_ROWS", "NONE"] }],
        passkeyNeeded: true,
        notes: ["Statement timeout now in force: 5000 ms."],
        database: { host: "db.example.com", port: 5432, database: "app" },
      },
    }),
    RunSetup: () => ({ body: { warnings: ["row-level security still hides public.notes"], passkeys: [{ credentialId: CRED_ID, checkCode: BASE_POINT_CODE }] } }),
  });
  await toPaste(nodes, env(fetchFn));
  assert.match(nodes.disclosure.textContent, /^Your database password goes to Basalt Vault's connect service for this one setup and is never stored\.$/);
  await paste(nodes);
  assert.equal(shown(nodes), "s-tables");
  assert.equal(nodes["db-name"].textContent, "db.example.com");
  assert.equal(nodes["db-sub"].textContent, "Port 5432 · database app");
  assert.equal([...nodes.tables.walk()].filter((n) => n.tagName === "INPUT").length, 0, "no ticks");
  assert.match(nodes.tables.textContent, /leads/);
  assert.match(nodes.tables.textContent, /notesread only/);
  assert.match(nodes.notes.textContent, /Statement timeout/);
  await nodes["tables-next"].click();
  assert.equal(shown(nodes), "s-approve", "no columns, no labels step");
  await nodes.approve.click();
  const run = calls.at(-1).body;
  assert.equal(run.includedTables, undefined);
  assert.equal(run.columnClasses, undefined);
  assert.deepEqual(run.answers, [{ kind: "ROW_LEVEL_SECURITY", table: "public.leads", choice: "ALL_ROWS" }]);
  assert.equal(shown(nodes), "s-done");
  assert.ok(!methods().includes("HandoffStatus"));
  assert.equal(nodes["done-pickup"].hidden, true);
  assert.equal(nodes["chat-text"].textContent, 'Tell familite-bot "done" so it checks now. It names this passkey code when it picks up the setup:');
  assert.match(nodes.warnings.textContent, /still hides/);
});

test("a later code signs with the existing passkey; approve makes one first when the database has none", async () => {
  const nodes = fakeDocument();
  const { calls, fetchFn } = service({
    DescribeSetup: () => ({ body: { summary: summary("AGENT"), challenge: challenge() } }),
    CheckSetup: () => ({ body: { passkeyNeeded: true } }),
    RunSetup: () => ({ body: { passkeys: [{ credentialId: CRED_ID, checkCode: BASE_POINT_CODE }] } }),
  });
  const creds = credentials();
  const { ready } = start(env(fetchFn, creds));
  await ready;
  assert.equal(nodes["bot-wants"].textContent, "wants to change its access to your database");
  await nodes["same-code"].click();
  assert.equal(nodes["passkey-go"].textContent, "Sign with your passkey");
  assert.equal(nodes["passkey-existing"].hidden, true);
  await nodes["passkey-go"].click();
  assert.equal(creds.log[0].op, "get");
  assert.equal(creds.log[0].opts.publicKey.rpId, "basaltvault.app");
  await paste(nodes);
  await nodes["tables-next"].click();
  await nodes.approve.click();
  assert.equal(creds.log[1].op, "create", "the database has no passkey: one is made at approval");
  assert.equal(calls.at(-1).method, "RunSetup");
  assert.equal(calls.at(-1).body.passkey.credentialId, CRED_ID);
  assert.equal(nodes["check-code"].textContent, BASE_POINT_CODE);
});

test("an INSTALL may use the passkey the database has, and cannot skip one", async () => {
  const nodes = fakeDocument();
  const { calls, fetchFn } = service({
    DescribeSetup: () => ({ body: { summary: summary("INSTALL"), challenge: challenge() } }),
    CheckSetup: () => ({ body: { passkeyNeeded: false } }),
    RunSetup: () => ({ body: {} }),
  });
  const creds = credentials();
  creds.create = async () => {
    throw Object.assign(new Error("cancelled"), { name: "NotAllowedError" });
  };
  const { flow, ready } = start(env(fetchFn, creds));
  await ready;
  await nodes["same-code"].click();
  await nodes["passkey-go"].click();
  assert.equal(shown(nodes), "s-passkey");
  assert.equal(nodes["passkey-skip"].hidden, true);
  assert.throws(() => flow.skipSign(), /not at the passkey step/);
  await nodes["passkey-use"].click();
  assert.equal(creds.log[0].op, "get");
  assert.equal(shown(nodes), "s-paste");
  await paste(nodes);
  await nodes["tables-next"].click();
  await nodes.approve.click();
  assert.equal(calls.at(-1).body.passkey, undefined, "nothing of the signature is sent");
  assert.equal(nodes["check-code"].hidden, true);
  assert.equal(nodes["check-problem"].hidden, true);
});

test("an upgrade without a passkey on this device goes on after a warning; nothing to do", async () => {
  const nodes = fakeDocument();
  const { calls, fetchFn } = service({
    DescribeSetup: () => ({ body: { summary: { ...summary("UPGRADE"), write: [], read: [] }, challenge: challenge() } }),
    CheckSetup: () => ({ body: { notes: ["nothing to upgrade"], nothingToDo: true } }),
    RunSetup: () => ({ body: { nothingToDo: true } }),
  });
  const creds = credentials();
  creds.get = async () => {
    throw Object.assign(new Error("cancelled"), { name: "NotAllowedError" });
  };
  const { ready } = start(env(fetchFn, creds));
  await ready;
  assert.equal(nodes["bot-name"].textContent, "Your bot");
  await nodes["same-code"].click();
  await nodes["passkey-go"].click();
  assert.equal(shown(nodes), "s-passkey", "a failed sign does not open the paste box");
  assert.equal(nodes["passkey-skip"].hidden, false);
  nodes["passkey-skip"].click();
  assert.equal(shown(nodes), "s-paste");
  assert.match(nodes["paste-error"].textContent, /may not be the real site/);
  await paste(nodes);
  assert.equal(nodes["tables-box"].hidden, true);
  await nodes["tables-next"].click();
  assert.equal(nodes["ap-limits"].hidden, true);
  await nodes.approve.click();
  assert.equal(calls.at(-1).body.passkey, undefined);
  assert.match(nodes["done-title"].textContent, /Nothing to do/);
});

test("a different code stops the page", async () => {
  const nodes = fakeDocument();
  const { fetchFn, methods } = service({ DescribeSetup: () => ({ body: { summary: connectOnly(), challenge: challenge() } }) });
  const { flow, ready } = start(env(fetchFn));
  await ready;
  await nodes["different-code"].click();
  assert.equal(shown(nodes), "s-stop");
  assert.equal(nodes.back.hidden, true);
  assert.equal(flow.step, "stopped");
  assert.throws(() => flow.confirmBot());
  assert.deepEqual(methods(), ["DescribeSetup"]);
});

test("refusals of RunSetup send the person back to paste, with what changed", async () => {
  const nodes = fakeDocument();
  let runs = 0;
  const { flow } = await (async () => {
    const svc = service({
      DescribeSetup: () => ({ body: { summary: connectOnly(), challenge: challenge() } }),
      CheckSetup: () => ({ body: connectOnlyCheck({ ticket: "", columns: [] }) }),
      RunSetup: () => (++runs === 1
        ? { status: 400, body: refusalBody("failed_precondition", "TABLES_CHANGED", "The tables changed since they were listed. Nothing changed.") }
        : { status: 400, body: refusalBody("failed_precondition", "SETUP_FAILED", "The admin role lacks a privilege. Nothing changed.") }),
    });
    return toPaste(nodes, env(svc.fetchFn));
  })();
  for (const want of [/Paste the connection string again to see the tables as they are now/, /lacks a privilege[\s\S]*Paste the connection string again to retry/]) {
    await paste(nodes);
    await nodes["go-on"].click();
    await nodes["tables-next"].click();
    await nodes.approve.click();
    assert.equal(shown(nodes), "s-paste");
    assert.match(nodes["paste-error"].textContent, want);
    assert.equal(flow.holdsConnectionString, false);
  }
  assert.doesNotMatch(everything(nodes), /Marker-7f3a9c/);
});

test("an expired challenge or a refused passkey sends the person back to the link", async () => {
  for (const reason of ["CHALLENGE_EXPIRED", "PASSKEY_INVALID"]) {
    const nodes = fakeDocument();
    const { calls, fetchFn } = service({
      DescribeSetup: () => ({ body: { summary: summary("INSTALL"), challenge: challenge() } }),
      CheckSetup: () => ({ body: {} }),
      RunSetup: () => ({ status: 400, body: refusalBody("invalid_argument", reason, "Refused.") }),
    });
    const { flow } = await toPaste(nodes, env(fetchFn));
    await paste(nodes);
    await nodes["tables-next"].click();
    await nodes.approve.click();
    assert.equal(nodes.error.hidden, false);
    assert.match(nodes["error-text"].textContent, /Open the link from your bot again/);
    assert.equal(nodes["s-paste"].hidden, true, "no retry with the same registration");
    assert.equal(calls.filter((c) => c.method === "RunSetup").length, 1);
    assert.equal(flow.holdsConnectionString, false);
  }
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
  const { flow } = await toPaste(nodes, env(fetchFn));
  await paste(nodes);
  await nodes["tables-next"].click();
  await nodes.approve.click();
  assert.match(nodes["error-text"].textContent, /cannot tell whether the setup ran/);
  assert.equal(nodes["error-check-code"].textContent, BASE_POINT_CODE);
  assert.equal(nodes["error-code"].hidden, false);
  assert.equal(nodes["s-done"].hidden, true, "no result, no waitlist");
  assert.equal(flow.holdsConnectionString, false);
  assert.doesNotMatch(everything(nodes), /Marker-7f3a9c/);
});

test("a setup that already ran: no ticks, no labels, nothing of the choices sent, no check code", async () => {
  const nodes = fakeDocument();
  const { calls, fetchFn } = service({
    DescribeSetup: () => ({ body: { summary: connectOnly(), challenge: challenge() } }),
    CheckSetup: () => ({ body: { database: SUPABASE, alreadyRan: true } }),
    RunSetup: () => ({ body: { ticket: SETUP_TICKET, reconnected: true } }),
    HandoffStatus: () => ({ body: { state: "COLLECTED", phase: "SET_UP" } }),
  });
  await toPaste(nodes, env(fetchFn));
  await paste(nodes);
  assert.equal(shown(nodes), "s-tables", "no reach check on a re-run");
  assert.equal(nodes["already-ran"].hidden, false);
  assert.equal(nodes["tables-box"].hidden, true);
  await nodes["tables-next"].click();
  assert.equal(shown(nodes), "s-approve");
  assert.equal(nodes["ap-counts"].hidden, true);
  await nodes.approve.click();
  const run = calls.find((c) => c.method === "RunSetup").body;
  assert.deepEqual(Object.keys(run).sort(), ["answers", "code", "databaseUrl"]);
  assert.equal(nodes.reconnected.hidden, false);
  assert.equal(nodes["check-code"].hidden, true);
  assert.equal(nodes["check-problem"].hidden, true, "a re-run registers no passkey: nothing to compare");
  assert.equal(nodes["chat-text"].textContent, "familite-bot will ask you to confirm the database.");
});

test("a pick-up that takes over 2 minutes says to tell the bot", async () => {
  const nodes = fakeDocument();
  const { fetchFn } = service({
    DescribeSetup: () => ({ body: { summary: connectOnly(), challenge: challenge() } }),
    CheckSetup: () => ({ body: connectOnlyCheck({ ticket: "", columns: [] }) }),
    RunSetup: () => ({ body: { ticket: SETUP_TICKET } }),
    HandoffStatus: () => ({ body: { state: "HELD", phase: "SET_UP" } }),
  });
  const e = env(fetchFn);
  await toPaste(nodes, e);
  await paste(nodes);
  await nodes["go-on"].click();
  await nodes["tables-next"].click();
  await nodes.approve.click();
  assert.ok(e.clock.t >= LATE_MS);
  assert.equal(nodes["pickup-text"].textContent, "Your bot hasn't picked it up yet. Tell it to check its status.");
  assert.equal(nodes["done-pickup"].className, "check wait");
});

test("Back keeps the person's ticks and labels, and back to the paste step drops the string", async () => {
  const nodes = fakeDocument();
  const { fetchFn } = service({
    DescribeSetup: () => ({ body: { summary: connectOnly(), challenge: challenge() } }),
    CheckSetup: () => ({ body: connectOnlyCheck({ ticket: "" }) }),
  });
  const { flow } = await toPaste(nodes, env(fetchFn));
  await paste(nodes);
  await nodes["go-on"].click();
  const pay = [...nodes.tables.walk()].find((n) => n.tagName === "INPUT" && n.value === "public.payments");
  pay.checked = false;
  pay.fire("change");
  await nodes["tables-next"].click();
  const email = find(nodes["label-tables"], (n) => n.tagName === "SELECT" && n.getAttribute("aria-label") === "Label for users.email");
  email.value = "SECRET";
  email.fire("change");
  await nodes["labels-next"].click();
  assert.equal(nodes["ap-counts"].textContent, "2 tables · 1 column marked");
  await nodes.back.click();
  assert.equal(shown(nodes), "s-labels");
  assert.equal(find(nodes["label-tables"], (n) => n.tagName === "SELECT" && n.getAttribute("aria-label") === "Label for users.email").value, "SECRET");
  await nodes.back.click();
  assert.equal(shown(nodes), "s-tables");
  assert.equal(nodes["tables-count"].textContent, "2 of 3");
  await nodes.back.click();
  assert.equal(shown(nodes), "s-paste");
  assert.equal(flow.holdsConnectionString, false);
  await nodes.back.click();
  assert.equal(shown(nodes), "s-passkey");
  assert.equal(nodes["passkey-go"].textContent, "Continue");
});

test("without a code in the link, the paste box reads one; a bad code shows the refusal", async () => {
  const nodes = fakeDocument();
  let describes = 0;
  const { calls, fetchFn } = service({
    DescribeSetup: () => (++describes === 1
      ? { status: 400, body: refusalBody("invalid_argument", "DAMAGED", "This setup code is damaged; copy it again.") }
      : { body: { summary: summary("INSTALL"), challenge: challenge() } }),
  });
  const { ready } = start(env(fetchFn, credentials(), ""));
  await ready;
  assert.equal(calls.length, 0);
  assert.equal(shown(nodes), "s-code");
  nodes["code-paste"].value = "no code here";
  await nodes["code-read"].click();
  assert.equal(calls.length, 0);
  assert.match(nodes["code-status"].textContent, /No setup code found/);
  nodes["code-paste"].value = `Here it is: ${CODE}`;
  await nodes["code-read"].click();
  assert.match(nodes["code-status"].textContent, /damaged; copy it again/);
  assert.equal(shown(nodes), "s-code");
  nodes["code-paste"].value = CODE;
  await nodes["code-read"].click();
  assert.equal(shown(nodes), "s-bot");
  assert.deepEqual(calls.map((c) => c.body), [{ code: CODE }, { code: CODE }]);
});
