// Runs with `node --test web/lib/*.test.mjs` (make web-check). The local
// setup page: it runs only on the engine's own local origin, reads its job
// from the link's fragment, and posts the job with the admin connection
// string only to the engine's own setup routes.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { b64urlEncode, utf8 } from "./codec.js";
import { Labels, restNote } from "./picks.js";
// Imported before any document exists, so the page's main() does not run.
import { agentProbe, answerFits, CHECK_PATH, CHOICES, DOCTOR_PATH, doneText, Install, labelFields, startUpdate, UpdateCheck, JOB_TEXT, JOBS, labelWords, localOrigin, parseSetupLink, pickJob, postSetup, RUN_PATH, removeConfirmed, REMOVE_LAST_STEP, ENGINE_PATH, NOT_MINE_PATH, SetupError, setupRequest, startReal, suggestionOf } from "./setup.js";

const link = (job) => "#1." + b64urlEncode(utf8(JSON.stringify(job)));
const job = { job: "INSTALL", agent: "demo_bot", osUser: "alice", demo: true };

test("the page asks for nothing outside the engine's own local origin", () => {
  assert.equal(localOrigin({ protocol: "http:", hostname: "localhost", port: "8787" }), "http://localhost:8787");
  for (const loc of [
    { protocol: "https:", hostname: "portal.basaltvault.app", port: "" },
    { protocol: "http:", hostname: "127.0.0.1", port: "8787" },
    { protocol: "http:", hostname: "localhost", port: "" },
    { protocol: "https:", hostname: "localhost", port: "8787" },
  ]) {
    assert.throws(() => localOrigin(loc), /runs only on this computer's own engine/, JSON.stringify(loc));
  }
});

// The link basalt init prints (internal/setup/in/localsetup.Link) parses to its job.
const vector = JSON.parse(readFileSync(new URL("../../internal/setup/in/localsetup/testdata/link.json", import.meta.url), "utf8"));

test("the page reads the link basalt init prints", () => {
  const url = new URL(vector.link);
  assert.equal(url.origin, vector.origin);
  assert.equal(url.pathname, "/setup/");
  assert.deepEqual(parseSetupLink(url.hash), vector.job);
});

test("the link carries the job, the agent, its OS user and demo, and nothing else", () => {
  assert.deepEqual(parseSetupLink(link(job)), job);
  for (const bad of [
    "",
    "#",
    "#2." + link(job).slice(3),
    link({ ...job, databaseUrl: "x" }),
    link({ ...job, job: "REPAIR" }),
    link({ ...job, job: "REMOVE", demo: true }),
    link({ ...job, job: "UPDATE", demo: true }),
    link({ ...job, agent: "Bad-Name" }),
    link({ ...job, osUser: "a b" }),
    link({ ...job, demo: "yes" }),
    "#1.not-json",
  ]) {
    assert.throws(() => parseSetupLink(bad), undefined, bad);
  }
});

test("a check and a run post the job with the string to the setup routes only", async () => {
  const calls = [];
  const fetchFn = async (path, init) => {
    calls.push({ path, init });
    return { ok: true, status: 200, json: async () => ({ database: "app" }) };
  };
  const body = setupRequest(job, "postgres://u@h/d");
  assert.deepEqual(await postSetup(fetchFn, CHECK_PATH, body), { database: "app" });
  await postSetup(fetchFn, RUN_PATH, setupRequest(job, "postgres://u@h/d", { passkey: { credentialId: "x" } }));
  assert.deepEqual(calls.map((c) => c.path), ["/api/v1/setup/check", "/api/v1/setup/run"]);
  assert.equal(calls[0].init.method, "POST");
  assert.equal(calls[0].init.headers["Content-Type"], "application/json");
  assert.equal(calls[0].init.credentials, "omit");
  assert.deepEqual(JSON.parse(calls[0].init.body), { ...job, databaseUrl: "postgres://u@h/d" });
  assert.deepEqual(JSON.parse(calls[1].init.body).passkey, { credentialId: "x" });
});

test("a refusal comes back with its code and the engine's fixed message", async () => {
  const fetchFn = async () => ({ ok: false, status: 409, json: async () => ({ code: "ROLE_EXISTS", message: "The database already has the role." }) });
  await assert.rejects(postSetup(fetchFn, CHECK_PATH, {}), (err) => err.status === 409 && err.code === "ROLE_EXISTS" && /already has the role/.test(err.message));
  const down = async () => {
    throw new TypeError("network");
  };
  await assert.rejects(postSetup(down, CHECK_PATH, {}), /did not answer/);
});

test("the link may name an update or a removal of the agent, never with the sample database", () => {
  for (const name of ["UPDATE", "REMOVE", "CHANGE"]) {
    const j = { ...job, job: name, demo: false };
    assert.deepEqual(parseSetupLink(link(j)), j);
    assert.deepEqual(setupRequest(j, "postgres://u@h/d"), { ...j, databaseUrl: "postgres://u@h/d" });
  }
});

test("every job has its own fixed words, which name the agent", () => {
  assert.match(JOB_TEXT.CHANGE.intro("demo_bot"), /demo_bot/);
  for (const name of JOBS.filter((j) => j !== "CHANGE")) {
    const t = JOB_TEXT[name];
    assert.ok(t.title && t.run, name);
    assert.match(t.intro("demo_bot"), /demo_bot/, name);
    assert.match(t.done("demo_bot"), /demo_bot/, name);
  }
  assert.match(JOB_TEXT.REMOVE.intro("a"), /Nothing can undo it/);
});

test("a CHANGE link runs only the job the person picks, and never sends CHANGE", () => {
  const change = parseSetupLink(link({ ...job, job: "CHANGE", demo: false }));
  assert.equal(pickJob(change, ""), null, "nothing runs before a pick");
  assert.equal(pickJob(change, "INSTALL"), null, "only UPDATE or REMOVE");
  assert.deepEqual(CHOICES, ["UPDATE", "REMOVE"]);
  for (const name of CHOICES) {
    assert.deepEqual(setupRequest(pickJob(change, name), "postgres://u@h/d").job, name);
  }
  assert.throws(() => parseSetupLink(link({ ...job, job: "CHANGE", demo: true })));
  const install = parseSetupLink(link(job));
  assert.equal(pickJob(install, "REMOVE"), install, "an install link keeps its own job");
});

test("a check answer for an earlier pick is dropped", () => {
  const change = parseSetupLink(link({ ...job, job: "CHANGE", demo: false }));
  const update = pickJob(change, "UPDATE");
  const remove = pickJob(change, "REMOVE");
  assert.ok(answerFits(update, update));
  assert.ok(!answerFits(update, remove), "the person switched to Remove while Update was checked");
  assert.ok(!answerFits(null, update));
});

test("the agent is checked before the admin string is asked for", async () => {
  const calls = [];
  const answering = (code, message) => async (path, init) => {
    calls.push({ path, body: JSON.parse(init.body) });
    return { ok: false, status: code === "CONNECTION_STRING_REFUSED" ? 400 : 400, json: async () => ({ code, message }) };
  };
  const change = parseSetupLink(link({ ...job, job: "CHANGE", demo: false }));
  assert.equal(await agentProbe(answering("CONNECTION_STRING_REFUSED", "x"), change), null);
  assert.deepEqual(calls[0], { path: CHECK_PATH, body: { ...change, job: "UPDATE", databaseUrl: "" } }, "a CHANGE link probes as UPDATE, with no admin string");
  const msg = await agentProbe(answering("INVALID_ARGUMENT", "This engine has no agent demo_bot. Ask the agent to run basalt init --agent NAME"), change);
  assert.match(msg, /basalt init --agent NAME/);
  calls.length = 0;
  assert.equal(await agentProbe(answering("INVALID_ARGUMENT", "x"), job), null, "an install link needs no probe");
  assert.equal(calls.length, 0);
});

// ---- The install of a real database ----

const real = { job: "INSTALL", agent: "bot", osUser: "alice", demo: false };
// Split so no whole admin string with a password sits in the source.
const ADMIN = "postgres://admin" + ":" + "pw@db.example.com/app";
const FP = "ab".repeat(32);
const challenge = { challenge: "Y2g", userId: "dQ", userName: "bot", displayName: "bot", expiresAt: "2030-01-01T00:00:00Z", mac: "bWFj" };

const listing = {
  database: "app",
  host: "db.example.com",
  port: 5432,
  sessionUser: "admin",
  certificate: { kind: "PUBLIC", issuer: "ISRG Root X1" },
  lines: [],
  tables: [{ table: "public.orders", canWrite: true }, { table: "public.logs", canWrite: false }, { table: "sales.leads", canWrite: true }],
  excluded: [{ table: "public.Mixed", owner: "unsupported name" }],
  notes: [],
  passkeyNeeded: true,
  questions: [],
  sql: "",
};

const columns = [
  { table: "public.orders", column: "email", dataType: "text", class: "UNCLASSIFIED", suggestedClass: "IDENTIFIER", suggestedEntityType: "EMAIL", reason: "NAME:email" },
  { table: "public.orders", column: "note", dataType: "text", class: "UNCLASSIFIED" },
  { table: "public.logs", column: "line", dataType: "text", class: "UNCLASSIFIED" },
];

// fakeEngine answers the listing for a check without tables, a full
// check (with the columns and a challenge) for one with tables, and a run.
// It records every body; hold() keeps the next answer until release().
function fakeEngine(over = {}) {
  const bodies = [];
  let held = null;
  const fetchFn = async (path, init) => {
    const body = JSON.parse(init.body);
    bodies.push({ path, body });
    if (held) await held.promise;
    const answer = over.answer?.(path, body);
    if (answer) return answer;
    if (path === RUN_PATH) return new Response(JSON.stringify({ agent: "bot", lines: ["agent bot ready"], warnings: [], passkeys: [], mcpCommand: "basalt mcp --agent bot" }), { status: 200 });
    if (!body.tables) return new Response(JSON.stringify(listing), { status: 200 });
    const questions = body.tables.some((t) => t.table === "sales.leads") ? [{ kind: "ROW_LEVEL_SECURITY", table: "sales.leads", text: "?", choices: ["ALL_ROWS", "NONE"] }] : [];
    return new Response(JSON.stringify({ database: "app", lines: ["the guard"], sql: "GRANT …", questions, notes: [], passkeyNeeded: true, challenge, columns: columns.filter((c) => body.tables.some((t) => t.table === c.table)) }), { status: 200 });
  };
  return {
    fetchFn,
    bodies,
    hold() {
      let release;
      held = { promise: new Promise((r) => { release = r; }) };
      return () => { const h = held; held = null; release(); return h; };
    },
  };
}

test("a real install lists the tables, ticks each with write access where it can have it, and checks the picks", async () => {
  const e = fakeEngine();
  const i = new Install(e.fetchFn, real);
  const l = await i.list(ADMIN);
  assert.deepEqual(e.bodies[0].body, { ...real, databaseUrl: ADMIN }, "the listing check sends no tables");
  assert.deepEqual(l.excluded, [{ table: "public.Mixed", owner: "unsupported name" }]);
  assert.deepEqual([...i.picks], [["public.orders", "WRITE"], ["public.logs", "READ"], ["sales.leads", "WRITE"]]);

  i.setAccess("public.logs", "WRITE");
  assert.equal(i.picks.get("public.logs"), "READ", "a table without a primary key is read only");
  i.setAccess("public.orders", "READ");
  i.tick("sales.leads", false);
  i.tick("public.nothing", true);
  assert.deepEqual(i.picked(), ["public.orders", "public.logs"]);

  const v = await i.check();
  assert.deepEqual(e.bodies[1].body.tables, [{ table: "public.orders", access: "READ" }, { table: "public.logs", access: "READ" }]);
  assert.equal(e.bodies[1].body.columnClasses, undefined, "no labels until the person sets one");
  assert.deepEqual(v.tables.map((t) => [t.name, t.access]), [["orders", "READ"], ["logs", "READ"]]);
  assert.equal(v.sql, "GRANT …");
});

test("no table ticked: nothing is sent", async () => {
  const e = fakeEngine();
  const i = new Install(e.fetchFn, real);
  await i.list(ADMIN);
  for (const t of i.picked()) i.tick(t, false);
  await assert.rejects(i.check(), (err) => err.code === "NO_TABLES");
  assert.equal(e.bodies.length, 1);
});

test("the run sends exactly the checked request, its challenge and ALL_ROWS to each question", async () => {
  const e = fakeEngine();
  const i = new Install(e.fetchFn, real);
  await i.list(ADMIN);
  await i.check();
  let asked = null;
  const done = await i.run(async (c) => { asked = c; return { credentialId: "aWQ" }; });
  assert.deepEqual(asked, challenge, "the passkey is made with the check's challenge");
  const checkBody = e.bodies[1].body;
  const runBody = e.bodies[2].body;
  assert.equal(e.bodies[2].path, RUN_PATH);
  assert.deepEqual(runBody, { ...checkBody, answers: [{ table: "sales.leads", choice: "ALL_ROWS" }], challenge, passkey: { credentialId: "aWQ" } });
  assert.equal(done.mcpCommand, "basalt mcp --agent bot");
  assert.equal(i.checked, null, "the admin string and the check are dropped after the run");
});

test("the challenge goes with every real-install run, with or without a passkey", async () => {
  const e = fakeEngine({ answer: (path, body) => body.tables && path === CHECK_PATH ? new Response(JSON.stringify({ database: "app", lines: [], sql: "", questions: [], notes: [], passkeyNeeded: false, challenge }), { status: 200 }) : null });
  const i = new Install(e.fetchFn, real);
  await i.list(ADMIN);
  await i.check();
  await i.run(async () => assert.fail("no passkey is made when the database has one"));
  assert.deepEqual(e.bodies[2].body.challenge, challenge);
  assert.equal(e.bodies[2].body.passkey, undefined);
});

test("any change after the check drops it: the run needs a new check", async () => {
  for (const change of [
    (i) => i.tick("public.logs", false),
    (i) => i.setAccess("public.orders", "READ"),
    (i) => i.setLabel("public.orders", "note", { class: "SECRET" }),
    (i) => i.setLabelMode("changes"),
  ]) {
    const e = fakeEngine();
    const i = new Install(e.fetchFn, real);
    await i.list(ADMIN);
    await i.check();
    change(i);
    assert.equal(i.view(), null, String(change));
    await assert.rejects(i.run(async () => ({})), /Check again/);
    assert.equal(e.bodies.filter((b) => b.path === RUN_PATH).length, 0);
  }
});

test("a check answer for an earlier state is dropped", async () => {
  const e = fakeEngine();
  const i = new Install(e.fetchFn, real);
  await i.list(ADMIN);
  const release = e.hold();
  const pending = i.check();
  i.tick("public.logs", false);
  release();
  assert.equal(await pending, null);
  assert.equal(i.checked, null, "the answer for the old picks is not kept");
  await i.check();
  assert.deepEqual(i.view().tables.map((t) => t.table), ["public.orders", "sales.leads"]);
});

test("a change while the passkey prompt is open stops the run", async () => {
  const e = fakeEngine();
  const i = new Install(e.fetchFn, real);
  await i.list(ADMIN);
  await i.check();
  await assert.rejects(i.run(async () => { i.tick("public.logs", false); return {}; }), /Check again/);
  assert.equal(e.bodies.filter((b) => b.path === RUN_PATH).length, 0);
});

test("labels: a suggestion is shown, never sent until accepted, and the checked labels are the ones run", async () => {
  const e = fakeEngine();
  const i = new Install(e.fetchFn, real);
  await i.list(ADMIN);
  i.tick("sales.leads", false);
  await i.check();
  const email = i.labels.columns.find((c) => c.column === "email");
  const s = suggestionOf(email);
  assert.deepEqual(s, { label: { class: "IDENTIFIER", entityType: "EMAIL", phoneRegion: "" }, reason: "NAME:email", words: "Personal: email" });
  assert.equal(suggestionOf(i.labels.columns.find((c) => c.column === "note")), null);

  i.setLabelMode("changes");
  await i.check();
  assert.equal(e.bodies.at(-1).body.columnClasses, undefined, "an unaccepted suggestion writes nothing");

  i.acceptSuggestion(email);
  assert.equal(i.view(), null);
  await i.check();
  const labeled = e.bodies.at(-1).body;
  assert.deepEqual(labeled.columnClasses, [{ table: "public.orders", column: "email", class: "IDENTIFIER", entityType: "EMAIL", was: { class: "UNCLASSIFIED" } }]);
  assert.equal(i.view().labeled, 1);
  await i.run(async () => ({}));
  assert.deepEqual(e.bodies.at(-1).body.columnClasses, labeled.columnClasses);

  // A new pick keeps the labels of the columns still listed.
  const j = new Install(fakeEngine().fetchFn, real);
  await j.list(ADMIN);
  await j.check();
  j.setLabel("public.orders", "note", { class: "SECRET" });
  j.tick("sales.leads", false);
  await j.check();
  assert.equal(j.labels.current({ table: "public.orders", column: "note" }).class, "SECRET");
});

test("labels: the rest as not personal, and as restPublic when the check listed only part of the columns", async () => {
  const e = fakeEngine();
  const i = new Install(e.fetchFn, real);
  await i.list(ADMIN);
  i.tick("sales.leads", false);
  await i.check();
  i.setLabelMode("rest");
  await i.check();
  assert.deepEqual(e.bodies.at(-1).body.columnClasses.map((c) => [c.column, c.class]), [["note", "PUBLIC"], ["line", "PUBLIC"]], "email, suggested as personal and not accepted, is left out");
  assert.deepEqual(i.restNote(), ["2 columns will be marked not personal.", "Not included, because they look personal:", "orders.email"]);
  assert.equal(i.view().labeled, 0, "the rest are not counted as the person's labels");
  assert.equal(i.view().restPublic, true);

  const more = fakeEngine({ answer: (path, body) => body.tables ? new Response(JSON.stringify({ database: "app", lines: [], sql: "", questions: [], notes: [], passkeyNeeded: true, challenge, columns, columnsMore: true }), { status: 200 }) : null });
  const j = new Install(more.fetchFn, real);
  await j.list(ADMIN);
  await j.check();
  j.setLabel("public.orders", "email", { class: "IDENTIFIER", entityType: "EMAIL" });
  j.setLabelMode("rest");
  await j.check();
  const body = more.bodies.at(-1).body;
  assert.equal(body.restPublic, true, "the columns the page never showed are covered only by restPublic");
  assert.deepEqual(j.restNote(), ["All unlabeled columns, the ones not listed here too, will be marked not personal."], "email is labeled, so nothing suggested is named");
  assert.deepEqual(body.columnClasses.map((c) => c.column), ["email"]);
  assert.equal(j.view().restPublic, true);
});

test("a certificate no authority signs: the page shows the fingerprint, and trusting it sends its SHA-256 with every call", async () => {
  const refusal = { code: "CERTIFICATE_NOT_VERIFIED", message: "The database's certificate is not signed by an authority this computer trusts.", trustRoot: { subject: "CN=Acme Root", sha256: FP, expiresAt: "2031-05-01T00:00:00Z" } };
  const e = fakeEngine({ answer: (path, body) => body.trustRoot ? null : new Response(JSON.stringify(refusal), { status: 409 }) });
  const i = new Install(e.fetchFn, real);
  await assert.rejects(i.list(ADMIN), (err) => err instanceof SetupError && err.code === "CERTIFICATE_NOT_VERIFIED");
  assert.deepEqual(i.asking, refusal.trustRoot);
  assert.deepEqual(i.stringFacts, { database: "app", host: "db.example.com", port: 5432, user: "admin" }, "what the string names, never its password");
  assert.equal(e.bodies.length, 1, "nothing is trusted until the person says yes");
  await i.trust();
  assert.equal(e.bodies[1].body.trustRoot, FP, "lowercase, as received");
  await i.check();
  await i.run(async () => ({}));
  assert.equal(e.bodies[2].body.trustRoot, FP);
  assert.equal(e.bodies[3].body.trustRoot, FP, "the run carries the trusted root it was checked with");
});

test("Cancel on the certificate drops the admin string; a new string trusts nothing", async () => {
  const refusal = { code: "CERTIFICATE_NOT_VERIFIED", message: "x", trustRoot: { subject: "CN=Acme Root", sha256: FP, expiresAt: "2031-05-01T00:00:00Z" } };
  const e = fakeEngine({ answer: (path, body) => body.trustRoot ? null : new Response(JSON.stringify(refusal), { status: 409 }) });
  const i = new Install(e.fetchFn, real);
  await assert.rejects(i.list(ADMIN));
  i.cancelTrust();
  assert.equal(i.asking, null);
  await assert.rejects(i.check());
  assert.equal(e.bodies.length, 1, "nothing more is sent after Cancel");

  const j = new Install(e.fetchFn, real);
  await assert.rejects(j.list(ADMIN));
  await j.trust();
  await assert.rejects(j.list("postgres://admin" + ":" + "pw@other.example.com/app"));
  assert.equal(j.trustRoot, "");
  assert.equal(e.bodies.at(-1).body.trustRoot, undefined);
});

test("a refusal's certificate is kept only when it reads as one", async () => {
  const bad = { code: "CERTIFICATE_NOT_VERIFIED", message: "x", trustRoot: { subject: "CN=x", sha256: "AB".repeat(32), expiresAt: "2031-05-01T00:00:00Z" } };
  const fetchFn = async () => new Response(JSON.stringify(bad), { status: 409 });
  await assert.rejects(postSetup(fetchFn, CHECK_PATH, {}), (err) => err.trustRoot === null);
  const other = { code: "LOGIN_FAILED", message: "x", trustRoot: { subject: "CN=x", sha256: FP, expiresAt: "2031-05-01T00:00:00Z" } };
  await assert.rejects(postSetup(async () => new Response(JSON.stringify(other), { status: 409 }), CHECK_PATH, {}), (err) => err.trustRoot === null);
});

test("labels are named with the connect page's words", () => {
  assert.equal(labelWords({ class: "IDENTIFIER", entityType: "PHONE", phoneRegion: "US" }), "Personal: phone (US)");
  assert.equal(labelWords({ class: "SECRET" }), "Secret");
  assert.equal(labelWords({ class: "PUBLIC" }), "Not personal");
  assert.equal(suggestionOf({ suggestedClass: "IDENTIFIER", suggestedEntityType: "bad type" }), null);
  assert.equal(suggestionOf({ suggestedClass: "UNCLASSIFIED" }), null);
  assert.throws(() => new Install(async () => {}, { ...real, demo: true }));
});

// ---- The real install's screens, on a fake document built from the page ----

const HTML = readFileSync(new URL("../setup/index.html", import.meta.url), "utf8");

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
    this.classList = { add: (c) => { this.className += ` ${c}`; } };
  }
  get textContent() {
    return this._text + this.children.map((c) => c.textContent).join("");
  }
  set textContent(v) {
    this.children = [];
    this._text = String(v);
  }
  appendChild(c) {
    this.children.push(c);
    return c;
  }
  replaceChildren(...c) {
    this.children = c;
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

const FLOW = (() => {
  const body = HTML.slice(HTML.indexOf("<body"));
  const out = new Map();
  for (const m of body.matchAll(/<([a-z0-9]+) id="([^"]+)"([^>]*)>/g)) out.set(m[2], { tag: m[1], hidden: /\shidden(\s|>|$)/.test(m[3] + ">") });
  return out;
})();

test("every element with an id on the setup page names it first, once", () => {
  const ids = [...HTML.matchAll(/\sid="([^"]+)"/g)].map((m) => m[1]);
  assert.deepEqual([...FLOW.keys()].sort(), [...new Set(ids)].sort());
  assert.equal(ids.length, new Set(ids).size, "no id twice");
});

function fakePage() {
  const nodes = {};
  for (const [id, { tag, hidden }] of FLOW) {
    nodes[id] = new Node(tag, id);
    nodes[id].hidden = hidden;
  }
  nodes.progress.children = Array.from({ length: 5 }, () => new Node("span"));
  nodes["paste-url"].type = "password";
  globalThis.document = {
    body: new Node("body"),
    getElementById: (id) => {
      assert.ok(nodes[id], `no element ${id}`);
      return nodes[id];
    },
    createElement: (tag) => new Node(tag),
  };
  return nodes;
}

const screenOf = (nodes) => {
  const on = [...FLOW.keys()].filter((id) => id.startsWith("s-") && !nodes[id].hidden);
  assert.equal(on.length, 1, `screens shown: ${on}`);
  return on[0];
};
const find = (root, pred) => {
  for (const n of root.walk()) if (pred(n)) return n;
  return null;
};
const settle = () => new Promise((r) => setImmediate(r));

async function toTables(nodes, e) {
  const install = startReal(real, { fetchFn: e.fetchFn, makePasskey: async () => ({ credentialId: "aWQ" }) });
  assert.equal(screenOf(nodes), "s-user");
  assert.equal(nodes["user-name"].textContent, "alice");
  assert.equal(nodes["user-next"].disabled, true, "the OS user is confirmed first");
  nodes["user-confirm"].checked = true;
  nodes["user-confirm"].fire("change");
  nodes["user-next"].click();
  assert.equal(screenOf(nodes), "s-paste");
  nodes["paste-url"].value = ADMIN;
  await nodes["paste-next"].click();
  assert.equal(nodes["paste-url"].value, "", "the box is emptied once read");
  // The confirm step, when the engine signed in: Yes goes on to the tables.
  if (screenOf(nodes) === "s-confirm" && nodes["confirm-details"].hidden) await nodes["confirm-go"].click();
  return install;
}

// facts are the confirm step's rows, as "label: value".
const facts = (nodes) => nodes["confirm-facts"].children.map((r) => r.children.map((c) => c.textContent).join(": "));

test("after the string, one confirm step: database, host, who it signs in as and the certificate", async () => {
  const nodes = fakePage();
  const e = fakeEngine();
  startReal(real, { fetchFn: e.fetchFn, makePasskey: async () => ({}) });
  nodes["user-confirm"].checked = true;
  nodes["user-confirm"].fire("change");
  nodes["user-next"].click();
  nodes["paste-url"].value = ADMIN;
  await nodes["paste-next"].click();
  assert.equal(screenOf(nodes), "s-confirm");
  assert.equal(nodes["confirm-title"].textContent, "Is this your database?");
  assert.equal(nodes["confirm-sub"].textContent, "Check these, then continue.");
  assert.deepEqual(facts(nodes), ["Database: app", "Host: db.example.com:5432", "Signed in as: admin", "Certificate: ✓ Verified by ISRG Root X1"]);
  assert.equal(nodes["confirm-details"].hidden, true, "no fingerprint to check for a public authority");
  assert.equal(nodes["confirm-go"].textContent, "Yes, this is it");
  assert.equal(nodes["confirm-back"].textContent, "No, go back");
  assert.ok(!JSON.stringify(facts(nodes)).includes("pw"), "never the password");
  assert.equal(e.bodies.length, 1);

  await nodes["confirm-back"].click();
  assert.equal(screenOf(nodes), "s-paste", "No, go back drops the string");
  assert.equal(e.bodies.length, 1, "and sends nothing");
  nodes["paste-url"].value = ADMIN;
  await nodes["paste-next"].click();
  await nodes["confirm-go"].click();
  assert.equal(screenOf(nodes), "s-tables");
  assert.ok(e.bodies.every((b) => b.body.trustRoot === undefined), "a public authority is never trusted by the page");
});

test("the setup page walks the connect page's steps: OS user, string, tables with access, labels, approve", async () => {
  const nodes = fakePage();
  const e = fakeEngine();
  const install = await toTables(nodes, e);
  assert.equal(screenOf(nodes), "s-tables");
  assert.equal(nodes["tables-count"].textContent, "3 of 3");
  assert.match(nodes.excluded.textContent, /Mixed \(a name BasaltDB cannot use\)/);
  const rows = nodes.tables.children;
  assert.match(rows[1].textContent, /logs.*read only \(no row ID\)/, "a table without a primary key has no switch");
  // Untick sales.leads, set orders to Read.
  const leads = find(rows[2], (n) => n.tagName === "INPUT");
  leads.checked = false;
  leads.fire("change");
  assert.equal(find(rows[2], (n) => n.value === "WRITE").disabled, true, "an unticked table's switch is off");
  find(rows[0], (n) => n.value === "READ").click();
  assert.equal(find(rows[0], (n) => n.value === "READ").getAttribute("aria-pressed"), "true");
  assert.equal(nodes["tables-count"].textContent, "2 of 3");

  await nodes["tables-next"].click();
  assert.equal(screenOf(nodes), "s-labels");
  const pick = find(nodes["label-tables"], (n) => n.tagName === "SELECT" && n.attrs["aria-label"] === "Label for orders.email");
  assert.equal(pick.value, "", "the suggestion is not chosen for the person");
  assert.ok(find(pick, (n) => n.textContent === "Personal: email (suggested)"));
  assert.ok(find(pick.parent ?? nodes["label-tables"], (n) => n.textContent === "Suggested: Personal: email"), "the suggestion is shown in the row");
  pick.value = "IDENTIFIER:EMAIL";
  pick.fire("change");
  assert.equal(install.view(), null, "a label drops the check");
  await nodes["labels-next"].click();
  assert.equal(screenOf(nodes), "s-approve");
  const checkBody = e.bodies.at(-1).body;
  assert.deepEqual(checkBody.columnClasses.map((c) => c.column), ["email"], "the labels were checked before the approval shows");
  assert.match(nodes["ap-facts"].textContent, /Reads: orders, logs/);
  assert.doesNotMatch(nodes["ap-facts"].textContent, /Changes rows in/);
  assert.match(nodes["ap-facts"].textContent, /Personal data: 1 column marked/);
  assert.equal(nodes["ap-sql"].textContent, "GRANT …");
  assert.equal(nodes.approve.textContent, "Set up with passkey");

  await nodes.approve.click();
  const run = e.bodies.at(-1);
  assert.equal(run.path, RUN_PATH);
  assert.deepEqual(run.body, { ...checkBody, challenge, passkey: { credentialId: "aWQ" } });
  assert.equal(nodes.done.hidden, false);
  assert.equal(nodes["mcp-command"].textContent, "basalt mcp --agent bot");
});

test("Back to the tables and a new access: the approval shows and runs the new check", async () => {
  const nodes = fakePage();
  const e = fakeEngine();
  await toTables(nodes, e);
  const leads = find(nodes.tables.children[2], (n) => n.tagName === "INPUT");
  leads.checked = false;
  leads.fire("change");
  await nodes["tables-next"].click();
  await nodes["labels-next"].click();
  assert.equal(screenOf(nodes), "s-approve");
  assert.match(nodes["ap-facts"].textContent, /Changes rows in: orders/);
  nodes.back.click();
  assert.equal(screenOf(nodes), "s-labels");
  nodes.back.click();
  find(nodes.tables.children[0], (n) => n.value === "READ").click();
  await nodes["tables-next"].click();
  await nodes["labels-next"].click();
  assert.match(nodes["ap-facts"].textContent, /Reads: orders, logs/);
  await nodes.approve.click();
  assert.deepEqual(e.bodies.at(-1).body.tables, [{ table: "public.orders", access: "READ" }, { table: "public.logs", access: "READ" }]);
});

test("the provider's own certificate: the same confirm step trusts it on Yes, the fingerprint under Details; No sends nothing", async () => {
  const nodes = fakePage();
  const refusal = { code: "CERTIFICATE_NOT_VERIFIED", message: "x", trustRoot: { subject: "CN=Acme Root,O=Acme", sha256: FP, expiresAt: "2031-05-01T00:00:00Z" } };
  const e = fakeEngine({ answer: (path, body) => body.trustRoot ? null : new Response(JSON.stringify(refusal), { status: 409 }) });
  await toTables(nodes, e);
  assert.equal(screenOf(nodes), "s-confirm");
  assert.equal(nodes["confirm-title"].textContent, "Is this your database?");
  assert.equal(nodes["confirm-sub"].textContent, "Check these, then continue. Your provider signs its own security certificate, so confirming also trusts it for this database only.");
  assert.deepEqual(facts(nodes), ["Database: app", "Host: db.example.com:5432", "Signed in as: admin", "Certificate: Acme Root"], "read from the string before any login");
  assert.equal(nodes["confirm-details"].hidden, false);
  assert.equal(nodes["confirm-fp"].textContent, `SHA-256: ${"AB:".repeat(31)}AB`);
  nodes["confirm-back"].click();
  assert.equal(screenOf(nodes), "s-paste");
  assert.equal(e.bodies.length, 1);
  assert.equal(e.bodies[0].body.trustRoot, undefined);

  nodes["paste-url"].value = ADMIN;
  await nodes["paste-next"].click();
  assert.equal(e.bodies.at(-1).body.trustRoot, undefined, "nothing trusted before the click");
  await nodes["confirm-go"].click();
  assert.equal(screenOf(nodes), "s-tables", "no second confirm once the person confirmed and trusted");
  assert.equal(e.bodies.at(-1).body.trustRoot, FP);
});

test("signed in somewhere else than the string named: the confirm step again, with what the engine reached", async () => {
  const nodes = fakePage();
  const refusal = { code: "CERTIFICATE_NOT_VERIFIED", message: "x", trustRoot: { subject: "CN=Acme Root", sha256: FP, expiresAt: "2031-05-01T00:00:00Z" } };
  const e = fakeEngine({ answer: (path, body) => body.trustRoot ? (body.tables ? null : new Response(JSON.stringify({ ...listing, database: "other_db", sessionUser: "cloudsqladmin", certificate: { kind: "OWN", issuer: "Acme Root" } }), { status: 200 })) : new Response(JSON.stringify(refusal), { status: 409 }) });
  await toTables(nodes, e);
  await nodes["confirm-go"].click();
  assert.equal(screenOf(nodes), "s-confirm", "asked again");
  assert.deepEqual(facts(nodes), ["Database: other_db", "Host: db.example.com:5432", "Signed in as: cloudsqladmin", "Certificate: Acme Root"]);
  assert.equal(nodes["confirm-details"].hidden, true, "nothing more to trust");
  const sent = e.bodies.length;
  await nodes["confirm-go"].click();
  assert.equal(screenOf(nodes), "s-tables");
  assert.equal(e.bodies.length, sent, "the second Yes sends nothing");
});

test("a run refused because the tables changed goes back to the string", async () => {
  const nodes = fakePage();
  const e = fakeEngine({ answer: (path) => path === RUN_PATH ? new Response(JSON.stringify({ code: "TABLES_CHANGED", message: "A table changed." }), { status: 409 }) : null });
  await toTables(nodes, e);
  await nodes["tables-next"].click();
  await nodes["labels-next"].click();
  await nodes.approve.click();
  await settle();
  assert.equal(screenOf(nodes), "s-paste");
  assert.match(nodes["paste-error"].textContent, /A table changed\.\nPaste the connection string again to see the tables as they are now\./);
  assert.equal(nodes.back.hidden, false, "Back is offered again");
});

test("a removal runs only once the database name is typed exactly as the check named it", () => {
  const checked = { database: "app" };
  assert.equal(removeConfirmed("app", checked), true);
  for (const typed of ["", "App", "app ", " app", "ap"]) assert.equal(removeConfirmed(typed, checked), false, typed);
  assert.equal(removeConfirmed("", { database: "" }), false);
  assert.equal(removeConfirmed("app", null), false);
});

test("the approval after Mark the rest says the rest are not personal", async () => {
  const nodes = fakePage();
  const e = fakeEngine();
  await toTables(nodes, e);
  const leads = find(nodes.tables.children[2], (n) => n.tagName === "INPUT");
  leads.checked = false;
  leads.fire("change");
  await nodes["tables-next"].click();
  const pick = find(nodes["label-tables"], (n) => n.tagName === "SELECT" && n.attrs["aria-label"] === "Label for orders.email");
  pick.value = "SECRET";
  pick.fire("change");
  nodes["rest-mark"].checked = true;
  nodes["rest-mark"].fire("change");
  assert.equal(nodes["rest-note"].textContent, "2 columns will be marked not personal.");
  await nodes["labels-next"].click();
  assert.equal(screenOf(nodes), "s-approve", "the choice is the confirmation");
  assert.match(nodes["ap-facts"].textContent, /Personal data: 1 column marked · the rest not personal/);
});

test("when the rest must go as restPublic, the note names the columns that look personal it would mark too", async () => {
  const more = fakeEngine({ answer: (path, body) => body.tables ? new Response(JSON.stringify({ database: "app", lines: [], sql: "", questions: [], notes: [], passkeyNeeded: true, challenge, columns, columnsMore: true }), { status: 200 }) : null });
  const i = new Install(more.fetchFn, real);
  await i.list(ADMIN);
  await i.check();
  assert.deepEqual(i.restPlan().suggested.map((c) => c.column), ["email"]);
  assert.deepEqual(i.restNote(), ["All unlabeled columns, the ones not listed here too, will be marked not personal, including these that look personal:", "orders.email"]);
  // Accepting the suggestion takes it out of the rest.
  i.acceptSuggestion(i.labels.columns.find((c) => c.column === "email"));
  assert.equal(i.restNote().length, 1);
});

test("Mark the rest leaves out a suggested column the person did not accept, on the page too", async () => {
  const nodes = fakePage();
  const e = fakeEngine();
  await toTables(nodes, e);
  const leads = find(nodes.tables.children[2], (n) => n.tagName === "INPUT");
  leads.checked = false;
  leads.fire("change");
  await nodes["tables-next"].click();
  assert.equal(nodes["rest-leave"].checked, true, "leaving them unlabeled is the default");
  assert.equal(nodes["rest-note"].hidden, true, "no note under the default");
  nodes["rest-mark"].checked = true;
  nodes["rest-mark"].fire("change");
  assert.equal(nodes["rest-note"].hidden, false);
  assert.deepEqual(nodes["rest-note"].children.map((n) => n.textContent), ["2 columns will be marked not personal.", "Not included, because they look personal:", "orders.email"]);
  await nodes["labels-next"].click();
  assert.deepEqual(e.bodies.at(-1).body.columnClasses.map((c) => c.column), ["note", "line"]);
  assert.equal(e.bodies.at(-1).body.restPublic, undefined);
});

test("Continue with the default choice keeps the picked labels and marks nothing else; the choice hides with nothing left unlabeled", async () => {
  const nodes = fakePage();
  const e = fakeEngine();
  await toTables(nodes, e);
  const leads = find(nodes.tables.children[2], (n) => n.tagName === "INPUT");
  leads.checked = false;
  leads.fire("change");
  await nodes["tables-next"].click();
  assert.equal(nodes["rest-choice"].hidden, false);
  const pick = (col) => find(nodes["label-tables"], (n) => n.tagName === "SELECT" && n.attrs["aria-label"] === `Label for ${col}`);
  pick("orders.note").value = "SECRET";
  pick("orders.note").fire("change");
  await nodes["labels-next"].click();
  assert.equal(screenOf(nodes), "s-approve", "no confirm with the default choice");
  assert.deepEqual(e.bodies.at(-1).body.columnClasses.map((c) => [c.column, c.class]), [["note", "SECRET"]]);
  assert.equal(e.bodies.at(-1).body.restPublic, undefined);

  nodes.back.click();
  for (const col of ["orders.email", "logs.line"]) {
    pick(col).value = "SECRET";
    pick(col).fire("change");
  }
  assert.equal(nodes["rest-choice"].hidden, true, "nothing left unlabeled: no choice");
});

test("the restPublic note counts every unlabeled column when more than 500 labels would go", () => {
  assert.deepEqual(restNote({ count: 501, forced: true, personal: ["orders.email"] }), ["All 501 unlabeled columns will be marked not personal, including these that look personal:", "orders.email"]);
});

test("a removal that removed the engine's last agent ends with the last step", () => {
  const job = { job: "REMOVE", agent: "demo_bot" };
  assert.ok(doneText(job, { agent: "demo_bot", engineRemoved: true }).endsWith(REMOVE_LAST_STEP));
  assert.ok(!doneText(job, { agent: "demo_bot", engineRemoved: false }).includes("Last step"));
  assert.ok(!doneText({ job: "UPDATE", agent: "demo_bot" }, { engineRemoved: true }).includes("Last step"));
});

// ---- The Update check: a CHANGE link opens on doctor ----

const change = { job: "CHANGE", agent: "bot", osUser: "alice", demo: false };
const ORIGIN = "http://localhost:8787";
const NEW_FP = "cd".repeat(32);
const ROOT = { subject: "CN=Provider Root", sha256: NEW_FP, expiresAt: "2031-05-01T00:00:00Z" };
const keyLocal = { credentialId: "a2V5MQ", label: "MacBook Pro", rpId: "localhost", origin: ORIGIN, createdAt: "2026-11-03T12:00:00Z", lastUsedAt: "2026-11-22T09:00:00Z" };
const keyPortal = { credentialId: "a2V5Mg", label: "iPhone", rpId: "basaltvault.app", origin: "https://portal.basaltvault.app", createdAt: "2026-11-03T12:00:00Z" };
const allGood = {
  database: "shop_db", guard: { state: "CURRENT" }, certificate: { state: "OK" },
  labels: { state: "OK", count: 0, columns: [] }, passkeys: { state: "OK", items: [keyLocal, keyPortal] },
};
const needs = {
  ...allGood,
  certificate: { state: "CHANGED", host: "db.example.com", port: 5432, pinned: FP, presented: ROOT, pinnedSubject: "CN=Provider Root,O=Provider", database: "shop_db", sameIssuer: true },
  labels: { state: "UNKNOWN", count: 0, columns: [] }, passkeys: { state: "UNKNOWN", items: [] },
};

// updateEngine answers doctor from doctors (one per call, the last kept),
// and each check or run from answers[job] (a function of the body).
function updateEngine(doctors, answers) {
  const bodies = [];
  const fetchFn = async (path, init) => {
    const body = JSON.parse(init.body);
    bodies.push({ path, body });
    let out;
    if (path === DOCTOR_PATH) out = doctors.length > 1 ? doctors.shift() : doctors[0];
    else if (path === ENGINE_PATH || path === NOT_MINE_PATH) out = answers[path](path, body);
    else out = answers[body.job](path, body);
    if (out.code) return new Response(JSON.stringify(out), { status: 409 });
    return new Response(JSON.stringify(out), { status: 200 });
  };
  return { bodies, fetchFn };
}

const shown = (nodes) => [...FLOW.keys()].filter((id) => /^(u|s)-/.test(id) && FLOW.get(id).tag === "section" && !nodes[id].hidden);

test("a refusal of a changed certificate keeps the pin it names", async () => {
  const body = { code: "CERTIFICATE_NOT_VERIFIED", message: "x", trustRoot: ROOT, pinned: FP };
  await assert.rejects(postSetup(async () => new Response(JSON.stringify(body), { status: 409 }), CHECK_PATH, {}), (err) => err.pinned === FP && err.trustRoot.sha256 === NEW_FP);
  const bad = { ...body, pinned: "AB" };
  await assert.rejects(postSetup(async () => new Response(JSON.stringify(bad), { status: 409 }), CHECK_PATH, {}), (err) => err.pinned === "");
});

test("doctor sends no admin string, and a refusal of the string drops it", async () => {
  const e = updateEngine([allGood], { REPAIR: () => ({ code: "LOGIN_FAILED", message: "The database refused the login." }) });
  const u = new UpdateCheck(e.fetchFn, change);
  await u.doctor();
  assert.deepEqual(e.bodies[0], { path: DOCTOR_PATH, body: { agent: "bot", osUser: "alice" } });
  await assert.rejects(u.check("REPAIR"), /Paste the admin connection string first/);
  u.setString(ADMIN);
  assert.equal(u.request("REPAIR").databaseUrl, ADMIN);
  await assert.rejects(u.check("REPAIR"), (err) => err.code === "LOGIN_FAILED");
  assert.equal(u.hasString, false, "the person types it again");
  assert.throws(() => new UpdateCheck(e.fetchFn, real));
});

test("the labels fix sends what the install sends, for the unlabeled columns only", () => {
  const cols = [
    { table: "public.orders", column: "phone", class: "UNCLASSIFIED", suggestedClass: "IDENTIFIER", suggestedEntityType: "PHONE" },
    { table: "public.orders", column: "note", class: "UNCLASSIFIED" },
  ];
  const l = new Labels(cols);
  assert.deepEqual(labelFields(l, false, false), {}, "left unlabeled: no run");
  assert.deepEqual(labelFields(l, false, true).columnClasses.map((c) => c.column), ["note"], "the suggested personal column is left out");
  assert.deepEqual(labelFields(l, true, true), { restPublic: true });
  l.set("public.orders", "phone", { class: "SECRET" });
  assert.deepEqual(labelFields(l, false, false), { columnClasses: [{ table: "public.orders", column: "phone", class: "SECRET", was: { class: "UNCLASSIFIED" } }] });
});

test("the Update check shows what needs the person, each critical row fixes itself, then Done ends on All set", async () => {
  const nodes = fakePage();
  const store = new Map();
  globalThis.localStorage = { getItem: (k) => store.get(k) ?? null, setItem: (k, v) => store.set(k, v) };
  const unlabeled = { ...allGood, labels: { state: "UNLABELED", count: 1, columns: ["public.orders.phone"] } };
  const e = updateEngine([needs, unlabeled, unlabeled, unlabeled], {
    TRUST: (path, body) => {
      if (!body.trustRoot) return { code: "CERTIFICATE_NOT_VERIFIED", message: "x", trustRoot: ROOT, pinned: FP };
      return path === RUN_PATH ? { agent: "bot", lines: ["done"] } : { database: "shop_db", lines: ["This replaces…"], sql: "SELECT …" };
    },
    LABELS: () => ({ database: "shop_db", lines: [], sql: "", columns: [{ table: "public.orders", column: "phone", class: "UNCLASSIFIED", dataType: "text" }] }),
  });
  startUpdate(change, { fetchFn: e.fetchFn, origin: ORIGIN, makePasskey: async () => ({}), pkc: null, now: () => new Date("2026-11-22T12:00:00Z"), onPick: () => {} });
  await settle();
  assert.deepEqual(shown(nodes), ["u-check"]);
  assert.equal(nodes["u-title"].textContent, "1 thing needs you");
  assert.equal(nodes["u-sub"].textContent, "The rest is checked once BasaltDB can connect.");
  assert.match(nodes["u-rows"].textContent, /shop_db renewed its security certificate.*Your agents are paused until you confirm\.Check/);
  assert.match(nodes["u-rows"].textContent, /Checked once BasaltDB can connect\./);
  assert.equal(nodes["u-end"].getAttribute("aria-disabled"), "true", "Done waits while something critical is open");
  assert.equal(nodes["u-end-why"].hidden, false);
  assert.equal(nodes["u-end-why"].textContent, "Confirm the certificate to finish. Until then, your agents are paused.");
  nodes["u-end"].click();
  assert.deepEqual(shown(nodes), ["u-check"], "a disabled Done does nothing");
  assert.ok(e.bodies.every((b) => !("databaseUrl" in b.body)), "nothing asks for the string to show the check");

  await find(nodes["u-rows"], (n) => n.tagName === "BUTTON" && n.textContent === "Check").click();
  assert.deepEqual(shown(nodes), ["s-paste"], "the string is asked at the first fix");
  nodes["paste-url"].value = ADMIN;
  nodes["paste-next"].click();
  await settle();
  assert.deepEqual(shown(nodes), ["s-confirm"]);
  assert.equal(nodes["confirm-title"].textContent, "Is this still your database?");
  assert.equal(nodes["confirm-sub"].textContent, "Providers renew certificates about once a year.");
  assert.deepEqual(facts(nodes), ["Database: shop_db", "Host: db.example.com:5432", "Signed in as: admin", "Certificate: Provider Root"]);
  assert.equal(nodes["confirm-ok"].textContent, "✓ Same issuer as before");
  assert.equal(nodes["confirm-go"].textContent, "Yes, trust the new certificate");
  assert.equal(nodes["confirm-back"].textContent, "Not expecting this? Stop here");
  assert.equal(nodes["confirm-fp"].textContent, `SHA-256: ${"CD:".repeat(31)}CD`);
  assert.equal(e.bodies.filter((b) => b.body.trustRoot).length, 0, "nothing trusted before the click");

  await nodes["confirm-go"].click();
  await settle();
  const trusted = e.bodies.filter((b) => b.body.job === "TRUST" && b.body.trustRoot === NEW_FP).map((b) => b.path);
  assert.deepEqual(trusted, [CHECK_PATH, RUN_PATH]);
  assert.deepEqual(shown(nodes), ["u-done"]);
  assert.equal(nodes["u-done-title"].textContent, "Security certificate trusted");
  assert.equal(nodes["u-done-text"].textContent, "Your agents reconnect.");
  nodes["u-done-next"].click();
  // Doctor again: the unlabeled columns it now reads are a warning; the walk does not go on to them.
  await settle();
  await settle();
  assert.equal(e.bodies.filter((b) => b.body.job === "LABELS").length, 0, "no labels fix is started on its own");
  assert.deepEqual(shown(nodes), ["u-check"]);
  assert.equal(nodes["u-title"].textContent, "Ready");
  assert.match(nodes["u-rows"].textContent, /1 column has no label.*orders\.phone.*Label/);
  assert.equal(nodes["u-end"].getAttribute("aria-disabled"), "false");

  // Label opens the labels page; leaving them unlabeled is saved and returns to the check.
  await find(nodes["u-rows"], (n) => n.tagName === "BUTTON" && n.textContent === "Label").click();
  await settle();
  assert.deepEqual(shown(nodes), ["s-labels"]);
  await nodes["labels-next"].click();
  await settle();
  await settle();
  assert.equal(e.bodies.filter((b) => b.path === RUN_PATH && b.body.job === "LABELS").length, 0, "leaving them unlabeled sends no run");
  assert.deepEqual(shown(nodes), ["u-check"]);
  assert.equal(nodes["u-title"].textContent, "Ready");
  assert.match(nodes["u-rows"].textContent, /orders\.phone · you chose to leave them for now/);
  delete globalThis.localStorage;

  // Done: the All set screen says what is left for later.
  nodes["u-end"].click();
  assert.deepEqual(shown(nodes), ["u-allset"]);
  assert.equal(nodes["u-allset-title"].textContent, "All set");
  assert.equal(nodes["u-allset-text"].textContent, "Close this tab and go back to your agent. It can work now.");
  assert.match(nodes["u-allset-lines"].textContent, /✓ Passkeys: 1 device can approve/);
  assert.equal(nodes["u-allset-later"].textContent, "Left for later: 1 column has no label. Run `basalt init` to change it.");
});

test("a certificate from a new issuer: the cautious words, Trust it anyway the weaker button, Stop here trusts nothing", async () => {
  const nodes = fakePage();
  const other = { ...needs, certificate: { ...needs.certificate, pinnedSubject: "CN=Google Cloud SQL Server CA,O=Google\\, Inc", sameIssuer: false } };
  const e = updateEngine([other, allGood], {
    TRUST: (path, body) => (body.trustRoot ? { database: "shop_db", lines: [], sql: "" } : { code: "CERTIFICATE_NOT_VERIFIED", message: "x", trustRoot: ROOT, pinned: FP }),
  });
  startUpdate(change, { fetchFn: e.fetchFn, origin: ORIGIN, makePasskey: async () => ({}), pkc: null, now: () => new Date(), onPick: () => {} });
  await settle();
  find(nodes["u-rows"], (n) => n.tagName === "BUTTON" && n.textContent === "Check").click();
  nodes["paste-url"].value = ADMIN;
  nodes["paste-next"].click();
  await settle();
  assert.deepEqual(shown(nodes), ["s-confirm"]);
  assert.equal(nodes["confirm-title"].textContent, "Is this still your database?");
  assert.equal(nodes["confirm-sub"].textContent, "The certificate now comes from someone new. Check with your provider first. Your agents stay paused.");
  assert.equal(nodes["confirm-before"].textContent, "Before: Google Cloud SQL Server CA");
  assert.equal(nodes["confirm-ok"].hidden, true);
  assert.equal(nodes["confirm-go"].textContent, "Trust it anyway");
  assert.equal(nodes["confirm-go"].className, "secondary");
  assert.equal(nodes["confirm-back"].textContent, "Stop here");
  await nodes["confirm-back"].click();
  await settle();
  assert.deepEqual(shown(nodes), ["u-check"]);
  assert.equal(e.bodies.filter((b) => b.body.trustRoot).length, 0, "Stop here trusts nothing");
  assert.ok(e.bodies.every((b) => b.path !== RUN_PATH));
});

test("Manage lists the passkeys, and removing the last one asks for a new one", async () => {
  const nodes = fakePage();
  const signals = [];
  const pkc = { signalUnknownCredential: async (o) => signals.push(o) };
  const e = updateEngine([allGood], {
    PASSKEY_REMOVE: (path) => (path === RUN_PATH ? { agent: "bot", lines: [], remaining: 0 } : { database: "shop_db", lines: ["This removes the passkey MacBook Pro, added 3 Nov 2026."], sql: "SELECT basalt_meta.revoke_passkey('\\x6b6579'::bytea, true);" }),
  });
  startUpdate(change, { fetchFn: e.fetchFn, origin: ORIGIN, makePasskey: async () => ({}), pkc, now: () => new Date("2026-11-22T12:00:00Z"), onPick: () => {} });
  await settle();
  assert.equal(nodes["u-title"].textContent, "Ready");
  assert.match(nodes["u-rows"].textContent, /Database certificate checked/);
  assert.match(nodes["u-rows"].textContent, /Passkeys1 device can approveManage/);
  const manage = find(nodes["u-rows"], (n) => n.tagName === "BUTTON" && n.textContent === "Manage");
  manage.click();
  assert.deepEqual(shown(nodes), ["u-passkeys"]);
  assert.match(nodes["u-keys"].textContent, /MacBook ProAdded 3 Nov · used today/);
  assert.match(nodes["u-keys"].textContent, /iPhoneAdded 3 Nov on portal\.basaltvault\.app · used never/);
  const remove = find(nodes["u-keys"], (n) => n.attrs["aria-label"] === "Remove MacBook Pro");
  remove.click();
  assert.deepEqual(shown(nodes), ["s-paste"]);
  nodes["paste-url"].value = ADMIN;
  nodes["paste-next"].click();
  await settle();
  assert.deepEqual(shown(nodes), ["u-confirm"]);
  assert.equal(nodes["u-confirm-go"].textContent, "Remove passkey");
  assert.equal(e.bodies.at(-1).body.credentialId, "a2V5MQ");
  await nodes["u-confirm-go"].click();
  assert.deepEqual(signals, [{ rpId: "localhost", credentialId: "a2V5MQ" }], "the browser is told the passkey is gone");
  assert.deepEqual(shown(nodes), ["u-done"]);
  assert.equal(nodes["u-done-text"].textContent, "Add a passkey so your agents can be approved again.");
});

test("a ledger that names another certificate is recorded with the pin the check showed", async () => {
  const nodes = fakePage();
  const mismatch = { ...allGood, certificate: { state: "MISMATCH", host: "db.example.com", port: 5432, pinned: FP, recorded: NEW_FP } };
  const e = updateEngine([mismatch, allGood], {
    TRUST: (path) => (path === RUN_PATH ? { agent: "bot", lines: [] } : { database: "shop_db", lines: ["This records…"], sql: "SELECT …", pinned: FP, recorded: NEW_FP }),
  });
  startUpdate(change, { fetchFn: e.fetchFn, origin: ORIGIN, makePasskey: async () => ({}), pkc: null, now: () => new Date(), onPick: () => {} });
  await settle();
  find(nodes["u-rows"], (n) => n.tagName === "BUTTON" && n.textContent === "Check").click();
  nodes["paste-url"].value = ADMIN;
  nodes["paste-next"].click();
  await settle();
  assert.deepEqual(shown(nodes), ["u-mismatch"]);
  assert.equal(nodes["u-mm-pinned"].textContent, "AB:".repeat(31) + "AB");
  assert.equal(nodes["u-mm-recorded"].textContent, "CD:".repeat(31) + "CD");
  await nodes["u-mm-go"].click();
  const run = e.bodies.find((b) => b.path === RUN_PATH);
  assert.equal(run.body.pinned, FP);
  assert.equal(run.body.trustRoot, undefined);
});

const engineDb = { agents: ["bot"], databases: [{ database: "shop_db", host: "db.example.com", port: 5432 }] };

test("before the check the page asks whose database the engine serves; Yes shows the check", async () => {
  const nodes = fakePage();
  const e = updateEngine([allGood], { [ENGINE_PATH]: () => engineDb, [NOT_MINE_PATH]: () => assert.fail("no No") });
  startUpdate(change, { fetchFn: e.fetchFn, origin: ORIGIN, makePasskey: async () => ({}), pkc: null, now: () => new Date(), onPick: () => {} });
  await settle();
  assert.deepEqual(shown(nodes), ["s-confirm"]);
  assert.deepEqual(e.bodies, [{ path: ENGINE_PATH, body: {} }], "the question names no agent and no string");
  assert.equal(nodes["confirm-title"].textContent, "Is this your database?");
  assert.deepEqual(facts(nodes), ["Database: shop_db", "Host: db.example.com:5432"]);
  assert.equal(nodes["confirm-go"].textContent, "Yes, this is it");
  assert.equal(nodes["confirm-back"].textContent, "No, this isn't mine");
  assert.equal(nodes.back.hidden, true);
  await nodes["confirm-go"].click();
  await settle();
  assert.deepEqual(shown(nodes), ["u-check"]);
  assert.equal(nodes["u-title"].textContent, "Ready");
  assert.deepEqual(e.bodies.map((b) => b.path), [ENGINE_PATH, DOCTOR_PATH]);
});

test("No, this isn't mine: the page only tells the engine and says the password dialog comes next; it resets nothing", async () => {
  const nodes = fakePage();
  const theirs = { agents: ["other_bot"], databases: [{ database: "agent_db", host: "10.0.0.9", port: 6543 }] };
  const e = updateEngine([{ code: "INVALID_ARGUMENT", message: "This engine has no agent bot." }], { [ENGINE_PATH]: () => theirs, [NOT_MINE_PATH]: () => ({}) });
  startUpdate(change, { fetchFn: e.fetchFn, origin: ORIGIN, makePasskey: async () => ({}), pkc: null, now: () => new Date(), onPick: () => {} });
  await settle();
  assert.deepEqual(facts(nodes), ["Database: agent_db", "Host: 10.0.0.9:6543"]);
  await nodes["confirm-back"].click();
  await settle();
  assert.deepEqual(e.bodies, [{ path: ENGINE_PATH, body: {} }, { path: NOT_MINE_PATH, body: {} }]);
  assert.deepEqual(shown(nodes), ["u-done"]);
  assert.equal(nodes["u-done-title"].textContent, "Your computer asks for your password next");
  assert.match(nodes["u-done-text"].textContent, /administrator password in the system dialog that opens\. It deletes BasaltDB's setup on this computer and touches no database\./);
  assert.equal(nodes["u-done-next"].hidden, true);
});

test("a refused engine check goes straight to the check", async () => {
  const nodes = fakePage();
  const e = updateEngine([allGood], { [ENGINE_PATH]: () => ({ code: "JOB_UNAVAILABLE", message: "x" }) });
  startUpdate(change, { fetchFn: e.fetchFn, origin: ORIGIN, makePasskey: async () => ({}), pkc: null, now: () => new Date(), onPick: () => {} });
  await settle();
  await settle();
  assert.deepEqual(shown(nodes), ["u-check"]);
});
