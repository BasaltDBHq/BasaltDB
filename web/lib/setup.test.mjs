// Runs with `node --test web/lib/*.test.mjs` (make web-check). The local
// setup page: it runs only on the engine's own local origin, reads its job
// from the link's fragment, and posts the job with the admin connection
// string only to the engine's own setup routes.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { b64urlEncode, utf8 } from "./codec.js";
// Imported before any document exists, so the page's main() does not run.
import { agentProbe, answerFits, CHECK_PATH, CHOICES, Install, JOB_TEXT, JOBS, labelWords, localOrigin, parseSetupLink, pickJob, postSetup, RUN_PATH, removeConfirmed, SetupError, setupRequest, startReal, suggestionOf, trustView } from "./setup.js";

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

// The link basalt init prints (internal/localsetup.Link) parses to its job.
const vector = JSON.parse(readFileSync(new URL("../../internal/localsetup/testdata/link.json", import.meta.url), "utf8"));

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
  assert.deepEqual(e.bodies.at(-1).body.columnClasses.map((c) => [c.column, c.class]), [["email", "PUBLIC"], ["note", "PUBLIC"], ["line", "PUBLIC"]]);
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
  assert.deepEqual(body.columnClasses.map((c) => c.column), ["email"]);
  assert.equal(j.view().restPublic, true);
});

test("a certificate no authority signs: the page shows the fingerprint, and trusting it sends its SHA-256 with every call", async () => {
  const refusal = { code: "CERTIFICATE_NOT_VERIFIED", message: "The database's certificate is not signed by an authority this computer trusts.", trustRoot: { subject: "CN=Acme Root", sha256: FP, expiresAt: "2031-05-01T00:00:00Z" } };
  const e = fakeEngine({ answer: (path, body) => body.trustRoot ? null : new Response(JSON.stringify(refusal), { status: 409 }) });
  const i = new Install(e.fetchFn, real);
  await assert.rejects(i.list(ADMIN), (err) => err instanceof SetupError && err.code === "CERTIFICATE_NOT_VERIFIED");
  assert.deepEqual(i.asking, refusal.trustRoot);
  assert.deepEqual(trustView(i.hostHint, i.asking), {
    host: "db.example.com",
    fingerprint: "AB:".repeat(31) + "AB",
    subject: "CN=Acme Root",
    expires: "2031-05-01",
    question: "Trust it for this host only?",
  });
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
  return install;
}

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
  await nodes["labels-skip"].click();
  assert.equal(screenOf(nodes), "s-approve");
  assert.match(nodes["ap-facts"].textContent, /Changes rows in: orders/);
  nodes.back.click();
  assert.equal(screenOf(nodes), "s-labels");
  nodes.back.click();
  find(nodes.tables.children[0], (n) => n.value === "READ").click();
  await nodes["tables-next"].click();
  await nodes["labels-skip"].click();
  assert.match(nodes["ap-facts"].textContent, /Reads: orders, logs/);
  await nodes.approve.click();
  assert.deepEqual(e.bodies.at(-1).body.tables, [{ table: "public.orders", access: "READ" }, { table: "public.logs", access: "READ" }]);
});

test("the certificate step shows the fingerprint; Cancel drops the string and sends nothing more", async () => {
  const nodes = fakePage();
  const refusal = { code: "CERTIFICATE_NOT_VERIFIED", message: "x", trustRoot: { subject: "CN=Acme Root", sha256: FP, expiresAt: "2031-05-01T00:00:00Z" } };
  const e = fakeEngine({ answer: (path, body) => body.trustRoot ? null : new Response(JSON.stringify(refusal), { status: 409 }) });
  await toTables(nodes, e);
  assert.equal(screenOf(nodes), "s-trust");
  assert.equal(nodes["trust-fp"].textContent, "AB:".repeat(31) + "AB");
  assert.equal(nodes["trust-subject"].textContent, "CN=Acme Root");
  assert.match(nodes["trust-host"].textContent, /^db\.example\.com /);
  nodes["trust-cancel"].click();
  assert.equal(screenOf(nodes), "s-paste");
  assert.equal(e.bodies.length, 1);

  nodes["paste-url"].value = ADMIN;
  await nodes["paste-next"].click();
  await nodes["trust-go"].click();
  assert.equal(screenOf(nodes), "s-tables");
  assert.equal(e.bodies.at(-1).body.trustRoot, FP);
});

test("a run refused because the tables changed goes back to the string", async () => {
  const nodes = fakePage();
  const e = fakeEngine({ answer: (path) => path === RUN_PATH ? new Response(JSON.stringify({ code: "TABLES_CHANGED", message: "A table changed." }), { status: 409 }) : null });
  await toTables(nodes, e);
  await nodes["tables-next"].click();
  await nodes["labels-skip"].click();
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
  nodes["labels-rest"].click();
  assert.match(nodes["rest-question"].textContent, /Mark 2 columns in 2 tables as not personal\?/);
  await nodes["rest-yes"].click();
  assert.equal(screenOf(nodes), "s-approve");
  assert.match(nodes["ap-facts"].textContent, /Personal data: 1 column marked · the rest not personal/);
});
