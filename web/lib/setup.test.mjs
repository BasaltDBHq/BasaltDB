// Runs with `node --test web/lib/*.test.mjs` (make web-check). The local
// setup page: it runs only on the engine's own local origin, reads its job
// from the link's fragment, and posts the job with the admin connection
// string only to the engine's own setup routes.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { b64urlEncode, utf8 } from "./codec.js";
// Imported before any document exists, so the page's main() does not run.
import { CHECK_PATH, JOB_TEXT, JOBS, localOrigin, parseSetupLink, postSetup, RUN_PATH, setupRequest } from "./setup.js";

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
  for (const name of ["UPDATE", "REMOVE"]) {
    const j = { ...job, job: name, demo: false };
    assert.deepEqual(parseSetupLink(link(j)), j);
    assert.deepEqual(setupRequest(j, "postgres://u@h/d"), { ...j, databaseUrl: "postgres://u@h/d" });
  }
});

test("every job has its own fixed words, which name the agent", () => {
  for (const name of JOBS) {
    const t = JOB_TEXT[name];
    assert.ok(t.title && t.run, name);
    assert.match(t.intro("demo_bot"), /demo_bot/, name);
    assert.match(t.done("demo_bot"), /demo_bot/, name);
  }
  assert.match(JOB_TEXT.REMOVE.intro("a"), /Nothing can undo it/);
});
