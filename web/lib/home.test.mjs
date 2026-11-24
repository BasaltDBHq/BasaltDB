import { test } from "node:test";
import assert from "node:assert/strict";
import { checkLabels, guardRow, homeView, passkeysRow } from "./home.js";

const running = { state: "RUNNING", version: "0.1.0-alpha", agents: 2, databases: 1, providers: ["SUPABASE"], guard: "CURRENT", passkeys: 1, checks: [{ provider: "SUPABASE", href: "http://localhost:8787/setup/#1.x" }] };

const text = (parts) => parts.map((p) => p.bold ?? p.code ?? p.plain).join("");

test("a running engine shows counts, the provider kind and three health rows", () => {
  const v = homeView(running);
  assert.equal(v.title, "BasaltDB is running");
  assert.equal(text(v.sub), "2 agents on 1 database (Supabase). Your agent sends you links here when a change needs your passkey.");
  assert.deepEqual(v.rows.map((r) => [r.title, r.text]), [
    ["Engine", "Running, 0.1.0-alpha"],
    ["Guard", "Up to date in your database"],
    ["Passkeys", "1 device can approve"],
  ]);
  assert.deepEqual(v.setup.checks.map((c) => c.label), ["Check your Supabase setup"]);
  assert.match(v.setup.text, /^Opens the check-up: certificate, passkeys and updates\. Changes there need your passkey or the database admin string\.$/);
  assert.ok(v.changes);
});

test("two databases of different kinds are both named, and one button each", () => {
  const v = homeView({ ...running, agents: 2, databases: 2, providers: ["AMAZON_RDS", "POSTGRES"], checks: [{ provider: "AMAZON_RDS", href: "a" }, { provider: "POSTGRES", href: "b" }] });
  assert.match(text(v.sub), /^2 agents on 2 databases \(Amazon RDS, Postgres\)\./);
  assert.deepEqual(v.setup.checks.map((c) => c.label), ["Check your Amazon RDS setup", "Check your Postgres setup"]);
});

test("two databases of one kind get numbered buttons", () => {
  assert.deepEqual(checkLabels([{ provider: "POSTGRES", href: "a" }, { provider: "POSTGRES", href: "b" }]).map((c) => c.label), ["Check your Postgres setup (1)", "Check your Postgres setup (2)"]);
});

test("a row that cannot be read says when it will be checked", () => {
  const unreadable = "Checked once BasaltDB can reach your database";
  assert.equal(guardRow("UNKNOWN").text, unreadable);
  assert.equal(passkeysRow(null).text, unreadable);
  assert.equal(guardRow("NEEDS_UPDATE").mark, "need");
  assert.equal(passkeysRow(0).mark, "need");
  assert.equal(passkeysRow(3).text, "3 devices can approve");
});

test("without the check-up the card tells the agent's command and has no button", () => {
  const v = homeView({ ...running, checks: [] });
  assert.deepEqual(v.setup.checks, []);
  assert.match(v.setup.text, /basalt init/);
});

test("an engine with no setup shows no counts and no rows", () => {
  const v = homeView({ state: "NOT_SET_UP", version: "0.1.0-alpha" });
  assert.equal(v.title, "BasaltDB is installed");
  assert.equal(text(v.sub), "Ask your agent to run basalt init to set it up.");
  assert.deepEqual(v.rows, []);
  assert.equal(v.setup, null);
});

test("a missing answer says it could not read the state", () => {
  assert.match(text(homeView(null).sub), /could not read/);
});
