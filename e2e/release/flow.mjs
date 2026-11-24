// The end-to-end flow of the release binaries on one machine (persona 1):
// install, the setup page, the agent's MCP session, a held write's approval,
// a revert and the removal. run.sh sets the machine up and calls this.
//
// Environment: E2E_BIN (the installed basalt), E2E_ADMIN_URL (the database's
// admin connection string, typed on the setup page only), E2E_OUT (where
// failure evidence goes), E2E_DIR (this folder).
import { execFileSync, spawn } from "node:child_process";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { chromium } from "playwright";
import { find, McpClient } from "./mcp.mjs";

const BIN = must("E2E_BIN");
const ADMIN_URL = must("E2E_ADMIN_URL");
const OUT = must("E2E_OUT");
const DIR = must("E2E_DIR");
const AGENT = "e2e_bot";
const PAGES = "http://localhost:8787";
const STEP_MS = 120000;

function must(name) {
  const v = process.env[name];
  if (!v) throw new Error(`${name} is not set`);
  return v;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const ok = (step) => console.log(`e2e: ${step} ok`);

// The test never prints the admin string: errors and logs go through this.
function scrub(text) {
  return String(text).split(ADMIN_URL).join("<admin-url>");
}

fs.mkdirSync(OUT, { recursive: true });

// ---- the browser: one page, one CDP session, one virtual authenticator ----

let browser;
let page;

async function openBrowser() {
  browser = await chromium.launch({ headless: true });
  const context = await browser.newContext();
  page = await context.newPage();
  page.setDefaultTimeout(STEP_MS);
  page.on("console", (m) => {
    if (m.type() === "error") console.log(`e2e: page console error: ${scrub(m.text())}`);
  });
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
}

// open goes to a link on a fresh load: a link that differs from the page's
// only in its fragment would not reload it.
async function open(url) {
  await page.goto("about:blank");
  await page.goto(url, { waitUntil: "load" });
}

async function evidence(label) {
  try {
    if (page) {
      await page.screenshot({ path: path.join(OUT, `${label}.png`), fullPage: true });
      const text = await page.evaluate(() => document.body.innerText);
      fs.writeFileSync(path.join(OUT, `${label}.txt`), scrub(`${page.url().split("#")[0]}\n\n${text}`));
    }
  } catch (err) {
    console.log(`e2e: no page evidence: ${err.message}`);
  }
}

const screenId = () =>
  page.evaluate(() => {
    const open = [...document.querySelectorAll("main section.screen")].find((s) => !s.hidden);
    return open ? open.id : "";
  });

// until polls fn until it returns something truthy.
async function until(what, fn, ms = STEP_MS) {
  const end = Date.now() + ms;
  let last;
  while (Date.now() < end) {
    last = await fn();
    if (last) return last;
    await sleep(500);
  }
  throw new Error(`timed out waiting for ${what}`);
}

const visible = (sel) => page.locator(sel).isVisible();

// ---- shell helpers ----

function run(cmd, args, opts = {}) {
  return execFileSync(cmd, args, { encoding: "utf8", env: process.env, ...opts });
}

// basaltInit runs `basalt init`, which prints the link on its first line and
// the MCP line on its second. It returns the process too: the removal's init
// waits on the page.
function basaltInit(args) {
  const child = spawn(BIN, ["init", ...args], { env: { ...process.env, BASALT_UPDATE_CHECK: "0" }, stdio: ["ignore", "pipe", "pipe"] });
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (d) => (stdout += d));
  child.stderr.on("data", (d) => (stderr += d));
  const exited = new Promise((resolve) => child.on("exit", (code) => resolve(code)));
  return { child, exited, out: () => stdout, err: () => stderr };
}

async function initLink(init) {
  const link = await until("the link from basalt init", () => init.out().split("\n").find((l) => l.startsWith("http://localhost:")), 180000);
  return link.trim();
}

// ---- the steps ----

let mcpLine = "";
let setupLink = "";

async function install() {
  // The administrator dialog is not available on a runner: run its fixed script under sudo.
  run("sh", [path.join(DIR, "service.sh"), "install", BIN], { stdio: "inherit" });
  const init = basaltInit(["--agent", AGENT]);
  try {
    setupLink = await initLink(init);
  } catch (err) {
    console.log(`e2e: basalt init stdout: ${init.out()}\nstderr: ${init.err()}`);
    throw err;
  }
  mcpLine = init.out().split("\n").find((l) => l.startsWith("basalt mcp")) ?? "";
  assert.match(mcpLine, new RegExp(`--agent ${AGENT}`), "init prints the mcp line");
  const code = await init.exited;
  assert.equal(code, 0, `basalt init exited ${code}: ${init.err()}`);
  assert.ok(!/administrator dialog.*cannot be shown/.test(init.err()), "init asked for the dialog");
  ok("install");
}

async function setupPage() {
  await open(setupLink);
  await page.locator("#s-user").waitFor({ state: "visible" });
  await page.locator("#user-confirm").check();
  await page.locator("#user-next").click();
  await page.locator("#paste-url").fill(ADMIN_URL);
  await page.locator("#paste-next").click();
  // Is this your database? may come more than once (trust, then facts); the
  // labels screen only when a column suggests one.
  for (;;) {
    const id = await until("the next setup screen", async () => {
      const s = await screenId();
      return s && s !== "s-checking" ? s : "";
    });
    if (id === "s-confirm") {
      if (await visible("#confirm-error")) throw new Error(`confirm refused: ${await page.locator("#confirm-error").innerText()}`);
      await page.locator("#confirm-go").click();
    } else if (id === "s-paste") {
      throw new Error(`the page asked for the string again: ${scrub(await page.locator("#paste-error").innerText())}`);
    } else if (id === "s-tables") {
      await page.locator("#tables-next").click();
    } else if (id === "s-labels") {
      await page.locator("#labels-next").click();
    } else if (id === "s-approve") {
      break;
    } else {
      throw new Error(`unexpected setup screen ${id}`);
    }
    await sleep(500);
  }
  await page.locator("#approve").click();
  await until("the done state", async () => (await visible("#done")) || (await visible("#approve-status") && /fail|refus|cannot|error/i.test(await page.locator("#approve-status").innerText())));
  assert.ok(await visible("#done"), `setup did not finish: ${await page.locator("#approve-status").innerText()}`);
  ok("setup page");
}

let mcp;
let runId;

const SNAPSHOT_SQL = "select id, name from public.items order by id";

async function snapshot() {
  const r = await mcp.call("query", { sql: SNAPSHOT_SQL, runId });
  assert.ok(!r.isError, `query failed: ${r.text}`);
  return JSON.stringify(r.data.rows);
}

async function mcpSession() {
  const args = mcpLine.split(/\s+/).slice(2);
  mcp = new McpClient(BIN, args, { ...process.env, BASALT_UPDATE_CHECK: "0" });
  await mcp.initialize();
  await until("status ready", async () => {
    const s = await mcp.call("status");
    return s.data.ready === true;
  }, 90000);
  const started = await mcp.call("run_start", { intent: "release e2e: change and revert items" });
  assert.ok(!started.isError, `run_start failed: ${started.text}`);
  runId = started.data.runId;
  assert.ok(runId, "run_start returns a runId");
  const count = await mcp.call("query", { sql: "select count(*) as n from public.items", runId });
  assert.ok(!count.isError, `query failed: ${count.text}`);
  assert.equal(Number(count.data.rows[0].n), 20, "20 rows to start");
  before = await snapshot();
  const one = await mcp.call("write", { sql: "update public.items set name = name || '-one' where id = $1", params: [1], intent: "release e2e: change one row", runId });
  assert.ok(!one.isError, `one-row write failed: ${one.text}`);
  assert.equal(one.data.status, "APPLIED");
  assert.equal(one.data.rows, 1);
  const held = await mcp.call("write", { sql: HELD_SQL, intent: HELD_INTENT, runId });
  assert.ok(held.isError, `a 12-row write must be held: ${held.text}`);
  heldUrl = find(held.data, "approvalUrl") ?? (held.text.match(/http:\/\/localhost:\d+\/approvals\/[^\s"\\]+/) ?? [])[0];
  heldId = find(held.data, "approvalId");
  assert.ok(heldUrl && heldUrl.startsWith(`${PAGES}/approvals/`), `the hold carries an approval link: ${held.text}`);
  assert.ok(heldId, `the hold carries an approvalId: ${held.text}`);
  ok("mcp");
}

let before = "";
let heldUrl = "";
let heldId = "";
const HELD_SQL = "update public.items set name = name || '-twelve' where id between 2 and 13";
const HELD_INTENT = "release e2e: change twelve rows";

async function approve() {
  await open(heldUrl);
  await page.locator("#approve").waitFor({ state: "visible" });
  await page.locator("#approve").click();
  await until("the approval to finish", () => visible("#done"));
  const applied = await mcp.call("write", { sql: HELD_SQL, intent: HELD_INTENT, runId, approvalId: heldId });
  assert.ok(!applied.isError, `the approved write failed: ${applied.text}`);
  assert.equal(applied.data.status, "APPLIED");
  assert.equal(applied.data.rows, 12);
  const changed = await mcp.call("query", { sql: "select count(*) as n from public.items where name like '%-twelve'", runId });
  assert.equal(Number(changed.data.rows[0].n), 12, "12 rows changed");
  ok("approve");
}

async function revert() {
  const asked = await mcp.call("request_revert", { runId, intent: "release e2e: undo the run" });
  assert.ok(!asked.isError, `request_revert failed: ${asked.text}`);
  const revertId = find(asked.data, "revertId");
  const url = find(asked.data, "revertUrl") ?? (asked.text.match(/http:\/\/localhost:\d+\/reverts\/[^\s"\\]+/) ?? [])[0];
  assert.ok(revertId && url && url.startsWith(`${PAGES}/reverts/`), `the revert carries its link: ${asked.text}`);
  await open(url);
  await page.locator("#sign").waitFor({ state: "visible" });
  await page.locator("#sign").click();
  await until("the revert to finish", () => visible("#done"));
  let state = await mcp.call("request_revert", { revertId, waitForSignature: 30 });
  assert.ok(!state.isError, `request_revert wait failed: ${state.text}`);
  if (state.data.status === "APPLYING") {
    const plan = await mcp.call("revert_plan", { revertId });
    const lines = (find(plan.data, "lines") ?? []).map((l) => l.line ?? l).filter(Number.isInteger);
    for (let i = 0; i < lines.length; i += 200) {
      const batch = await mcp.call("apply_revert_batch", { revertId, lines: lines.slice(i, i + 200) });
      assert.ok(!batch.isError, `apply_revert_batch failed: ${batch.text}`);
    }
    state = await mcp.call("request_revert", { revertId, waitForSignature: 0 });
  }
  assert.equal(state.data.status, "APPLIED", `the revert is applied: ${state.text}`);
  assert.equal(await snapshot(), before, "the items are back as they were");
  ok("revert");
}

async function remove() {
  mcp.close();
  const init = basaltInit(["--agent", AGENT]);
  const link = await initLink(init);
  await open(link);
  // The change link first asks whose database the engine serves, then runs the check.
  const first = await until("the confirm step or the check", async () => {
    if (await visible("#confirm-go")) return "confirm";
    if (await visible("#u-pick")) return "check";
    return "";
  });
  if (first === "confirm") {
    await page.locator("#confirm-go").click();
    await page.locator("#u-pick").waitFor({ state: "visible" });
  }
  await page.locator("#u-pick").click();
  await page.locator("#choice-remove").check();
  await page.locator("#confirm-os-user").check();
  await page.locator("#database-url").fill(ADMIN_URL);
  await page.locator("#check").click();
  await page.locator("#remove-name").waitFor({ state: "visible" });
  await page.locator("#confirm-remove").fill((await page.locator("#remove-name").innerText()).trim());
  await page.locator("#run").click();
  await until("the removal to finish", () => visible("#done"));
  // The service itself is removed through the administrator dialog, which a
  // runner cannot show: init says so and the fixed script runs under sudo.
  await Promise.race([init.exited, sleep(120000)]);
  init.child.kill();
  run("sh", [path.join(DIR, "service.sh"), "remove"], { stdio: "inherit" });
  assert.ok(!serviceListed(), "the engine service is gone");
  ok("remove");
}

function serviceListed() {
  try {
    if (process.platform === "darwin") run("launchctl", ["print", "system/dev.basaltdb.engine"], { stdio: "ignore" });
    else run("systemctl", ["status", "basalt-engine"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

const steps = [
  ["install", install],
  ["setup-page", setupPage],
  ["mcp", mcpSession],
  ["approve", approve],
  ["revert", revert],
  ["remove", remove],
];

let failed = null;
try {
  await openBrowser();
  for (const [name, fn] of steps) {
    try {
      await fn();
    } catch (err) {
      failed = name;
      await evidence(`fail-${name}`);
      throw err;
    }
  }
} catch (err) {
  console.error(`e2e: FAILED at ${failed}: ${scrub(err.stack ?? err)}`);
  process.exitCode = 1;
} finally {
  if (mcp) {
    fs.writeFileSync(path.join(OUT, "mcp-stderr.txt"), scrub(mcp.stderr));
    mcp.close();
  }
  if (browser) await browser.close();
}
