// The end-to-end flow of the release binaries on one machine (persona 1):
// install, the setup page, the agent's MCP session, a held write's approval,
// a revert and the removal. run.sh sets the machine up and calls this.
//
// Environment: E2E_BIN (the basalt under test, in a folder the runner's
// account owns, as a person's is), E2E_SERVICE_BIN (the engine service's own
// copy the install makes), E2E_ADMIN_URL (the database's
// admin connection string, typed on the setup page only), E2E_OUT (where
// failure evidence goes), E2E_DIR (this folder).
import { execFileSync, spawn } from "node:child_process";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { chromium } from "playwright";
import { find, McpClient } from "./mcp.mjs";

const BIN = must("E2E_BIN");
const SERVICE_BIN = must("E2E_SERVICE_BIN");
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
  // basalt is not root's where it was unpacked: the install copied it, root's.
  assert.notEqual(fs.statSync(BIN).uid, 0, "the basalt under test is the runner's, as a person's is");
  const copy = fs.lstatSync(SERVICE_BIN);
  assert.ok(copy.isFile(), `${SERVICE_BIN} is a plain file`);
  assert.equal(copy.uid, 0, `${SERVICE_BIN} is root's`);
  assert.equal(copy.mode & 0o777, 0o755, `${SERVICE_BIN} is 0755`);
  assert.ok(fs.readFileSync(SERVICE_BIN).equals(fs.readFileSync(BIN)), "the service runs a copy of the basalt under test");
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
  await realInstall();
  ok("setup page");
}

// realInstall walks the install of a real database on the setup page, from
// its first screen to done, with the passkey from the virtual authenticator.
async function realInstall() {
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
    // Wait for the page to leave the screen just handled before reading the
    // next one; a slow runner otherwise gets the same screen and clicks its
    // now-hidden button twice. The confirm screen can come twice in a row
    // (trust, then facts), so it only waits a short while for a change.
    if (id === "s-confirm") {
      await until("the confirm screen to change", async () => (await screenId()) !== id, 5000).catch(() => {});
    } else {
      await until(`the page to leave ${id}`, async () => (await screenId()) !== id, 30000);
    }
  }
  await page.locator("#approve").click();
  await until("the done state", async () => (await visible("#done")) || (await visible("#approve-status") && /fail|refus|cannot|error/i.test(await page.locator("#approve-status").innerText())));
  assert.ok(await visible("#done"), `setup did not finish: ${await page.locator("#approve-status").innerText()}`);
}

// The root page: running, with the counts, and the check-up button's link
// is the setup page's.
async function homePage() {
  await open(`${PAGES}/`);
  await page.getByText("BasaltDB is running").waitFor({ state: "visible" });
  const text = await page.locator("main").innerText();
  assert.match(text, /1 agent on 1 database/, "the home page counts the agent and its database");
  assert.ok(!text.includes(AGENT), "the home page never names the agent");
  const button = page.locator("#home-checks a").first();
  if ((await button.count()) === 0) throw new Error("the home page has no check-up button (#home-checks a)");
  const href = await button.getAttribute("href");
  assert.ok(href.startsWith(`${PAGES}/setup/#1.`), `the check-up button opens the setup page: ${href}`);
  ok("home page");
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
  await until("status ready, with engineRecord.state RECORDED", async () => {
    const s = await mcp.call("status");
    return s.data.ready === true && s.data.engineRecord?.state === "RECORDED";
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

// withdraw holds a write, opens its approval page, then withdraws it as the
// agent: the open page refuses the signature, the link shows Withdrawn with
// nothing to sign, and a write with its approvalId writes nothing.
const WITHDRAW_SQL = "update public.items set name = name || '-withdrawn' where id between 2 and 13";
const WITHDRAW_INTENT = "release e2e: a write the person cancels";
const WITHDRAW_REASON = "the person cancelled it";
const WITHDRAWN_LINE = `The agent withdrew this request: ${WITHDRAW_REASON}. Nothing changed.`;

async function withdraw() {
  const held = await mcp.call("write", { sql: WITHDRAW_SQL, intent: WITHDRAW_INTENT, runId });
  assert.ok(held.isError, `a 12-row write must be held: ${held.text}`);
  const url = find(held.data, "approvalUrl") ?? (held.text.match(/http:\/\/localhost:\d+\/approvals\/[^\s"\\]+/) ?? [])[0];
  const approvalId = find(held.data, "approvalId");
  assert.ok(url && approvalId, `the hold carries its link and approvalId: ${held.text}`);
  // The page is open before the agent withdraws.
  await open(url);
  await page.locator("#approve").waitFor({ state: "visible" });
  const out = await mcp.call("withdraw", { approvalId, reason: WITHDRAW_REASON });
  assert.ok(!out.isError, `withdraw failed: ${out.text}`);
  assert.equal(out.data.status, "WITHDRAWN", `the held write is withdrawn: ${out.text}`);
  assert.equal(out.data.personMessage, WITHDRAWN_LINE);
  // Signing on the page opened earlier is refused.
  await page.locator("#approve").click();
  await until("the open page to show Withdrawn", async () => (await page.locator("#state").textContent()) === "Withdrawn");
  assert.equal((await page.locator("#error-text").textContent()).trim(), WITHDRAWN_LINE);
  // The link opened again shows Withdrawn and nothing to sign.
  await open(url);
  await until("the link to show Withdrawn", async () => (await page.locator("#state").textContent()) === "Withdrawn");
  assert.equal((await page.locator("#error-text").textContent()).trim(), WITHDRAWN_LINE);
  assert.ok(!(await visible("#approve")), "a withdrawn approval has no sign button");
  const write = await mcp.call("write", { sql: WITHDRAW_SQL, intent: WITHDRAW_INTENT, runId, approvalId });
  assert.ok(write.isError, `a write with a withdrawn approvalId must be refused: ${write.text}`);
  assert.equal(find(write.data, "reason"), "WITHDRAWN", `refused as withdrawn: ${write.text}`);
  const pending = await mcp.call("list_pending", { runId });
  assert.ok(!pending.text.includes(approvalId), `list_pending no longer lists it: ${pending.text}`);
  const changed = await mcp.call("query", { sql: "select count(*) as n from public.items where name like '%-withdrawn'", runId });
  assert.equal(Number(changed.data.rows[0].n), 0, "nothing was written");
  ok("withdraw");
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

// Saves the engine log and the service state while the service still exists:
// removing BasaltDB deletes the log on macOS, so the exit trap in run.sh finds nothing.
function collectEngineLog() {
  run("sh", [path.join(DIR, "service.sh"), "collect", OUT], { stdio: "inherit" });
  for (const f of ["engine.log", "service-state.txt"]) {
    const file = path.join(OUT, f);
    if (fs.existsSync(file)) fs.writeFileSync(file, scrub(fs.readFileSync(file, "utf8")));
  }
}

// removeOnPage opens init's CHANGE link and removes BasaltDB on its page:
// one box (the admin string), one press. The button names the database and
// its host; no name is typed.
async function removeOnPage(init) {
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
  await page.locator("#remove-note").waitFor({ state: "visible" });
  assert.match((await page.locator("#run").innerText()).trim(), /^Remove BasaltDB from e2e on \S+$/, "the button names the database and its host");
  assert.equal(await page.locator("#confirm-remove").count(), 0, "no name to type");
  await page.locator("#run").click();
}

// linkJob is the job a setup link carries.
function linkJob(link) {
  const frag = link.split("#1.")[1];
  return JSON.parse(Buffer.from(frag, "base64url").toString("utf8"));
}

// jobListed reports whether the removal job is still loaded.
function jobListed() {
  try {
    if (process.platform === "darwin") run("sudo", ["launchctl", "print", "system/dev.basaltdb.remove"], { stdio: "ignore" });
    else run("systemctl", ["is-enabled", "--quiet", "basalt-remove.path"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

// engineAccount is the engine's OS user's uid, or "" when there is none.
function engineAccount() {
  try {
    return run("id", ["-u", process.platform === "darwin" ? "_basalt" : "basalt"]).trim();
  } catch {
    return "";
  }
}

const REMOVAL_JOB = process.platform === "darwin"
  ? ["/Library/LaunchDaemons/dev.basaltdb.remove.plist", "/usr/local/libexec/basalt-remove"]
  : ["/etc/systemd/system/basalt-remove.path", "/etc/systemd/system/basalt-remove.service", "/usr/libexec/basalt-remove"];
const CONFIG_DIR = process.platform === "darwin" ? "/Library/Application Support/Basalt" : "/etc/basalt";

let removedUid = "";

// remove: from the agent's basalt init to "BasaltDB is removed" on one page,
// with one press and no password: the removal job removes the engine from
// this computer, and the agent's status then answers REMOVED.
async function remove() {
  collectEngineLog();
  fs.writeFileSync(path.join(OUT, "mcp-stderr.txt"), scrub(mcp.stderr));
  mcp.close();
  mcp = null;
  assert.ok(jobListed(), "the install loaded the removal job");
  removedUid = engineAccount();
  assert.ok(removedUid, "the install made the engine's OS user");
  const init = basaltInit(["--agent", AGENT]);
  await removeOnPage(init);
  await page.locator("#removal-steps").waitFor({ state: "visible" });
  await until("the page to tick this computer", async () => (await page.locator("#done-title").innerText()).trim() === "BasaltDB is removed", 120000);
  const steps = await page.locator("#removal-steps li").allInnerTexts();
  assert.deepEqual(steps.map((t) => t.trim()), ["✓ Database e2e: BasaltDB removed", "✓ This computer: engine removed", "Your agent: drops its connection the next time you talk to it."]);
  assert.equal(await page.locator("#removal-mac").isVisible(), process.platform === "darwin" && /Macintosh/.test(await page.evaluate(() => navigator.userAgent)));
  assert.equal(await Promise.race([init.exited, sleep(120000).then(() => "timeout")]), 0, `init after the removal: ${init.err()}`);
  assert.match(init.err(), /the engine is removing itself from this computer/);
  assert.ok(!/administrator dialog/.test(init.err()), "no password dialog");

  await until("the removal job to finish", () => !serviceListed() && !jobListed(), 60000);
  assert.ok(!fs.existsSync(SERVICE_BIN), `the service's copy ${SERVICE_BIN} is deleted`);
  assert.ok(!fs.existsSync(CONFIG_DIR), `${CONFIG_DIR} is deleted`);
  for (const f of REMOVAL_JOB) assert.ok(!fs.existsSync(f), `the removal job removed itself: ${f}`);
  assert.ok(fs.existsSync(BIN), "the person's own basalt stays");
  if (process.platform === "darwin") assert.equal(engineAccount(), removedUid, "macOS keeps the hidden _basalt account");
  else assert.equal(engineAccount(), "", "Linux deletes the engine's OS user");

  // The agent's next status: no engine, no config folder, REMOVED.
  const args = mcpLine.split(/\s+/).slice(2);
  const after = new McpClient(BIN, args, { ...process.env, BASALT_UPDATE_CHECK: "0" });
  try {
    await after.initialize();
    const s = await after.call("status");
    const codes = (s.data.problems ?? []).map((p) => p.code);
    assert.deepEqual(codes, ["REMOVED"], `status after the removal: ${s.text}`);
    assert.match(JSON.stringify(s.data.problems[0].nextSteps), /Remove this MCP server/);
  } finally {
    after.close();
  }
  ok("remove");
}

// installAgain: the next setup after a removal is a first install. On
// macOS it takes over the _basalt account the removal kept; on Linux it
// makes a new one.
async function installAgain() {
  run("sh", [path.join(DIR, "service.sh"), "install", BIN], { stdio: "inherit" });
  assert.ok(jobListed(), "the new install loaded the removal job again");
  if (process.platform === "darwin") assert.equal(engineAccount(), removedUid, "the install reused _basalt");
  else assert.ok(engineAccount(), "the install made the engine's OS user again");
  const init = basaltInit(["--agent", AGENT, "--demo"]);
  const link = await initLink(init);
  assert.equal(await init.exited, 0, `init after the removal: ${init.err()}`);
  assert.equal(linkJob(link).job, "INSTALL");
  assert.equal(linkJob(link).demo, true);
  ok("install again");
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
  ["home-page", homePage],
  ["mcp", mcpSession],
  ["approve", approve],
  ["withdraw", withdraw],
  ["revert", revert],
  ["remove", remove],
  ["install-again", installAgain],
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
