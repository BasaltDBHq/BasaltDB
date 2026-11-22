// The local setup page (CONTRACT.md, The local setup page): the person
// confirms the job, types the admin connection string, checks, creates a
// passkey when the database has none for this computer, and runs the
// install. The string stays in a variable of this page only: never in
// storage, never in the URL, and cleared after the run.
import { ALG_ES256, b64urlDecode, CodeError, registrationResponseJson } from "./codec.js";
import { $, el, webauthnError } from "./page.js";
import { browserFetch } from "./transport.js";

export const CHECK_PATH = "/api/v1/setup/check";
export const RUN_PATH = "/api/v1/setup/run";
export const LINK_PREFIX = "1.";

// JOBS are the jobs this page runs: INSTALL on an engine with no config,
// UPDATE (the guard's missing migrations) and REMOVE (Basalt out of the
// agent's database) on one that has it.
export const JOBS = ["INSTALL", "UPDATE", "REMOVE", "CHANGE"];

// CHOICES are the jobs a CHANGE link offers: basalt init's link for an
// engine that is already set up. The page sends the one the person picks.
export const CHOICES = ["UPDATE", "REMOVE"];

// pickJob is the job the page runs for a link: the link's own, or for a
// CHANGE link the person's pick (null until they pick).
export function pickJob(link, picked) {
  if (link.job !== "CHANGE") return link;
  if (!CHOICES.includes(picked)) return null;
  return { ...link, job: picked };
}

// JOB_TEXT is each job's fixed words on the page.
export const JOB_TEXT = {
  INSTALL: {
    title: "Set up BasaltDB for your agent",
    intro: (agent) => `Your agent ${agent} asked to connect to a database. This page sets it up on this computer.`,
    run: "Set up",
    done: (agent) => `The agent ${agent} is set up. Tell it to go on; it connects with:`,
  },
  UPDATE: {
    title: "Update BasaltDB's guard",
    intro: (agent) => `Your agent ${agent} found that the guard in its database is older than BasaltDB on this computer. This page adds the guard's missing migrations, and nothing else.`,
    run: "Update the guard",
    done: (agent) => `The guard is updated. Tell the agent ${agent} to go on; it needs no restart.`,
  },
  CHANGE: {
    title: "Change BasaltDB on this computer",
    intro: (agent) => `BasaltDB is already set up for your agent ${agent}. Pick what to do: update the guard in its database, or remove BasaltDB.`,
    run: "",
    done: () => "",
  },
  REMOVE: {
    title: "Remove BasaltDB",
    intro: (agent) => `This page removes BasaltDB from the database of your agent ${agent}: the guard, the ledger of every action and the agents' roles. Nothing can undo it.`,
    run: "Remove BasaltDB",
    done: (agent) => `BasaltDB is removed from the database, and this computer's engine no longer serves ${agent}.`,
  },
};

const PROMPT_TIMEOUT_MS = 120000;
const MAX_FRAGMENT = 4096;
const AGENT_NAME = /^[a-z][a-z0-9_]{0,49}$/;
const OS_USER = /^[A-Za-z0-9._][A-Za-z0-9._-]{0,63}$/;

// localOrigin is the page's origin when it runs on the engine's own local
// pages (http://localhost:<port>); anywhere else, the page asks for nothing.
export function localOrigin(loc) {
  if (loc.protocol === "http:" && loc.hostname === "localhost" && loc.port !== "") {
    return `http://localhost:${loc.port}`;
  }
  throw new CodeError("The setup page runs only on this computer's own engine, at http://localhost:<port>.");
}

// parseSetupLink reads the job from the link's fragment: #1.<b64url(json)>
// with job, agent, osUser and demo, and nothing else.
export function parseSetupLink(hash) {
  const fragment = String(hash).replace(/^#/, "");
  if (fragment.length === 0 || fragment.length > MAX_FRAGMENT || !fragment.startsWith(LINK_PREFIX)) {
    throw new CodeError("This setup link is incomplete. Ask the agent for a new one.");
  }
  let job;
  try {
    job = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(b64urlDecode(fragment.slice(LINK_PREFIX.length))));
  } catch {
    throw new CodeError("This setup link is damaged. Ask the agent for a new one.");
  }
  const keys = job && typeof job === "object" && !Array.isArray(job) ? Object.keys(job).sort().join(",") : "";
  if (keys !== "agent,demo,job,osUser") {
    throw new CodeError("This setup link is damaged. Ask the agent for a new one.");
  }
  if (!JOBS.includes(job.job)) throw new CodeError("This setup link names a job this page does not run.");
  if (typeof job.agent !== "string" || !AGENT_NAME.test(job.agent)) throw new CodeError("This setup link names an agent whose name cannot be used.");
  if (typeof job.osUser !== "string" || !OS_USER.test(job.osUser)) throw new CodeError("This setup link names an OS user that cannot be used.");
  if (typeof job.demo !== "boolean") throw new CodeError("This setup link is damaged. Ask the agent for a new one.");
  if (job.demo && job.job !== "INSTALL") throw new CodeError("This setup link is damaged. Ask the agent for a new one.");
  return { job: job.job, agent: job.agent, osUser: job.osUser, demo: job.demo };
}

// setupRequest is the body of a check or run: the job and the string,
// plus the passkey on a run.
export function setupRequest(job, databaseUrl, extra = {}) {
  return { job: job.job, agent: job.agent, osUser: job.osUser, demo: job.demo, databaseUrl, ...extra };
}

export class SetupError extends Error {
  constructor(status, code, message) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

// postSetup posts body to the engine's own setup route.
export async function postSetup(fetchFn, path, body) {
  let resp;
  try {
    resp = await fetchFn(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      credentials: "omit",
      cache: "no-store",
      referrerPolicy: "no-referrer",
    });
  } catch {
    throw new SetupError(0, "", "The engine on this computer did not answer. Check it is running, then try again.");
  }
  let payload = {};
  try {
    payload = await resp.json();
  } catch {
    // An answer that is not JSON: say so below.
  }
  if (!resp.ok) {
    throw new SetupError(resp.status, String(payload.code || ""), String(payload.message || `The engine answered ${resp.status}.`));
  }
  return payload;
}

// passkeyFields creates the passkey with the challenge check handed over.
async function createPasskey(challenge, rpId) {
  const cred = await navigator.credentials.create({
    publicKey: {
      challenge: b64urlDecode(challenge.challenge),
      rp: { id: rpId, name: "BasaltDB" },
      user: { id: b64urlDecode(challenge.userId), name: challenge.userName, displayName: challenge.displayName },
      pubKeyCredParams: [{ type: "public-key", alg: ALG_ES256 }],
      authenticatorSelection: { residentKey: "required", requireResidentKey: true, userVerification: "required" },
      attestation: "none",
      timeout: PROMPT_TIMEOUT_MS,
    },
  });
  const r = cred.response;
  if (typeof r.getPublicKey !== "function" || typeof r.getAuthenticatorData !== "function") {
    throw new Error("this browser is too old to export the passkey's public key");
  }
  return JSON.parse(
    registrationResponseJson({
      credentialId: new Uint8Array(cred.rawId),
      clientDataJson: new Uint8Array(r.clientDataJSON),
      authenticatorData: new Uint8Array(r.getAuthenticatorData()),
      publicKey: new Uint8Array(r.getPublicKey()),
      publicKeyAlgorithm: r.getPublicKeyAlgorithm(),
    }),
  );
}

function list(id, lines) {
  const ul = $(id);
  ul.replaceChildren(...lines.map((line) => el("li", "", line)));
  ul.hidden = lines.length === 0;
}

function showError(err) {
  $("status").textContent = err.message;
}

async function main() {
  let link;
  try {
    localOrigin(window.location);
    link = parseSetupLink(window.location.hash);
  } catch (err) {
    $("error-text").textContent = err.message;
    $("error").hidden = false;
    return;
  }
  let job = pickJob(link, "");
  let text = JOB_TEXT[link.job];
  const showJob = () => {
    text = JOB_TEXT[job ? job.job : link.job];
    document.title = text.title;
    $("title").textContent = text.title;
    $("intro").textContent = JOB_TEXT[link.job].intro(link.agent);
    $("remove-confirm").hidden = !job || job.job !== "REMOVE";
  };
  showJob();
  $("job-os-user").textContent = link.osUser;
  $("job-demo").hidden = !link.demo;
  $("choice").hidden = link.job !== "CHANGE";
  $("main").hidden = false;
  const fetchFn = browserFetch;
  let databaseUrl = "";
  let checked = null;
  const confirmed = () => job !== null && $("confirm-os-user").checked && (job.job !== "REMOVE" || $("confirm-remove").checked);
  const sync = () => {
    $("check").disabled = !confirmed() || $("database-url").value === "";
  };
  $("confirm-os-user").addEventListener("change", sync);
  for (const name of CHOICES) {
    $("choice-" + name.toLowerCase()).addEventListener("change", () => {
      job = pickJob(link, name);
      checked = null;
      $("review").hidden = true;
      showJob();
      sync();
    });
  }
  $("confirm-remove").addEventListener("change", () => {
    if (checked) $("run").disabled = !confirmed();
  });
  $("database-url").addEventListener("input", () => {
    checked = null;
    $("review").hidden = true;
    sync();
  });
  $("check").addEventListener("click", async () => {
    $("check").disabled = true;
    $("status").textContent = "Checking your database…";
    databaseUrl = $("database-url").value;
    try {
      checked = await postSetup(fetchFn, CHECK_PATH, setupRequest(job, databaseUrl));
    } catch (err) {
      showError(err);
      sync();
      return;
    }
    $("status").textContent = "";
    $("database").textContent = checked.database;
    list("lines", checked.lines);
    list("notes", checked.notes);
    $("sql").textContent = checked.sql;
    $("run").textContent = checked.passkeyNeeded ? "Create passkey and set up" : text.run;
    $("review").hidden = false;
    $("run").disabled = !confirmed();
    sync();
  });
  $("run").addEventListener("click", async () => {
    if (!checked || !confirmed()) return;
    $("run").disabled = true;
    let extra = {};
    try {
      if (checked.passkeyNeeded) {
        $("status").textContent = "Create the passkey in your browser's prompt.";
        extra = { challenge: checked.challenge, passkey: await createPasskey(checked.challenge, "localhost") };
      }
    } catch (err) {
      $("status").textContent = webauthnError(err);
      $("run").disabled = false;
      return;
    }
    $("status").textContent = "Setting up…";
    try {
      const done = await postSetup(fetchFn, RUN_PATH, setupRequest(job, databaseUrl, extra));
      databaseUrl = "";
      $("database-url").value = "";
      $("status").textContent = "";
      showDone(job, done);
    } catch (err) {
      showError(err);
      $("run").disabled = false;
    }
  });
}

function showDone(job, done) {
  $("main").hidden = true;
  $("done").hidden = false;
  $("done-text").textContent = JOB_TEXT[job.job].done(done.agent || job.agent);
  $("mcp-command").textContent = done.mcpCommand || "";
  $("mcp-command").hidden = job.job !== "INSTALL" || !done.mcpCommand;
  list("done-lines", done.lines || []);
  list("warnings", done.warnings || []);
  const codes = (done.passkeys || []).map((p) => `${p.label || "Passkey"}: ${p.checkCode}`);
  list("check-codes", codes);
  $("check-codes-box").hidden = codes.length === 0;
}

if (typeof document !== "undefined") main();
