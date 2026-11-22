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
  if (job.job !== "INSTALL") throw new CodeError("This setup link names a job this page does not run.");
  if (typeof job.agent !== "string" || !AGENT_NAME.test(job.agent)) throw new CodeError("This setup link names an agent whose name cannot be used.");
  if (typeof job.osUser !== "string" || !OS_USER.test(job.osUser)) throw new CodeError("This setup link names an OS user that cannot be used.");
  if (typeof job.demo !== "boolean") throw new CodeError("This setup link is damaged. Ask the agent for a new one.");
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
  let job;
  try {
    localOrigin(window.location);
    job = parseSetupLink(window.location.hash);
  } catch (err) {
    $("error-text").textContent = err.message;
    $("error").hidden = false;
    return;
  }
  $("job-agent").textContent = job.agent;
  $("job-os-user").textContent = job.osUser;
  $("job-demo").hidden = !job.demo;
  $("main").hidden = false;
  const fetchFn = browserFetch;
  let databaseUrl = "";
  let checked = null;
  const confirmed = () => $("confirm-os-user").checked;
  const sync = () => {
    $("check").disabled = !confirmed() || $("database-url").value === "";
  };
  $("confirm-os-user").addEventListener("change", sync);
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
    $("run").textContent = checked.passkeyNeeded ? "Create passkey and set up" : "Set up";
    $("review").hidden = false;
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
      showDone(done);
    } catch (err) {
      showError(err);
      $("run").disabled = false;
    }
  });
}

function showDone(done) {
  $("main").hidden = true;
  $("done").hidden = false;
  $("done-agent").textContent = done.agent;
  $("mcp-command").textContent = done.mcpCommand;
  list("warnings", done.warnings || []);
  const codes = (done.passkeys || []).map((p) => `${p.label || "Passkey"}: ${p.checkCode}`);
  list("check-codes", codes);
  $("check-codes-box").hidden = codes.length === 0;
}

if (typeof document !== "undefined") main();
