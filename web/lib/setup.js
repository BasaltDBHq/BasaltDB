// The local setup page (CONTRACT.md, The local setup page): the person
// confirms the job, types the admin connection string, checks, creates a
// passkey when the database has none for this computer, and runs the
// install. The string stays in a variable of this page only: never in
// storage, never in the URL, and cleared after the run.
import { ALG_ES256, b64urlDecode, CodeError, registrationResponseJson } from "./codec.js";
import { $, el, webauthnError } from "./page.js";
import { answersFor, ENTITY_WORDS, fingerprintText, hostOf, Labels, MAX_LABELS, restQuestion, tableName, trustRootFrom } from "./picks.js";
import { labelRow } from "./pickviews.js";
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

// agentProbe asks the engine, before the admin-string field opens, whether
// the link's agent is one of its own: a check with no admin string, which
// the engine refuses CONNECTION_STRING_REFUSED only after the agent passed
// (CONTRACT.md, The local setup page). It returns null when the agent is
// this engine's, else the engine's message. An INSTALL link needs none.
export async function agentProbe(fetchFn, link) {
  if (link.job === "INSTALL") return null;
  const job = link.job === "CHANGE" ? { ...link, job: "UPDATE" } : link;
  try {
    await postSetup(fetchFn, CHECK_PATH, setupRequest(job, ""));
  } catch (err) {
    if (err.code === "CONNECTION_STRING_REFUSED") return null;
    return err.message;
  }
  return null;
}

// answerFits reports whether a check's answer, asked for job asked, is
// still the one to run: a pick changed during the check makes it stale.
export function answerFits(asked, current) {
  return asked !== null && asked === current;
}

// removeConfirmed reports whether the typed text is the database name the
// removal's check named, exactly: the Remove button waits for it.
export function removeConfirmed(typed, checked) {
  return Boolean(checked) && typeof checked.database === "string" && checked.database !== "" && typed === checked.database;
}

// setupRequest is the body of a check or run: the job and the string,
// plus the passkey on a run.
export function setupRequest(job, databaseUrl, extra = {}) {
  return { job: job.job, agent: job.agent, osUser: job.osUser, demo: job.demo, databaseUrl, ...extra };
}

// SetupError is a refused call: its HTTP status, the engine's code and
// fixed message, and on a CERTIFICATE_NOT_VERIFIED the certificate
// authority the person may trust (checked by trustRootFrom), else null.
export class SetupError extends Error {
  constructor(status, code, message, trustRoot = null) {
    super(message);
    this.status = status;
    this.code = code;
    this.trustRoot = trustRoot;
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
    const code = String(payload.code || "");
    throw new SetupError(resp.status, code, String(payload.message || `The engine answered ${resp.status}.`), trustRootFrom(code, payload.trustRoot));
  }
  return payload;
}

// ---- The install of a real database (CONTRACT.md, The install of a real
// database) ----
//
// The person types the admin string, trusts the certificate when asked,
// ticks the tables with the access of each, labels columns or skips that,
// and approves once. Install holds that state with the admin string in a
// private field. Every change of the string, the certificate, a tick, an
// access or a label drops the last full check, and the run sends exactly
// the request that check was made with, plus its challenge: the page
// always shows what the challenge binds.

export const ACCESS = ["WRITE", "READ"];

// The words a label has on the page, as the connect page's label picker
// shows them.
const CLASS_WORDS = { PUBLIC: "Not personal", FREE_TEXT: "Free text", SECRET: "Secret" };
const SUGGESTED = new Set(["PUBLIC", "FREE_TEXT", "SECRET", "IDENTIFIER"]);
const REGION = /^[A-Z]{2}$/;
const ENTITY = /^[A-Z][A-Z_]{0,31}$/;

// labelWords is a label as the page names it: "Personal: email", "Secret".
export function labelWords(label) {
  if (label.class === "IDENTIFIER") {
    const words = ENTITY_WORDS[label.entityType] ?? String(label.entityType || "").toLowerCase();
    return label.entityType === "PHONE" && label.phoneRegion ? `Personal: ${words} (${label.phoneRegion})` : `Personal: ${words}`;
  }
  return CLASS_WORDS[label.class] ?? "";
}

// suggestionOf is a column's suggestion as a label the person may accept,
// with the classifier's reason, or null when the check made none or it is
// not one the page can read. The page never applies it by itself.
export function suggestionOf(c) {
  const cls = c?.suggestedClass;
  if (typeof cls !== "string" || !SUGGESTED.has(cls)) return null;
  const label = { class: cls, entityType: "", phoneRegion: "" };
  if (cls === "IDENTIFIER") {
    if (typeof c.suggestedEntityType !== "string" || !ENTITY.test(c.suggestedEntityType)) return null;
    label.entityType = c.suggestedEntityType;
    if (label.entityType === "PHONE" && typeof c.suggestedPhoneRegion === "string" && REGION.test(c.suggestedPhoneRegion)) {
      label.phoneRegion = c.suggestedPhoneRegion;
    }
  }
  const reason = typeof c.reason === "string" ? c.reason : "";
  return { label, reason, words: labelWords(label) };
}

// trustView is what the certificate step shows for trustRoot on host, the
// fingerprint first: the person checks it against the provider's console.
export function trustView(host, trustRoot) {
  return {
    host,
    fingerprint: fingerprintText(trustRoot.sha256),
    subject: trustRoot.subject,
    expires: trustRoot.expiresAt.slice(0, 10),
    question: "Trust it for this host only?",
  };
}

const strings = (v) => (Array.isArray(v) ? v.filter((x) => typeof x === "string") : []);
const isRestEntry = (e) => e.class === "PUBLIC" && e.was?.class === "UNCLASSIFIED";

// Install is the state of one real install. job is the link's job (an
// INSTALL without demo). A call whose answer arrives after the state it
// was made for changed returns null and changes nothing.
export class Install {
  #databaseUrl = "";
  // #trustRoot is the SHA-256 the person trusted, as the refusal sent it
  // (lowercase hex), sent with every check and the run.
  #trustRoot = "";
  #gen = 0;

  constructor(fetchFn, job) {
    if (job.job !== "INSTALL" || job.demo) throw new Error("Install runs only an INSTALL without the sample database");
    this.fetchFn = fetchFn;
    this.job = job;
    this.#reset();
  }

  #reset() {
    this.listing = null; // the listing check's answer
    this.asking = null; // the certificate authority offered, until answered
    this.picks = new Map(); // ticked table -> access
    this.labels = null;
    this.labelMode = "skip";
    this.columnsMore = false;
    this.checked = null; // { request, answer } of the last full check
  }

  // hostHint is the host the admin string names, for the certificate
  // question: the host alone, never the string.
  get hostHint() {
    return hostOf(this.#databaseUrl);
  }

  // trustRoot is the SHA-256 the person trusted, "" when none.
  get trustRoot() {
    return this.#trustRoot;
  }

  #stale() {
    this.#gen++;
    this.checked = null;
  }

  // list sends the listing check for databaseUrl: a new string starts
  // over, with no certificate trusted. On a certificate to trust it keeps
  // the string and sets asking; the error is thrown either way.
  async list(databaseUrl) {
    this.#stale();
    this.#databaseUrl = databaseUrl;
    this.#trustRoot = "";
    this.#reset();
    return this.#list();
  }

  async #list() {
    const gen = this.#gen;
    let answer;
    try {
      answer = await postSetup(this.fetchFn, CHECK_PATH, this.#request({}));
    } catch (err) {
      if (gen === this.#gen && err instanceof SetupError && err.trustRoot && this.#trustRoot === "") this.asking = err.trustRoot;
      throw err;
    }
    if (gen !== this.#gen) return null;
    this.listing = {
      database: String(answer.database ?? ""),
      tables: (Array.isArray(answer.tables) ? answer.tables : []).filter((t) => typeof t?.table === "string").map((t) => ({ table: t.table, canWrite: t.canWrite === true })),
      excluded: (Array.isArray(answer.excluded) ? answer.excluded : []).filter((e) => typeof e?.table === "string").map((e) => ({ table: e.table, owner: String(e.owner ?? "") })),
      tablesMore: answer.tablesMore === true,
      notes: strings(answer.notes),
      lines: strings(answer.lines),
    };
    // As on the connect page, every table starts ticked, with write access
    // when it can have it.
    this.picks = new Map(this.listing.tables.map((t) => [t.table, t.canWrite ? "WRITE" : "READ"]));
    return this.listing;
  }

  // trust answers yes to the certificate asked about: the listing is sent
  // again with its SHA-256.
  async trust() {
    if (!this.asking) throw new Error("no certificate to trust");
    this.#stale();
    this.#trustRoot = this.asking.sha256;
    this.asking = null;
    return this.#list();
  }

  // cancelTrust answers no: the admin string is dropped.
  cancelTrust() {
    this.forget();
  }

  // forget drops the admin string and everything checked with it.
  forget() {
    this.#stale();
    this.#databaseUrl = "";
    this.#trustRoot = "";
    this.#reset();
  }

  #listed(table) {
    return this.listing?.tables.find((t) => t.table === table) ?? null;
  }

  // tick picks or drops a listed table.
  tick(table, on) {
    const t = this.#listed(table);
    if (!t) return;
    this.#stale();
    if (on) this.picks.set(table, this.picks.get(table) ?? (t.canWrite ? "WRITE" : "READ"));
    else this.picks.delete(table);
  }

  // setAccess sets a ticked table's access; WRITE only where canWrite.
  setAccess(table, access) {
    const t = this.#listed(table);
    if (!t || !this.picks.has(table) || !ACCESS.includes(access) || (access === "WRITE" && !t.canWrite)) return;
    this.#stale();
    this.picks.set(table, access);
  }

  // picked are the ticked tables, in the listing's order.
  picked() {
    return (this.listing?.tables ?? []).filter((t) => this.picks.has(t.table)).map((t) => t.table);
  }

  // setLabel records a label for a column of a picked table (null clears
  // the choice); acceptSuggestion takes the column's suggestion.
  setLabel(table, column, label) {
    if (!this.labels) return;
    this.#stale();
    this.labels.set(table, column, label);
  }

  acceptSuggestion(c) {
    const s = suggestionOf(c);
    if (s) this.setLabel(c.table, c.column, s.label);
  }

  // setLabelMode is how the labels go: "skip" (nothing), "changes" (what
  // the person set) or "rest" (and the rest as not personal).
  setLabelMode(mode) {
    if (!["skip", "changes", "rest"].includes(mode) || mode === this.labelMode) return;
    this.#stale();
    this.labelMode = mode;
  }

  // labelsProblem is what stops the labels step, "" when nothing does.
  labelsProblem() {
    return this.labels ? this.labels.problem(this.picked()) : "";
  }

  // restPlan is what "Mark the rest as not personal" marks. A column the
  // classifier suggests is personal or secret, and that the person has not
  // labeled, is left out: the page never applies what the person did not
  // accept. When the rest cannot go as entries (columns past the 500
  // listed, or more than 500 labels), it goes as restPublic, which marks
  // every column without a label; then the suggested ones are named in the
  // confirm, so the person accepts that too.
  restPlan() {
    const picked = this.picked();
    const unlabeled = this.labels ? this.labels.unlabeled(picked) : [];
    const suggested = unlabeled.filter((c) => {
      const s = suggestionOf(c);
      return s !== null && (s.label.class === "IDENTIFIER" || s.label.class === "SECRET");
    });
    const rest = unlabeled.filter((c) => !suggested.includes(c));
    const changes = this.labels ? this.labels.changes(picked).length : 0;
    const restPublic = this.columnsMore || changes + rest.length > MAX_LABELS;
    return { rest, suggested, restPublic };
  }

  // restQuestion is the confirm before "Mark the rest as not personal".
  restQuestion() {
    const p = this.restPlan();
    const names = (cols) => cols.map((c) => `${tableName(c.table)}.${c.column}`).join(", ");
    if (p.restPublic) {
      const more = this.columnsMore ? ", the ones not listed here too" : "";
      const flagged = p.suggested.length > 0 ? ` This includes ${names(p.suggested)}, suggested as personal or secret.` : "";
      return `Mark every column without a label in the ticked tables as not personal${more}?${flagged}`;
    }
    const left = p.suggested.length > 0 ? ` Left out: ${names(p.suggested)}, suggested as personal or secret; label them or leave them blank.` : "";
    return restQuestion(p.rest) + left;
  }

  #labelFields() {
    if (!this.labels) return {};
    if (this.labelMode !== "rest") return this.labels.request(this.picked(), this.labelMode);
    const out = this.labels.request(this.picked(), "changes");
    const p = this.restPlan();
    if (p.restPublic) return { ...out, restPublic: true };
    const rest = p.rest.map((c) => ({ table: c.table, column: c.column, class: "PUBLIC", was: { class: "UNCLASSIFIED" } }));
    const all = [...(out.columnClasses ?? []), ...rest];
    return all.length > 0 ? { columnClasses: all } : {};
  }

  #request(extra) {
    const out = setupRequest(this.job, this.#databaseUrl, extra);
    if (this.#trustRoot !== "") out.trustRoot = this.#trustRoot;
    return out;
  }

  // planned is the request a full check is sent with: the picks, the
  // labels and the certificate as they are now.
  planned() {
    const tables = this.picked().map((table) => ({ table, access: this.picks.get(table) }));
    return this.#request({ tables, ...this.#labelFields() });
  }

  // check sends the full check for the state as it is now. Its answer is
  // what the page shows and what the run sends; null when the state
  // changed meanwhile.
  async check() {
    if (this.picked().length === 0) throw new SetupError(0, "NO_TABLES", "Tick at least one table.");
    this.#stale();
    const gen = this.#gen;
    const request = this.planned();
    const answer = await postSetup(this.fetchFn, CHECK_PATH, request);
    if (gen !== this.#gen) return null;
    if (!answer.challenge) throw new SetupError(0, "", "The engine sent a check this page cannot run.");
    this.#adoptColumns(answer.columns, answer.columnsMore === true);
    this.checked = { request: structuredClone(request), answer };
    return this.view();
  }

  // #adoptColumns keeps the person's labels for the columns still listed.
  #adoptColumns(columns, more) {
    const next = new Labels(columns);
    if (this.labels) {
      const known = new Set(next.columns.map((c) => `${c.table}\u0000${c.column}`));
      for (const [k, v] of this.labels.chosen) if (known.has(k)) next.chosen.set(k, v);
    }
    this.labels = next;
    this.columnsMore = more;
  }

  // view is what the approval shows: exactly what the last check was made
  // for and answered, or null when there is none for the state now.
  view() {
    if (!this.checked) return null;
    const { request, answer } = this.checked;
    return {
      database: String(answer.database ?? ""),
      tables: request.tables.map((t) => ({ ...t, name: tableName(t.table) })),
      // "The rest as not personal" goes as PUBLIC entries for columns that
      // had no class, or as restPublic; the person's own labels are the rest.
      labeled: (request.columnClasses ?? []).filter((e) => !isRestEntry(e)).length,
      restPublic: request.restPublic === true || (request.columnClasses ?? []).some(isRestEntry),
      trustRoot: request.trustRoot ?? "",
      lines: strings(answer.lines),
      notes: strings(answer.notes),
      sql: String(answer.sql ?? ""),
      questions: Array.isArray(answer.questions) ? answer.questions : [],
      passkeyNeeded: answer.passkeyNeeded === true,
    };
  }

  // runRequest is the run's body: the checked request unchanged, the
  // page's ALL_ROWS answer to each question the check asked, the
  // challenge, and the passkey when one was made.
  runRequest(passkey) {
    if (!this.checked) throw new Error("nothing checked");
    const { request, answer } = this.checked;
    const out = { ...structuredClone(request), challenge: answer.challenge };
    const answers = answersFor(answer.questions, null).map((a) => ({ table: a.table, choice: a.choice }));
    if (answers.length > 0) out.answers = answers;
    if (passkey) out.passkey = passkey;
    return out;
  }

  // run makes the passkey when the check asked for one (makePasskey gets
  // the challenge), then runs what was checked. The admin string is
  // dropped once the run answered.
  async run(makePasskey) {
    if (!this.checked) throw new SetupError(0, "", "Check again: something changed since the last check.");
    const gen = this.#gen;
    const { answer } = this.checked;
    const passkey = answer.passkeyNeeded ? await makePasskey(answer.challenge) : undefined;
    if (gen !== this.#gen || !this.checked) throw new SetupError(0, "", "Check again: something changed since the last check.");
    const done = await postSetup(this.fetchFn, RUN_PATH, this.runRequest(passkey));
    this.forget();
    return done;
  }
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
  if (link.job === "INSTALL" && !link.demo) {
    startReal(link, { fetchFn: browserFetch, makePasskey: (c) => createPasskey(c, "localhost") });
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
  $("admin-panel").hidden = true;
  const refused = await agentProbe(fetchFn, link);
  if (refused !== null) {
    $("main").hidden = true;
    $("error-text").textContent = refused;
    $("error").hidden = false;
    return;
  }
  $("admin-panel").hidden = false;
  let databaseUrl = "";
  let checked = null;
  let checkedFor = null;
  const setChoices = (disabled) => {
    for (const name of CHOICES) $("choice-" + name.toLowerCase()).disabled = disabled;
  };
  const confirmed = () => job !== null && $("confirm-os-user").checked;
  // A removal also needs the database's name typed as the check named it.
  const runnable = () => confirmed() && checked !== null && (job.job !== "REMOVE" || removeConfirmed($("confirm-remove").value, checked));
  const sync = () => {
    $("check").disabled = !confirmed() || $("database-url").value === "";
  };
  $("confirm-os-user").addEventListener("change", sync);
  for (const name of CHOICES) {
    $("choice-" + name.toLowerCase()).addEventListener("change", () => {
      job = pickJob(link, name);
      checked = null;
      checkedFor = null;
      $("confirm-remove").value = "";
      $("review").hidden = true;
      showJob();
      sync();
    });
  }
  $("confirm-remove").addEventListener("input", () => {
    if (checked) $("run").disabled = !runnable();
  });
  $("database-url").addEventListener("input", () => {
    checked = null;
    $("confirm-remove").value = "";
    $("review").hidden = true;
    sync();
  });
  $("check").addEventListener("click", async () => {
    $("check").disabled = true;
    $("status").textContent = "Checking your database…";
    databaseUrl = $("database-url").value;
    const asked = job;
    setChoices(true);
    let answer;
    try {
      answer = await postSetup(fetchFn, CHECK_PATH, setupRequest(asked, databaseUrl));
    } catch (err) {
      setChoices(false);
      showError(err);
      sync();
      return;
    }
    setChoices(false);
    if (!answerFits(asked, job)) {
      $("status").textContent = "";
      sync();
      return;
    }
    checked = answer;
    checkedFor = asked;
    $("status").textContent = "";
    $("database").textContent = checked.database;
    $("remove-name").textContent = checked.database;
    $("confirm-remove").value = "";
    list("lines", checked.lines);
    list("notes", checked.notes);
    $("sql").textContent = checked.sql;
    $("run").textContent = checked.passkeyNeeded ? "Create passkey and set up" : text.run;
    $("review").hidden = false;
    $("run").disabled = !runnable();
    sync();
  });
  $("run").addEventListener("click", async () => {
    if (!checked || !runnable() || !answerFits(checkedFor, job)) return;
    const running = checkedFor;
    $("run").disabled = true;
    setChoices(true);
    let extra = running.job === "REMOVE" ? { confirmName: $("confirm-remove").value } : {};
    try {
      if (checked.passkeyNeeded) {
        $("status").textContent = "Create the passkey in your browser's prompt.";
        extra = { challenge: checked.challenge, passkey: await createPasskey(checked.challenge, "localhost") };
      }
    } catch (err) {
      $("status").textContent = webauthnError(err);
      $("run").disabled = false;
      setChoices(false);
      return;
    }
    $("status").textContent = "Setting up…";
    try {
      const done = await postSetup(fetchFn, RUN_PATH, setupRequest(running, databaseUrl, extra));
      databaseUrl = "";
      $("database-url").value = "";
      $("status").textContent = "";
      showDone(running, done);
    } catch (err) {
      showError(err);
      $("run").disabled = false;
      setChoices(false);
    }
  });
}

// ---- The real install's screens: the connect page's steps, on this page ----

const SCREENS = ["s-user", "s-paste", "s-trust", "s-checking", "s-tables", "s-labels", "s-approve"];
const PROGRESS = { "s-user": 1, "s-paste": 2, "s-trust": 2, "s-checking": 2, "s-tables": 3, "s-labels": 4, "s-approve": 5 };

function show(id, on = true) {
  $(id).hidden = !on;
}

function setText(id, text) {
  $(id).textContent = text;
}

// A refusal that the run cannot get past with the same check: the page
// goes back to the connection string, as the connect page does.
const RECHECK = { TABLES_CHANGED: "see the tables as they are now", CLASSES_CHANGED: "see the labels as they are now" };

// startReal runs the install of a real database for link on the page.
// env has fetchFn and makePasskey (the challenge to a registration). It
// returns the Install, for the tests.
export function startReal(link, env) {
  const install = new Install(env.fetchFn, link);
  const agent = link.agent;
  let screen = "s-user";
  let busy = false;

  const go = (name) => {
    screen = name;
    for (const id of SCREENS) show(id, id === name);
    const step = PROGRESS[name] ?? 0;
    show("progress", step > 0);
    const bar = $("progress");
    for (let i = 0; i < bar.children.length; i++) bar.children[i].className = i < step ? "on" : "";
    bar.setAttribute("aria-label", `Step ${step} of 5`);
    show("back", !busy && name !== "s-user" && name !== "s-checking");
  };

  // ---- 1: the agent's OS user ----
  setText("user-intro", JOB_TEXT.INSTALL.intro(agent));
  setText("user-name", link.osUser);
  $("user-next").disabled = !$("user-confirm").checked;
  $("user-confirm").addEventListener("change", () => {
    $("user-next").disabled = !$("user-confirm").checked;
  });
  $("user-next").addEventListener("click", () => {
    if ($("user-confirm").checked) showPaste("");
  });

  // ---- 2: the connection string, and the certificate when asked ----
  const hideString = () => {
    $("paste-url").type = "password";
    $("reveal").setAttribute("aria-pressed", "false");
    $("reveal").setAttribute("aria-label", "Show connection string");
  };
  const showPaste = (problem) => {
    hideString();
    setText("paste-error", problem);
    show("paste-error", problem !== "");
    go("s-paste");
  };
  $("reveal").addEventListener("click", () => {
    const shown = $("paste-url").type === "password";
    $("paste-url").type = shown ? "text" : "password";
    $("reveal").setAttribute("aria-pressed", shown ? "true" : "false");
    $("reveal").setAttribute("aria-label", shown ? "Hide connection string" : "Show connection string");
  });
  $("paste-url").addEventListener("paste", hideString);

  const checking = () => {
    $("chk-login").className = "check wait";
    setText("chk-login", "Signing in to the database");
    go("s-checking");
  };
  const listed = (answer) => {
    if (answer === null) return;
    showTables();
  };
  const listFailed = (err) => {
    if (install.asking) showTrust("");
    else {
      install.forget();
      showPaste(err.message);
    }
  };

  $("paste-next").addEventListener("click", async () => {
    const typed = $("paste-url").value;
    if (typed.trim() === "") return;
    $("paste-url").value = "";
    hideString();
    checking();
    let answer;
    try {
      answer = await install.list(typed);
    } catch (err) {
      listFailed(err);
      return;
    }
    listed(answer);
  });

  // The fingerprint first and large, the subject the server sent as text.
  const showTrust = (problem) => {
    const v = trustView(install.hostHint, install.asking);
    setText("trust-host", `${v.host} presents a certificate authority Basalt does not know.`);
    setText("trust-fp", v.fingerprint);
    setText("trust-subject", v.subject);
    setText("trust-expires", v.expires);
    setText("trust-error", problem);
    show("trust-error", problem !== "");
    go("s-trust");
  };
  $("trust-go").addEventListener("click", async () => {
    checking();
    let answer;
    try {
      answer = await install.trust();
    } catch (err) {
      install.forget();
      showPaste(err.message);
      return;
    }
    listed(answer);
  });
  $("trust-cancel").addEventListener("click", () => {
    install.cancelTrust();
    showPaste("");
  });

  // ---- 3: the tables, each with its access ----
  const showTables = () => {
    const l = install.listing;
    setText("db-label", `This is the database ${agent} will use`);
    setText("db-name", l.database);
    const list = $("tables");
    list.replaceChildren();
    for (const t of l.tables) list.appendChild(tableRow(t));
    countTables();
    setText("tables-note", `${agent} gets every row of the ticked tables, to read or to read and change as each one is set, and can't see the unticked ones.`);
    show("tables-more", l.tablesMore);
    const words = (e) => `${tableName(e.table)} (${e.owner === "unsupported name" ? "a name BasaltDB cannot use" : "owned by another role"})`;
    setText("excluded", l.excluded.length > 0 ? `Not offered: ${l.excluded.map(words).join(", ")}` : "");
    show("excluded", l.excluded.length > 0);
    list2("tables-notes", l.notes);
    show("tables-error", false);
    go("s-tables");
  };

  // tableRow is a tick, the name and the access switch (Read / Read +
  // change); a table without a primary key can only be read.
  const tableRow = (t) => {
    const item = el("div", "tick");
    const box = el("input");
    box.type = "checkbox";
    box.checked = install.picks.has(t.table);
    box.value = t.table;
    box.setAttribute("aria-label", `Give ${agent} ${tableName(t.table)}`);
    item.appendChild(box);
    item.appendChild(el("span", "mono", tableName(t.table)));
    if (!t.canWrite) {
      item.appendChild(el("span", "muted", "read only (no row ID)"));
      box.addEventListener("change", () => {
        install.tick(t.table, box.checked);
        countTables();
      });
      return item;
    }
    const seg = el("span", "seg");
    seg.setAttribute("role", "group");
    seg.setAttribute("aria-label", `What ${agent} may do in ${tableName(t.table)}`);
    const opts = [["READ", "Read"], ["WRITE", "Read + change"]].map(([access, words]) => {
      const b = el("button", "", words);
      b.type = "button";
      b.value = access;
      b.addEventListener("click", () => {
        install.setAccess(t.table, access);
        paint();
      });
      seg.appendChild(b);
      return b;
    });
    const paint = () => {
      const now = install.picks.get(t.table);
      for (const b of opts) {
        b.setAttribute("aria-pressed", String(now === b.value));
        b.disabled = !install.picks.has(t.table);
      }
    };
    box.addEventListener("change", () => {
      install.tick(t.table, box.checked);
      paint();
      countTables();
    });
    paint();
    item.appendChild(seg);
    return item;
  };

  const countTables = () => {
    const n = install.listing.tables.length;
    const m = install.picked().length;
    setText("tables-count", `${m} of ${n}`);
    $("tables-next").disabled = m === 0;
    setText("tables-error", m === 0 ? "Tick at least one table." : "");
    show("tables-error", m === 0);
  };

  // recheck sends the full check when the state changed since the last
  // one, and shows its refusal on the screen at hand.
  const recheck = async (errorId) => {
    if (install.view()) return true;
    busy = true;
    show("back", false);
    try {
      return (await install.check()) !== null;
    } catch (err) {
      setText(errorId, err.message);
      show(errorId);
      return false;
    } finally {
      busy = false;
      show("back", true);
    }
  };

  const labelsApply = () => install.labels !== null && install.labels.of(install.picked()).length > 0;

  $("tables-next").addEventListener("click", async () => {
    $("tables-next").disabled = true;
    const ok = await recheck("tables-error");
    $("tables-next").disabled = install.picked().length === 0;
    if (!ok) return;
    if (labelsApply()) showLabels();
    else showApprove();
  });

  // ---- 4: personal data ----
  const choices = {
    current: (c) => install.labels.current(c),
    set: (table, column, label) => install.setLabel(table, column, label),
  };
  const showLabels = () => {
    const box = $("label-tables");
    box.replaceChildren();
    const byTable = new Map();
    for (const c of install.labels.of(install.picked())) {
      if (!byTable.has(c.table)) byTable.set(c.table, []);
      byTable.get(c.table).push(c);
    }
    let first = true;
    for (const [table, cols] of byTable) {
      const d = el("details", "label-table");
      d.open = first;
      first = false;
      const head = el("summary");
      head.appendChild(el("span", "mono", tableName(table)));
      head.appendChild(el("span", "muted", ` ${cols.length} ${cols.length === 1 ? "column" : "columns"}`));
      d.appendChild(head);
      for (const c of cols) d.appendChild(labelRow(c, choices, restCount, suggestionOf(c)));
      box.appendChild(d);
    }
    setText("unlabeled-warn", `Columns without a label aren't masked: ${agent} reads them as they are, and they can be sent to its AI provider. They'll be blocked once PII protection ships, until you label them.`);
    show("labels-error", false);
    show("rest-confirm", false);
    restCount();
    go("s-labels");
  };
  const restCount = () => {
    const p = install.restPlan();
    $("labels-rest").disabled = p.rest.length === 0 && !p.restPublic;
  };
  const labelsProblem = (text) => {
    setText("labels-error", text);
    show("labels-error", text !== "");
    return text !== "";
  };
  const labelsDone = async (mode) => {
    install.setLabelMode(mode);
    if (await recheck("labels-error")) showApprove();
  };
  $("labels-next").addEventListener("click", () => {
    if (labelsProblem(install.labelsProblem())) return;
    return labelsDone("changes");
  });
  $("labels-rest").addEventListener("click", () => {
    if (labelsProblem(install.labelsProblem())) return;
    setText("rest-question", install.restQuestion());
    show("rest-confirm");
  });
  $("rest-yes").addEventListener("click", () => {
    show("rest-confirm", false);
    return labelsDone("rest");
  });
  $("rest-no").addEventListener("click", () => show("rest-confirm", false));
  $("labels-skip").addEventListener("click", () => {
    show("labels-error", false);
    return labelsDone("skip");
  });

  // ---- 5: approve: exactly what the last check was made for ----
  const showApprove = () => {
    const v = install.view();
    setText("ap-agent", agent);
    setText("ap-db", v.database);
    const facts = $("ap-facts");
    facts.replaceChildren();
    const fact = (label, value) => {
      if (!value) return;
      const row = el("li");
      row.appendChild(el("strong", "", label + ": "));
      row.appendChild(el("span", "", value));
      facts.appendChild(row);
    };
    fact("Changes rows in", v.tables.filter((t) => t.access === "WRITE").map((t) => t.name).join(", "));
    fact("Reads", v.tables.filter((t) => t.access === "READ").map((t) => t.name).join(", "));
    const rls = v.questions.map((q) => tableName(String(q.table)));
    fact("Every row, with row-level security on", rls.join(", "));
    const labels = v.labeled > 0 ? `${v.labeled} ${v.labeled === 1 ? "column" : "columns"} marked` : "";
    fact("Personal data", [labels, v.restPublic ? "the rest not personal" : ""].filter(Boolean).join(" · "));
    fact("Certificate authority trusted for this host", v.trustRoot ? fingerprintText(v.trustRoot) : "");
    list2("ap-lines", v.lines);
    list2("ap-notes", v.notes);
    setText("ap-sql", v.sql);
    setText("approve", v.passkeyNeeded ? "Set up with passkey" : "Set up");
    setText("approve-status", "");
    go("s-approve");
  };

  $("approve").addEventListener("click", async () => {
    if (!install.view()) return showTables();
    busy = true;
    $("approve").disabled = true;
    show("back", false);
    if (install.view().passkeyNeeded) setText("approve-status", "Create the passkey in your browser's prompt.");
    try {
      let done;
      try {
        done = await install.run(async (c) => {
          const passkey = await env.makePasskey(c);
          setText("approve-status", "Setting up…");
          return passkey;
        });
      } catch (err) {
        busy = false;
        ranRefused(err);
        return;
      }
      showDone(link, done);
    } finally {
      busy = false;
      $("approve").disabled = false;
      if (screen === "s-approve") show("back");
    }
  });

  const ranRefused = (err) => {
    if (!(err instanceof SetupError)) {
      setText("approve-status", webauthnError(err));
      return;
    }
    const again = RECHECK[err.code] ?? (err.code.startsWith("CHALLENGE_") || err.code === "PASSKEY_INVALID" ? "start again" : "");
    if (again) {
      install.forget();
      showPaste(`${err.message}\nPaste the connection string again to ${again}.`);
      return;
    }
    setText("approve-status", err.message);
  };

  // ---- Back ----
  $("back").addEventListener("click", () => {
    if (busy) return;
    if (screen === "s-paste") go("s-user");
    else if (screen === "s-trust" || screen === "s-tables") {
      install.forget();
      showPaste("");
    } else if (screen === "s-labels") showTables();
    else if (screen === "s-approve") {
      if (labelsApply()) showLabels();
      else showTables();
    }
  });

  document.body.classList.add("connect-page");
  show("flow");
  go("s-user");
  return install;
}

function list2(id, lines) {
  const ul = $(id);
  ul.replaceChildren(...lines.map((line) => el("li", "", line)));
  ul.hidden = lines.length === 0;
}

function showDone(job, done) {
  $("main").hidden = true;
  $("flow").hidden = true;
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
