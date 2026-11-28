// The local setup page (CONTRACT.md, The local setup page): the person
// confirms the job, types the admin connection string, checks, creates a
// passkey when the database has none for this computer, and runs the
// install. The string stays in a variable of this page only: never in
// storage, never in the URL, and cleared after the run.
import { ALG_ES256, b64urlDecode, CodeError, registrationResponseJson } from "./codec.js";
import { $, busy as working, controlsOf, el, webauthnError } from "./page.js";
import { answersFor, ENTITY_WORDS, fingerprintText, Labels, MAX_LABELS, restNote, tableName, trustRootFrom } from "./picks.js";
import { labelRow } from "./pickviews.js";
import { confirmView, factsDiffer, paintConfirm, sslModeOf, stringFacts, withVerifyFull } from "./confirm.js";
import { ALL_SET, checkView, columnKey, laterText, passkeyItems, PASSKEYS_NOTE, RESET, signalRemoved, targetView } from "./doctor.js";
import { browserFetch } from "./transport.js";

export const CHECK_PATH = "/api/v1/setup/check";
export const RUN_PATH = "/api/v1/setup/run";
export const DOCTOR_PATH = "/api/v1/setup/doctor";
export const ENGINE_PATH = "/api/v1/setup/engine";
export const NOT_MINE_PATH = "/api/v1/setup/not-mine";
// HEALTHZ_PATH is the engine's health route: after a removal of its last
// agent the page watches it stop answering, when the removal job stopped
// the engine.
export const HEALTHZ_PATH = "/healthz";
export const LINK_PREFIX = "1.";

// JOBS are the jobs this page runs: INSTALL on an engine with no config,
// UPDATE (the guard's missing migrations) and REMOVE (BasaltDB out of the
// agent's database, then off this computer) on one that has it. CHANGE is a
// link only: the pick of Update or Remove.
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

// JOB_TEXT is each job's fixed words on the page. hint is the note under
// the admin connection string box: what the string is used for in this job.
const KEPT = " It is never stored, and the agent never sees it.";
export const JOB_TEXT = {
  INSTALL: {
    title: "Set up BasaltDB for your agent",
    intro: (agent) => `Your agent ${agent} asked to connect to a database. This page sets it up on this computer.`,
    hint: "Used once, on this computer, to set up the database."+KEPT,
    run: "Set up",
    done: (agent) => `The agent ${agent} is set up. Tell it to go on; it connects with:`,
  },
  UPDATE: {
    title: "Update BasaltDB's guard",
    intro: (agent) => `Your agent ${agent} found that the guard in its database is older than BasaltDB on this computer. This page adds the guard's missing migrations, and nothing else.`,
    hint: "Used once, on this computer, to update the guard in the database."+KEPT,
    run: "Update the guard",
    done: (agent) => `The guard is updated. Tell the agent ${agent} to go on; it needs no restart.`,
  },
  CHANGE: {
    title: "Change BasaltDB on this computer",
    intro: (agent) => `BasaltDB is already set up for your agent ${agent}. Pick what to do: update the guard in its database, or remove BasaltDB.`,
    hint: "Used once, on this computer, for the job you pick."+KEPT,
    run: "",
    done: () => "",
  },
  REMOVE: {
    title: "Remove BasaltDB",
    intro: (agent) => `This page removes BasaltDB from the database of your agent ${agent}: the guard, the ledger of every action and the agents' roles. Nothing can undo it.`,
    hint: "Used once, on this computer, to remove BasaltDB from the database."+KEPT,
    run: "Remove BasaltDB",
    done: (agent) => `BasaltDB is removed from the database, and this computer's engine no longer serves ${agent}.`,
    removed: "BasaltDB is removed",
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
  // demo is in the link only when it is true: a missing one is false.
  if (keys !== "agent,job,osUser" && keys !== "agent,demo,job,osUser") {
    throw new CodeError("This setup link is damaged. Ask the agent for a new one.");
  }
  if (!JOBS.includes(job.job)) throw new CodeError("This setup link names a job this page does not run.");
  if (typeof job.agent !== "string" || !AGENT_NAME.test(job.agent)) throw new CodeError("This setup link names an agent whose name cannot be used.");
  if (typeof job.osUser !== "string" || !OS_USER.test(job.osUser)) throw new CodeError("This setup link names an OS user that cannot be used.");
  if (job.demo === undefined) job.demo = false;
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
    // A REMOVE link on an engine the page removed: the engine asked its
    // removal job again, and the page watches it stop.
    if (link.job === "REMOVE" && err.code === ENGINE_REMOVED) return ENGINE_REMOVED;
    return err.message;
  }
  return null;
}

// ENGINE_REMOVED is the engine's answer once a removal took its last agent.
export const ENGINE_REMOVED = "ENGINE_REMOVED";

// answerFits reports whether a check's answer, asked for job asked, is
// still the one to run: a pick changed during the check makes it stale.
export function answerFits(asked, current) {
  return asked !== null && asked === current;
}

// removeConfirmed reports whether the typed text is the database name the
// check named, exactly: the button of an install that replaces an old one
// waits for it. A removal needs none: its admin string is the confirmation.
export function removeConfirmed(typed, checked) {
  return Boolean(checked) && typeof checked.database === "string" && checked.database !== "" && typed === checked.database;
}

// removeButtonText is the Remove button of a checked removal: it names the
// database and its host, which the admin string opens.
export function removeButtonText(checked) {
  return checked.host ? `Remove BasaltDB from ${checked.database} on ${checked.host}` : `Remove BasaltDB from ${checked.database}`;
}

// REMOVAL_TEXT is the checklist after a removal (CONTRACT.md, The local
// setup page, Removing the engine service): the database, this computer and
// the agent's connection.
export const REMOVAL_TEXT = {
  database: (db) => (db ? `✓ Removed from the database ${db}` : "✓ Removed from the database"),
  removing: "Removing from this computer…",
  removed: "✓ Removed from this computer",
  stuck: "This computer: the engine is still running. Ask your agent to run basalt init --remove: your computer asks for your password once and removes the rest.",
  kept: "This computer: the engine stays, serving your other agents.",
  notAsked: "This computer: the engine stays, serving no agent (the warning below says why).",
  agent: "Agent connection: your agent drops it the next time you talk to it.",
  agentKept: "Agent connection: this agent's calls to that database now fail; your other agents go on.",
  done: (db) => (db ? `From the database ${db} and from this computer. You can close this tab.` : "From the database and from this computer. You can close this tab."),
};

// removalSteps are the checklist's lines; computer is "removing",
// "removed", "stuck", "kept" or "notAsked".
export function removalSteps(database, computer) {
  return [REMOVAL_TEXT.database(database), REMOVAL_TEXT[computer], computer === "kept" ? REMOVAL_TEXT.agentKept : REMOVAL_TEXT.agent];
}

// REMOVAL_WAIT_MS bounds the wait for the engine to stop after a removal,
// and REMOVAL_POLL_MS is how often the page asks.
export const REMOVAL_WAIT_MS = 60000;

// CHECK_DELAY_MS is how long a removal's page waits after the admin string
// changed before it checks it by itself: a paste is one change.
export const CHECK_DELAY_MS = 400;
export const REMOVAL_POLL_MS = 1000;

// engineGone waits, up to REMOVAL_WAIT_MS, for the engine's health route
// to stop answering: true once a request fails (the removal job stopped
// the engine), false when the time is up. It sends no body.
export async function engineGone(fetchFn, { sleep = defaultSleep, now = () => Date.now(), waitMs = REMOVAL_WAIT_MS } = {}) {
  const until = now() + waitMs;
  for (;;) {
    try {
      await fetchFn(HEALTHZ_PATH, { method: "GET", cache: "no-store" });
    } catch {
      return true;
    }
    if (now() >= until) return false;
    await sleep(REMOVAL_POLL_MS);
  }
}

function defaultSleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// isMac reports whether the browser runs on macOS, which keeps the
// engine's system account after a removal.
export function isMac(nav) {
  return /Macintosh|Mac OS X/.test(nav?.userAgent || "");
}

// REPLACE_TITLE and REPLACE_RUN are the words of an install that replaces
// a BasaltDB install too old to update (CONTRACT.md, The local setup page,
// An older install): the first screen's title and the last button.
export const REPLACE_TITLE = "This BasaltDB install is too old to update";
export const REPLACE_RUN = "Remove the old install and set up";

// replaceOf is a check answer's replace, its fields checked; null when the
// install replaces nothing.
export function replaceOf(r) {
  if (!r || typeof r !== "object" || !Number.isInteger(r.guardVersion) || !Number.isInteger(r.floor) || typeof r.this !== "string") return null;
  return { guardVersion: r.guardVersion, floor: r.floor, release: typeof r.release === "string" ? r.release : "", this: r.this };
}

// replaceLines are the first screen's words, built from the replace's data
// only, never a fixed release name: the engine's setup.ReplaceLines after
// its title.
export function replaceLines(r) {
  return [
    r.release !== "" ? `It was set up by BasaltDB ${r.release} (guard version ${r.guardVersion}).` : `It has guard version ${r.guardVersion}.`,
    `BasaltDB ${r.this} needs guard version ${r.floor} or later.`,
    "Setting up removes the old install first: its agents' history and undo, their held approvals and the passkeys go with it. Your tables and rows stay.",
  ];
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
  constructor(status, code, message, trustRoot = null, pinned = "") {
    super(message);
    this.status = status;
    this.code = code;
    this.trustRoot = trustRoot;
    // pinned is the SHA-256 pinned now, on a TRUST check's refusal of a
    // changed certificate ("" otherwise).
    this.pinned = pinned;
  }
}

const SHA256_HEX = /^[0-9a-f]{64}$/;

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
    const pinned = typeof payload.pinned === "string" && SHA256_HEX.test(payload.pinned) ? payload.pinned : "";
    throw new SetupError(resp.status, code, String(payload.message || `The engine answered ${resp.status}.`), trustRootFrom(code, payload.trustRoot), pinned);
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

  // stringFacts are what the admin string names (database, host, port,
  // user), for the confirm step before any login: never the password.
  get stringFacts() {
    return stringFacts(this.#databaseUrl);
  }

  // trustRoot is the SHA-256 the person trusted, "" when none.
  get trustRoot() {
    return this.#trustRoot;
  }

  // sslMode is the sslmode of the string the page holds, for the warning
  // of a certificate not checked.
  get sslMode() {
    return sslModeOf(this.#databaseUrl);
  }

  // checkCertificate is the person's click on Check the certificate: the
  // listing is sent again with only the string's sslmode replaced by
  // verify-full, and on a pass the page holds that string, so the agent's
  // connection string gets it too. On any refusal the pasted string and its
  // listing stay, as if nothing was clicked, and the error is thrown.
  async checkCertificate() {
    const pasted = this.#databaseUrl;
    const { listing, picks } = this;
    this.#stale();
    this.#databaseUrl = withVerifyFull(pasted);
    try {
      return await this.#list();
    } catch (err) {
      this.#stale();
      this.#databaseUrl = pasted;
      this.listing = listing;
      this.picks = picks;
      this.asking = null;
      throw err;
    }
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
      // The confirm step's facts, as the engine read them on its login.
      facts: {
        database: String(answer.database ?? ""),
        host: String(answer.host ?? ""),
        port: Number.isInteger(answer.port) ? answer.port : 0,
        user: String(answer.sessionUser ?? ""),
      },
      certificate: answer.certificate && typeof answer.certificate === "object" ? answer.certificate : null,
      // replace: the database's install is too old to update, and the run
      // removes it first (replaceOf); null otherwise.
      replace: replaceOf(answer.replace),
    };
    // As on the connect page, every table starts ticked, with write access
    // when it can have it.
    this.picks = new Map(this.listing.tables.map((t) => [t.table, t.canWrite ? "WRITE" : "READ"]));
    return this.listing;
  }

  // trust answers yes to the certificate asked about, the person's click on
  // the confirm step: the listing is sent again with its SHA-256, and only
  // this sends a trustRoot.
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

  // restNote is the note under "Mark them as not personal".
  restNote() {
    const p = this.restPlan();
    const personal = p.suggested.map((c) => `${tableName(c.table)}.${c.column}`);
    const count = p.restPublic ? p.rest.length + p.suggested.length : p.rest.length;
    return restNote({ count, forced: p.restPublic, more: this.columnsMore, personal });
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
      replace: replaceOf(answer.replace),
    };
  }

  // runRequest is the run's body: the checked request unchanged, the
  // page's ALL_ROWS answer to each question the check asked, the
  // challenge, the passkey when one was made, and, for an install that
  // replaces an old one, the database name the person typed.
  runRequest(passkey, confirmName = "") {
    if (!this.checked) throw new Error("nothing checked");
    const { request, answer } = this.checked;
    const out = { ...structuredClone(request), challenge: answer.challenge };
    const answers = answersFor(answer.questions, null).map((a) => ({ table: a.table, choice: a.choice }));
    if (answers.length > 0) out.answers = answers;
    if (passkey) out.passkey = passkey;
    if (replaceOf(answer.replace)) out.confirmName = confirmName;
    return out;
  }

  // run makes the passkey when the check asked for one (makePasskey gets
  // the challenge), then runs what was checked. The admin string is
  // dropped once the run answered.
  async run(makePasskey, confirmName = "") {
    if (!this.checked) throw new SetupError(0, "", "Check again: something changed since the last check.");
    const gen = this.#gen;
    const { answer } = this.checked;
    if (replaceOf(answer.replace) && !removeConfirmed(confirmName, answer)) throw new SetupError(0, "ANSWERS_INVALID", "Type the database's name exactly as the page shows it.");
    const passkey = answer.passkeyNeeded ? await makePasskey(answer.challenge) : undefined;
    if (gen !== this.#gen || !this.checked) throw new SetupError(0, "", "Check again: something changed since the last check.");
    const done = await postSetup(this.fetchFn, RUN_PATH, this.runRequest(passkey, confirmName));
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

function main() {
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
  if (link.job === "CHANGE") {
    startUpdate(link, {
      fetchFn: browserFetch,
      origin: localOrigin(window.location),
      makePasskey: (c) => createPasskey(c, "localhost"),
      pkc: globalThis.PublicKeyCredential,
      now: () => new Date(),
      onPick: (picked) => startJob(link, picked),
    });
    return;
  }
  startJob(link, "");
}

// startJob is the page of an UPDATE, REMOVE or demo INSTALL link, and the
// pick of Update the guard and Remove BasaltDB that the Update check opens
// for a CHANGE link (preset picks one).
// env (tests) hands in the fetch and the passkey prompt.
export async function startJob(link, preset, env = {}) {
  $("flow").hidden = true;
  let job = pickJob(link, preset);
  let text = JOB_TEXT[link.job];
  const showJob = () => {
    text = JOB_TEXT[job ? job.job : link.job];
    document.title = text.title;
    $("title").textContent = text.title;
    $("intro").textContent = JOB_TEXT[link.job].intro(link.agent);
    $("admin-hint").textContent = text.hint;
    // A removal is one box and one press: its admin string is the
    // confirmation, the check runs once the string is pasted, and it asks
    // nothing about the OS user.
    const removing = job?.job === "REMOVE";
    $("remove-note").hidden = !removing;
    $("os-user-panel").hidden = removing;
    $("check").hidden = removing;
  };
  showJob();
  $("job-os-user").textContent = link.osUser;
  $("job-demo").hidden = !link.demo;
  $("choice").hidden = link.job !== "CHANGE";
  if (job && link.job === "CHANGE") $("choice-" + job.job.toLowerCase()).checked = true;
  $("main").hidden = false;
  const fetchFn = env.fetchFn ?? browserFetch;
  $("admin-panel").hidden = true;
  const refused = await agentProbe(fetchFn, link);
  if (refused === ENGINE_REMOVED) {
    // Ask the engine to ask its removal job again: a run with no admin
    // string, which it answers ENGINE_REMOVED.
    try {
      await postSetup(fetchFn, RUN_PATH, setupRequest(link, ""));
    } catch {
      // ENGINE_REMOVED, or no engine any more: the checklist shows which.
    }
    await showRemoved(link, { agent: link.agent, lines: [], warnings: [], passkeys: [], engineRemoved: true, engineRemoving: true }, "", fetchFn, env);
    return;
  }
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
  const confirmed = () => job !== null && (job.job === "REMOVE" || $("confirm-os-user").checked);
  // An install that replaces an old one also needs the database's name
  // typed as the check named it; a removal is confirmed by its admin string.
  const typedName = () => $("confirm-replace").value;
  const runnable = () => confirmed() && checked !== null && (!replaceOf(checked.replace) || removeConfirmed(typedName(), checked));
  const sync = () => {
    $("check").disabled = !confirmed() || $("database-url").value === "";
  };
  $("confirm-os-user").addEventListener("change", sync);
  for (const name of CHOICES) {
    $("choice-" + name.toLowerCase()).addEventListener("change", () => {
      job = pickJob(link, name);
      checked = null;
      checkedFor = null;
      $("review").hidden = true;
      showJob();
      sync();
    });
  }
  $("confirm-replace").addEventListener("input", () => {
    if (checked) $("run").disabled = !runnable();
  });
  let autoCheck = null;
  // checkSeq numbers the checks: only the newest one's answer or refusal
  // is shown. A removal checks by itself on every change of the box, so a
  // check for an older string may still run when the next one starts.
  let checkSeq = 0;
  // checking counts the checks in flight: a stale one gives the choices
  // back only when no newer check still holds them.
  let checking = 0;
  $("database-url").addEventListener("input", () => {
    checked = null;
    $("review").hidden = true;
    $("remove-target").hidden = true;
    // A check still running is for an older string: its answer is dropped.
    checkSeq++;
    $("status").textContent = "";
    sync();
    clearTimeout(autoCheck);
    if (job?.job === "REMOVE" && $("database-url").value !== "") autoCheck = setTimeout(runCheck, env.checkDelayMs ?? CHECK_DELAY_MS);
  });
  const runCheck = async () => {
    if ($("database-url").value === "" || $("run").getAttribute("aria-busy") === "true") return;
    const auto = job?.job === "REMOVE";
    const done = auto ? () => {} : working($("check"), "Checking…");
    if (!done) return;
    const seq = ++checkSeq;
    checking++;
    $("status").textContent = "Checking your database…";
    const url = $("database-url").value;
    databaseUrl = url;
    const asked = job;
    setChoices(true);
    let answer;
    try {
      answer = await postSetup(fetchFn, CHECK_PATH, setupRequest(asked, url));
    } catch (err) {
      done();
      checking--;
      if (seq !== checkSeq) {
        if (checking === 0) setChoices(false);
        return;
      }
      setChoices(false);
      if (auto && err.code === "BUSY") {
        // The engine still runs the check of an earlier string.
        autoCheck = setTimeout(runCheck, env.checkDelayMs ?? CHECK_DELAY_MS);
        return;
      }
      showError(err);
      sync();
      return;
    }
    done();
    checking--;
    if (seq !== checkSeq) {
      if (checking === 0) setChoices(false);
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
    if (asked.job === "REMOVE") {
      $("remove-target").textContent = checked.host ? `It opens ${checked.database} on ${checked.host}.` : `It opens ${checked.database}.`;
      $("remove-target").hidden = false;
    }
    const replace = replaceOf(checked.replace);
    $("replace-confirm").hidden = replace === null;
    $("replace-name").textContent = checked.database;
    $("confirm-replace").value = "";
    list("lines", replace ? [REPLACE_TITLE + ".", ...replaceLines(replace), ...checked.lines] : checked.lines);
    list("notes", checked.notes);
    $("sql").textContent = checked.sql;
    $("run").textContent = replace ? REPLACE_RUN : checked.passkeyNeeded ? "Create passkey and set up" : asked.job === "REMOVE" ? removeButtonText(checked) : text.run;
    // The passkey note shows only under a button that asks for a passkey:
    // a removal and an update ask for none.
    $("run-passkey-note").hidden = !checked.passkeyNeeded;
    $("review").hidden = false;
    $("run").disabled = !runnable();
    sync();
  };
  $("check").addEventListener("click", runCheck);
  $("run").addEventListener("click", async () => {
    if (!checked || !runnable() || !answerFits(checkedFor, job)) return;
    const running = checkedFor;
    const workText = running.job === "REMOVE" ? "Removing BasaltDB…" : running.job === "UPDATE" ? "Updating…" : "Setting up…";
    // Everything that would start or change this run is off until it ends:
    // the Check button, the connection string, the OS-user box and the
    // replace box. A check that was due is dropped.
    const locks = [$("check"), $("database-url"), $("confirm-os-user"), $("confirm-replace")];
    const stop = working($("run"), checked.passkeyNeeded ? "Waiting for your passkey…" : workText, locks);
    if (!stop) return;
    clearTimeout(autoCheck);
    setChoices(true);
    let extra = replaceOf(checked.replace) ? { confirmName: typedName() } : {};
    try {
      if (checked.passkeyNeeded) {
        $("status").textContent = "Create the passkey in your browser's prompt.";
        extra = { ...extra, challenge: checked.challenge, passkey: await (env.makePasskey ?? ((c) => createPasskey(c, "localhost")))(checked.challenge) };
      }
    } catch (err) {
      $("status").textContent = webauthnError(err);
      stop();
      setChoices(false);
      return;
    }
    stop.label(workText);
    $("status").textContent = running.job === "REMOVE" ? "Removing…" : "Setting up…";
    try {
      const done = await postSetup(fetchFn, RUN_PATH, setupRequest(running, databaseUrl, extra));
      databaseUrl = "";
      $("database-url").value = "";
      $("status").textContent = "";
      stop();
      $("run").disabled = true;
      // The job is done: nothing on the page starts it again.
      for (const n of locks) n.disabled = true;
      if (running.job === "REMOVE") {
        showRemoved(running, done, checked.database, fetchFn);
        return;
      }
      showDone(running, done);
    } catch (err) {
      stop();
      showError(err);
      setChoices(false);
    }
  });
}

// ---- The real install's screens: the connect page's steps, on this page ----

const SCREENS = ["s-user", "s-paste", "s-confirm", "s-checking", "s-replace", "s-tables", "s-labels", "s-approve"];
const PROGRESS = { "s-user": 1, "s-paste": 2, "s-confirm": 2, "s-checking": 2, "s-replace": 2, "s-tables": 3, "s-labels": 4, "s-approve": 5 };

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
  setText("user-intro", "Your agent asked to connect to a database. This page sets it up on this computer.");
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
  // listed goes on once the listing answered: to the confirm step, or, once
  // the person confirmed and trusted the certificate, to the tables.
  const listed = (answer, confirmed = true) => {
    if (answer === null) return;
    if (!confirmed) showConfirm();
    else if (answer.replace) showReplace(answer.replace);
    else showTables();
  };
  // The first screen of an install that replaces one too old to update:
  // what the engine found, in words from its data, then the normal steps.
  const showReplace = (replace) => {
    setText("replace-title", REPLACE_TITLE);
    list2("replace-lines", replaceLines(replace));
    go("s-replace");
  };
  $("replace-next").addEventListener("click", () => showTables());
  const listFailed = (err) => {
    if (install.asking) showConfirm();
    else {
      install.forget();
      showPaste(err.message);
    }
  };

  $("paste-next").addEventListener("click", async () => {
    const typed = $("paste-url").value;
    if (typed.trim() === "") return;
    const done = working($("paste-next"), "Checking…");
    if (!done) return;
    $("paste-url").value = "";
    hideString();
    mismatch = "";
    checking();
    let answer;
    try {
      answer = await install.list(typed);
    } catch (err) {
      done();
      listFailed(err);
      return;
    }
    done();
    listed(answer, false);
  });

  // ---- 2b: Is this your database? One action: the database, its host,
  // who the string signs in as and the certificate. For a certificate
  // authority the provider runs itself, Yes is also the trust in it. ----
  let shownFacts = null; // what the confirm step showed
  // mismatch is the provider's name while the step says Check the
  // certificate found a certificate that is not the provider's.
  let mismatch = "";
  const showConfirm = () => {
    const view = install.asking
      ? confirmView({ facts: install.stringFacts, asking: install.asking })
      : confirmView({ facts: install.listing.facts, certificate: install.listing.certificate, sslMode: install.sslMode, mismatch });
    shownFacts = view.facts;
    paintConfirm(document, view, { box: true });
    show("confirm-error", false);
    go("s-confirm");
  };
  // Check the certificate: the same string with sslmode=verify-full. A
  // pass shows the step again, verified by the provider; a certificate that
  // is not the provider's sent nothing, and the person goes back or
  // continues with the string as pasted.
  $("confirm-check").addEventListener("click", async () => {
    if (screen !== "s-confirm" || install.asking || !install.listing) return;
    const provider = String(install.listing.certificate?.provider ?? "");
    const done = working($("confirm-check"), "Checking the certificate…");
    if (!done) return;
    checking();
    let answer;
    try {
      answer = await install.checkCertificate();
    } catch (err) {
      done();
      if (err instanceof SetupError && err.code === "CERTIFICATE_NOT_VERIFIED" && provider !== "") {
        mismatch = provider;
        return showConfirm();
      }
      install.forget();
      showPaste(err.message);
      return;
    }
    // Verified now: the step again, with the provider's check mark.
    done();
    if (answer !== null) showConfirm();
  });
  $("confirm-go").addEventListener("click", async () => {
    if (screen !== "s-confirm") return;
    if (mismatch) {
      // Go back: the string is dropped, as No, go back drops it.
      mismatch = "";
      install.cancelTrust();
      return showPaste("");
    }
    if (!install.asking) return listed(install.listing);
    const done = working($("confirm-go"), "Checking…");
    if (!done) return;
    checking();
    let answer;
    try {
      answer = await install.trust();
    } catch (err) {
      done();
      install.forget();
      showPaste(err.message);
      return;
    }
    // The step showed what the string names; once signed in, the engine
    // says what it reached. Anything else is asked again.
    done();
    if (answer !== null && factsDiffer(shownFacts, install.listing.facts)) return showConfirm();
    listed(answer);
  });
  $("confirm-back").addEventListener("click", () => {
    if (screen !== "s-confirm") return;
    if (mismatch) {
      // Continue without checking: the string as pasted, its sslmode kept.
      mismatch = "";
      return listed(install.listing);
    }
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
    const done = working($("tables-next"), "Checking…");
    if (!done) return;
    const ok = await recheck("tables-error");
    done();
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
    $("rest-mark").checked = install.labelMode === "rest";
    $("rest-leave").checked = install.labelMode !== "rest";
    restCount();
    go("s-labels");
  };
  // restCount shows the choice for the columns left unlabeled only while
  // "Mark them as not personal" would mark some, and the note under it
  // while it is chosen: the choice is the confirmation.
  const restCount = () => {
    const p = install.restPlan();
    show("rest-choice", p.rest.length > 0 || p.restPublic);
    showNote("rest-note", $("rest-mark").checked ? install.restNote() : []);
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
  // Continue keeps the labels the person picked, and with "Mark them as
  // not personal" marks the rest as its note says.
  $("labels-next").addEventListener("click", () => {
    if (labelsProblem(install.labelsProblem())) return;
    return labelsDone(!$("rest-choice").hidden && $("rest-mark").checked ? "rest" : "changes");
  });
  for (const id of ["rest-leave", "rest-mark"]) $(id).addEventListener("change", restCount);

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
    setText("approve", v.replace ? REPLACE_RUN : v.passkeyNeeded ? "Set up with passkey" : "Set up");
    // Replacing an old install removes it first: the database's name,
    // typed, is the confirmation, as for Remove BasaltDB.
    show("ap-replace", v.replace !== null);
    setText("ap-confirm-name", v.database);
    $("ap-confirm").value = "";
    $("approve").disabled = v.replace !== null;
    setText("approve-status", "");
    show("ap-passkey-note", v.passkeyNeeded);
    go("s-approve");
  };
  $("ap-confirm").addEventListener("input", () => {
    const v = install.view();
    if (v && v.replace) $("approve").disabled = busy || !removeConfirmed($("ap-confirm").value, v);
  });

  $("approve").addEventListener("click", async () => {
    if (!install.view()) return showTables();
    const stop = working($("approve"), install.view().passkeyNeeded ? "Waiting for your passkey…" : "Setting up…");
    if (!stop) return;
    busy = true;
    show("back", false);
    if (install.view().passkeyNeeded) setText("approve-status", "Create the passkey in your browser's prompt.");
    try {
      let done;
      try {
        done = await install.run(async (c) => {
          const passkey = await env.makePasskey(c);
          stop.label("Setting up…");
          setText("approve-status", "Setting up…");
          return passkey;
        }, $("ap-confirm").value);
      } catch (err) {
        busy = false;
        stop();
        ranRefused(err);
        return;
      }
      stop();
      showDone(link, done);
    } finally {
      busy = false;
      stop();
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
    else if (screen === "s-confirm" || screen === "s-replace" || screen === "s-tables") {
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

// ---- The Update check (CONTRACT.md, The Update check) ----
//
// A CHANGE link opens on the check: doctor reads what needs the person
// with the agent's own credential, and each fix is a setup job on check
// and run with the admin connection string. The page asks for the string
// at the first fix, keeps it in a private field for the fixes that follow,
// and drops it on Cancel, after a refusal of the string, and when the page
// closes.

// STRING_REFUSED are the refusals of the admin string itself: the person
// types it again.
const STRING_REFUSED = new Set(["CONNECTION_STRING_REFUSED", "LOGIN_FAILED", "TARGET_MISMATCH"]);

// UpdateCheck is the state of one Update check: the link's agent, the last
// doctor answer and the admin string, held only here.
export class UpdateCheck {
  #databaseUrl = "";

  constructor(fetchFn, link) {
    if (link.job !== "CHANGE") throw new Error("UpdateCheck runs only a CHANGE link");
    this.fetchFn = fetchFn;
    this.link = link;
    this.answer = null;
  }

  // doctor sends the check: the agent and its OS user, never the string.
  async doctor() {
    this.answer = await postSetup(this.fetchFn, DOCTOR_PATH, { agent: this.link.agent, osUser: this.link.osUser });
    return this.answer;
  }

  // engine asks what the engine is set up with (Not your database), and
  // notMine tells it the person answered No, for basalt init, which asks
  // for the administrator password. Neither takes the string or names an
  // agent, and neither changes anything.
  engine() {
    return postSetup(this.fetchFn, ENGINE_PATH, {});
  }

  notMine() {
    return postSetup(this.fetchFn, NOT_MINE_PATH, {});
  }

  get hasString() {
    return this.#databaseUrl !== "";
  }

  setString(databaseUrl) {
    this.#databaseUrl = String(databaseUrl);
  }

  // stringFacts are what the admin string names, for the confirm step of a
  // new certificate, which comes before any login: never the password.
  get stringFacts() {
    return stringFacts(this.#databaseUrl);
  }

  // forget drops the admin string.
  forget() {
    this.#databaseUrl = "";
  }

  // request is a fix's body: the job, the link's agent, the string and the
  // fix's own fields.
  request(job, extra = {}) {
    return setupRequest({ job, agent: this.link.agent, osUser: this.link.osUser, demo: false }, this.#databaseUrl, extra);
  }

  async #post(path, job, extra) {
    if (!this.hasString) throw new SetupError(0, "", "Paste the admin connection string first.");
    try {
      return await postSetup(this.fetchFn, path, this.request(job, extra));
    } catch (err) {
      if (err instanceof SetupError && STRING_REFUSED.has(err.code)) this.forget();
      throw err;
    }
  }

  check(job, extra = {}) {
    return this.#post(CHECK_PATH, job, extra);
  }

  run(job, extra = {}) {
    return this.#post(RUN_PATH, job, extra);
  }
}

// labelFields is what a LABELS run carries for the labels set on labels:
// nothing when the person left every column, the changes, and with "Mark
// them as not personal" the rest that does not look personal (all of it
// as restPublic when the entries would not fit, or columns are not
// listed).
export function labelFields(labels, more, mark) {
  const tables = [...new Set(labels.columns.map((c) => c.table))];
  const changes = labels.changes(tables);
  if (!mark) return changes.length > 0 ? { columnClasses: changes } : {};
  const plan = labelRest(labels, more);
  if (plan.restPublic) return { ...(changes.length > 0 ? { columnClasses: changes } : {}), restPublic: true };
  const rest = plan.rest.map((c) => ({ table: c.table, column: c.column, class: "PUBLIC", was: { class: "UNCLASSIFIED" } }));
  const all = [...changes, ...rest];
  return all.length > 0 ? { columnClasses: all } : {};
}

// labelRest is what "Mark them as not personal" marks on the labels fix,
// as on the install: every unlabeled column but those the classifier
// suggests are personal or secret, unless they must go as restPublic.
export function labelRest(labels, more) {
  const tables = [...new Set(labels.columns.map((c) => c.table))];
  const unlabeled = labels.unlabeled(tables);
  const suggested = unlabeled.filter((c) => {
    const s = suggestionOf(c);
    return s !== null && (s.label.class === "IDENTIFIER" || s.label.class === "SECRET");
  });
  const rest = unlabeled.filter((c) => !suggested.includes(c));
  const restPublic = more || labels.changes(tables).length + rest.length > MAX_LABELS;
  return { rest, suggested, restPublic };
}

// RELOAD_TRIES and RELOAD_WAIT_MS are how often, and how far apart, the
// check is asked again while the engine serves its config again.
const RELOAD_TRIES = 6;
const RELOAD_WAIT_MS = 1000;
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// FIX_WORK is what a fix button says while its fix runs.
const FIX_WORK = { TRUST: "Checking the certificate…", LABELS: "Checking…", PASSKEY_ADD: "Waiting for your passkey…", REPAIR: "Checking…" };

const UPDATE_SCREENS = ["u-check", "u-passkeys", "s-confirm", "u-mismatch", "u-confirm", "u-done", "u-allset", "s-paste", "s-labels", "s-checking"];

// startUpdate runs the Update check for a CHANGE link. env has fetchFn,
// origin (this page's), makePasskey (a challenge to a registration), pkc
// (the browser's PublicKeyCredential, for the hint after a removal), now
// and onPick (the job the person picked under Update or remove BasaltDB,
// or one a row opens). It returns the UpdateCheck, for the tests.
export function startUpdate(link, env) {
  const fix = new UpdateCheck(env.fetchFn, link);
  let screen = "s-checking";
  let pending = null; // the fix that waits for the admin string
  let labels = null;
  let columnsMore = false;
  let confirmGo = null;
  let doneNext = null;
  let view = null; // the check-up on screen
  // target is the engine's answer while "Is this your database?" is open.
  let target = null;

  const go = (name) => {
    screen = name;
    for (const id of UPDATE_SCREENS) show(id, id === name);
    show("progress", false);
    show("back", !["u-check", "s-checking", "u-done"].includes(name));
    globalThis.window?.scrollTo?.(0, 0);
  };
  const problem = (id, text) => {
    setText(id, text);
    show(id, text !== "");
  };
  const checking = (text) => {
    $("chk-login").className = "check wait";
    setText("chk-login", text);
    go("s-checking");
  };

  // ---- the check ----
  const refresh = async () => {
    checking("Checking BasaltDB and your database");
    let d;
    try {
      d = await fix.doctor();
    } catch (err) {
      $("flow").hidden = true;
      setText("error-text", err.message);
      show("error");
      return;
    }
    showCheck(d);
  };
  // ---- Not your database: before the check, the page asks whose
  // database the engine serves. No only tells the engine, for basalt init:
  // the page resets nothing; the administrator dialog does. A refused
  // engine check goes on to the check. ----
  const start = async () => {
    checking("Checking BasaltDB and your database");
    let r = null;
    try {
      r = await fix.engine();
    } catch {
      r = null;
    }
    if (!r || !Array.isArray(r.databases) || r.databases.length === 0) return refresh();
    target = r;
    paintConfirm(document, targetView(r.databases));
    problem("confirm-error", "");
    go("s-confirm");
    show("back", false);
  };
  const notMine = async () => {
    try {
      await fix.notMine();
    } catch (err) {
      return problem("confirm-error", err.message);
    }
    target = null;
    fix.forget();
    showDone(RESET.title, RESET.text, [], null, "");
  };
  const showCheck = (d) => {
    const crumb = document.querySelector?.(".crumb-page");
    if (crumb) crumb.textContent = d.database ? `Setup · ${d.database}` : "Setup";
    const v = checkView(d, env.origin, savedLeft(), link.agent);
    view = v;
    setText("u-title", v.title);
    setText("u-sub", v.sub);
    const list = $("u-rows");
    list.replaceChildren(...v.rows.map(checkRow));
    const fold = $("u-more");
    fold.replaceChildren(...v.more.map(checkRow));
    show("u-more", false);
    show("u-more-toggle", v.more.length > 0);
    setText("u-more-toggle", `Show ${v.more.length} more`);
    $("u-more-toggle").setAttribute("aria-expanded", "false");
    // Done is aria-disabled, not disabled, while something critical is
    // open: the reason under it is what the button's description names.
    $("u-end").setAttribute("aria-disabled", v.done.enabled ? "false" : "true");
    setText("u-end-why", v.done.why);
    show("u-end-why", !v.done.enabled);
    problem("u-error", "");
    go("u-check");
  };
  const checkRow = (r) => {
    const li = el("li", `check-row ${r.tone}`);
    li.appendChild(el("span", "mark", r.mark));
    const words = el("div", "words");
    words.appendChild(el("strong", "", r.title));
    if (r.text) words.appendChild(el("span", "", r.text));
    li.appendChild(words);
    if (r.action) {
      const b = el("button", r.tone === "critical" ? "fix" : "", r.action);
      b.type = "button";
      b.addEventListener("click", async () => {
        if (r.job === "MANAGE" || r.job === "UPDATE") return act(r.job);
        const stop = working(b, FIX_WORK[r.job] ?? "Checking…", controlsOf("#u-check"));
        if (!stop) return;
        try {
          await act(r.job);
        } finally {
          stop();
        }
      });
      li.appendChild(b);
    }
    return li;
  };
  const act = (job) => {
    if (job === "MANAGE") return showPasskeys("");
    if (job === "UPDATE") return pick("UPDATE");
    return startFix(job);
  };
  const pick = (job) => {
    fix.forget();
    show("flow", false);
    env.onPick(job);
  };
  $("u-pick").addEventListener("click", () => pick(""));
  $("u-more-toggle").addEventListener("click", () => {
    const open = $("u-more").hidden;
    show("u-more", open);
    $("u-more-toggle").setAttribute("aria-expanded", open ? "true" : "false");
    setText("u-more-toggle", open ? "Show fewer" : `Show ${view.more.length} more`);
  });
  // Done: with something critical open it does nothing (the reason is
  // under it); otherwise the All set screen. A page cannot close a tab it
  // did not open, so the screen says to.
  $("u-end").addEventListener("click", () => {
    if (!view?.done.enabled) return;
    fix.forget();
    setText("u-allset-title", ALL_SET.title);
    setText("u-allset-text", ALL_SET.text);
    $("u-allset-lines").replaceChildren(...view.allSet.lines.map((t) => el("li", "row", `✓ ${t}`)));
    setText("u-allset-later", laterText(view.allSet.later));
    show("u-allset-later", view.allSet.later.length > 0);
    go("u-allset");
  });
  // The person's choice to leave columns unlabeled is saved in this
  // browser, per agent, so the row reads as chosen and not as new.
  const leftKey = `basalt.leftUnlabeled.${link.agent}`;
  const savedLeft = () => {
    try {
      const v = JSON.parse(globalThis.localStorage?.getItem(leftKey) ?? "[]");
      return Array.isArray(v) ? v.filter((x) => typeof x === "string") : [];
    } catch {
      return [];
    }
  };
  const saveLeft = (names) => {
    try {
      globalThis.localStorage?.setItem(leftKey, JSON.stringify(names));
    } catch {
      // the row then reads as new again; nothing else depends on it
    }
  };
  // afterFix sends doctor again; every fix ends back on the check.
  const afterFix = () => refresh();
  const cancel = () => {
    fix.forget();
    refresh();
  };

  // ---- the admin string, asked at the first fix ----
  const withString = (run) => {
    if (fix.hasString) return run();
    pending = run;
    showPaste("");
  };
  const showPaste = (text) => {
    $("paste-url").type = "password";
    problem("paste-error", text);
    go("s-paste");
  };
  $("paste-next").addEventListener("click", async () => {
    const typed = $("paste-url").value;
    if (typed.trim() === "" || !pending) return;
    const stop = working($("paste-next"), "Checking…");
    if (!stop) return;
    $("paste-url").value = "";
    fix.setString(typed);
    const run = pending;
    pending = null;
    try {
      await run();
    } finally {
      stop();
    }
  });
  $("reveal").addEventListener("click", () => {
    const shown = $("paste-url").type === "password";
    $("paste-url").type = shown ? "text" : "password";
    $("reveal").setAttribute("aria-pressed", shown ? "true" : "false");
  });
  // failed shows a refusal: of the string, on the paste screen with the
  // same fix waiting; there is nothing to fix, the next one; else on the
  // screen at hand (errorId), or the check screen.
  const failed = (err, retry, errorId = "u-error") => {
    if (err instanceof SetupError && err.code === "NOTHING_TO_FIX") return afterFix();
    if (err instanceof SetupError && STRING_REFUSED.has(err.code)) {
      pending = retry;
      return showPaste(err.message);
    }
    const message = err instanceof SetupError ? err.message : webauthnError(err);
    if (errorId === "u-error" && screen !== "u-check") {
      showCheck(fix.answer);
    }
    problem(errorId, message);
  };

  // ---- the fixes ----
  const startFix = (job) => withString(() => FIXES[job]());
  const FIXES = {
    TRUST: async () => {
      checking("Checking the database's certificate");
      try {
        const a = await fix.check("TRUST");
        if (["NOT_CHECKED", "NOT_ENCRYPTED"].includes(fix.answer?.certificate?.state)) return showCheckOn(a);
        showMismatch(a);
      } catch (err) {
        if (err instanceof SetupError && err.code === "CERTIFICATE_NOT_VERIFIED" && err.trustRoot && err.pinned) return showRenewal(err.trustRoot, err.pinned);
        failed(err, FIXES.TRUST);
      }
    },
    LABELS: async () => {
      checking("Reading the columns without a label");
      let a;
      try {
        a = await fix.check("LABELS");
      } catch (err) {
        return failed(err, FIXES.LABELS);
      }
      labels = new Labels(a.columns);
      columnsMore = a.columnsMore === true;
      if (labels.columns.length === 0 && !columnsMore) return afterFix();
      showLabels();
    },
    PASSKEY_ADD: async () => {
      checking("Getting the passkey ready");
      try {
        const a = await fix.check("PASSKEY_ADD");
        setText("chk-login", "Create the passkey in your browser's prompt.");
        const passkey = await env.makePasskey(a.challenge);
        checking("Adding the passkey");
        const done = await fix.run("PASSKEY_ADD", { challenge: a.challenge, passkey });
        const codes = (done.passkeys || []).map((p) => `${p.label || "Passkey"}: ${p.checkCode}`);
        showDone("Passkey added", "This device can now approve your agents' writes and undos. This is its check code; the agent's status names the same code:", codes, afterFix);
      } catch (err) {
        failed(err, FIXES.PASSKEY_ADD);
      }
    },
    REPAIR: async () => {
      checking("Checking the agent's login");
      try {
        const a = await fix.check("REPAIR");
        showConfirm("Set a new password for your agent", a, "Fix", async () => {
          await fix.run("REPAIR");
          afterFix();
        });
      } catch (err) {
        failed(err, FIXES.REPAIR);
      }
    },
  };

  // ---- the certificate: the confirm step, "Is this still your
  // database?" The database and host are the agent's, the user the admin
  // string's; Yes is the person's trust in the new certificate. ----
  let trusting = null;
  const showRenewal = (trustRoot, pinned) => {
    trusting = trustRoot;
    const cert = fix.answer?.certificate ?? {};
    const named = fix.stringFacts ?? {};
    const facts = {
      database: String(cert.database || named.database || ""),
      host: String(cert.host || named.host || ""),
      port: Number.isInteger(cert.port) ? cert.port : named.port,
      user: String(named.user ?? ""),
    };
    const pinnedSubject = typeof cert.pinnedSubject === "string" ? cert.pinnedSubject : "";
    paintConfirm(document, confirmView({ facts, asking: trustRoot, renewal: { pinnedSubject, sameIssuer: cert.sameIssuer === true }, trustPin: pinned }));
    problem("confirm-error", "");
    go("s-confirm");
  };
  $("confirm-go").addEventListener("click", async () => {
    if (screen === "s-confirm" && target) {
      const stop = working($("confirm-go"), "Checking…");
      if (!stop) return;
      target = null;
      try {
        await refresh();
      } finally {
        stop();
      }
      return;
    }
    if (screen !== "s-confirm" || !trusting) return;
    const trustRoot = trusting.sha256;
    const stop = working($("confirm-go"), "Updating…");
    if (!stop) return;
    try {
      await fix.check("TRUST", { trustRoot });
      await fix.run("TRUST", { trustRoot });
      trusting = null;
      showDone("Security certificate trusted", "Your agents reconnect.", [], afterFix);
    } catch (err) {
      if (err instanceof SetupError && STRING_REFUSED.has(err.code)) return failed(err, FIXES.TRUST);
      problem("confirm-error", err.message);
    } finally {
      stop();
    }
  });
  $("confirm-back").addEventListener("click", async () => {
    if (screen !== "s-confirm") return;
    if (target) {
      const stop = working($("confirm-back"), "Sending…");
      if (!stop) return;
      try {
        await notMine();
      } finally {
        stop();
      }
      return;
    }
    trusting = null;
    cancel();
  });
  // ---- a certificate not checked: the agent's connection string gets
  // sslmode=verify-full once a login with it passed. The engine then
  // serves its config again, so the check reconnects. ----
  const showCheckOn = (a) =>
    showConfirm("Check the certificate", a, "Check it", async () => {
      await fix.run("TRUST");
      showDone("Certificate checked", `${link.agent} now checks the database's certificate. BasaltDB reconnects it.`, [], afterReload);
    });
  // afterReload is afterFix while the engine serves its config again: an
  // engine that does not answer yet is asked again, a few times.
  const afterReload = async () => {
    checking("Checking BasaltDB and your database");
    for (let i = 1; i < RELOAD_TRIES; i++) {
      try {
        await fix.doctor();
        return showCheck(fix.answer);
      } catch (err) {
        if (!(err instanceof SetupError) || err.status !== 0) break;
        await (env.sleep ?? sleep)(RELOAD_WAIT_MS);
      }
    }
    refresh();
  };
  let mismatchPinned = "";
  const showMismatch = (a) => {
    if (!SHA256_HEX.test(String(a.pinned)) || !SHA256_HEX.test(String(a.recorded))) return failed(new SetupError(0, "", "The engine sent a check this page cannot show."), FIXES.TRUST);
    mismatchPinned = a.pinned;
    setText("u-mm-pinned", fingerprintText(a.pinned));
    setText("u-mm-recorded", fingerprintText(a.recorded));
    problem("u-mm-error", "");
    go("u-mismatch");
  };
  $("u-mm-go").addEventListener("click", async () => {
    const stop = working($("u-mm-go"), "Updating…");
    if (!stop) return;
    try {
      await fix.run("TRUST", { pinned: mismatchPinned });
      afterFix();
    } catch (err) {
      if (err instanceof SetupError && STRING_REFUSED.has(err.code)) return failed(err, FIXES.TRUST);
      problem("u-mm-error", err.message);
    } finally {
      stop();
    }
  });
  $("u-mm-cancel").addEventListener("click", cancel);

  // ---- the labels: the install's screen, only the unlabeled columns ----
  const choices = {
    current: (c) => labels.current(c),
    set: (table, column, label) => labels.set(table, column, label),
  };
  const showLabels = () => {
    const box = $("label-tables");
    box.replaceChildren();
    const byTable = new Map();
    for (const c of labels.columns) {
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
    setText("unlabeled-warn", `Columns without a label aren't masked: ${link.agent} reads them as they are, and they can be sent to its AI provider. They'll be blocked once PII protection ships, until you label them.`);
    problem("labels-error", "");
    $("rest-leave").checked = true;
    $("rest-mark").checked = false;
    restCount();
    go("s-labels");
  };
  const restCount = () => {
    const p = labelRest(labels, columnsMore);
    show("rest-choice", p.rest.length > 0 || p.restPublic);
    const personal = p.suggested.map((c) => `${tableName(c.table)}.${c.column}`);
    const count = p.restPublic ? p.rest.length + p.suggested.length : p.rest.length;
    showNote("rest-note", $("rest-mark").checked ? restNote({ count, forced: p.restPublic, more: columnsMore, personal }) : []);
  };
  for (const id of ["rest-leave", "rest-mark"]) $(id).addEventListener("change", restCount);
  $("labels-next").addEventListener("click", async () => {
    const tables = [...new Set(labels.columns.map((c) => c.table))];
    const stop = labels.problem(tables);
    if (stop) return problem("labels-error", stop);
    const fields = labelFields(labels, columnsMore, !$("rest-choice").hidden && $("rest-mark").checked);
    const leave = () => saveLeft(labels.unlabeled(tables).map((c) => columnKey(c.table, c.column)));
    if (!fields.columnClasses && !fields.restPublic) {
      leave();
      return afterFix(); // left unlabeled for now: no run
    }
    const wait = working($("labels-next"), "Updating…");
    if (!wait) return;
    try {
      await fix.run("LABELS", fields);
      if (!fields.restPublic) leave();
      afterFix();
    } catch (err) {
      if (err instanceof SetupError && err.code === "CLASSES_CHANGED") return FIXES.LABELS();
      failed(err, FIXES.LABELS, "labels-error");
    } finally {
      wait();
    }
  });

  // ---- passkeys: the list, Remove and Add ----
  const showPasskeys = (text) => {
    const items = passkeyItems(fix.answer?.passkeys, env.origin, env.now());
    $("u-keys").replaceChildren(...items.map(keyRow));
    setText("u-keys-note", PASSKEYS_NOTE);
    problem("u-keys-error", text);
    go("u-passkeys");
  };
  const keyRow = (k) => {
    const li = el("li", "check-row");
    const words = el("div", "words");
    words.appendChild(el("strong", "", k.label));
    words.appendChild(el("span", "", k.line));
    li.appendChild(words);
    const b = el("button", "remove", "Remove");
    b.type = "button";
    b.setAttribute("aria-label", `Remove ${k.label}`);
    b.addEventListener("click", async () => {
      const stop = working(b, "Checking…", controlsOf("#u-passkeys"));
      if (!stop) return;
      try {
        await withString(() => removeKey(k));
      } finally {
        stop();
      }
    });
    li.appendChild(b);
    return li;
  };
  const removeKey = async (k) => {
    checking("Reading the passkey");
    let a;
    try {
      a = await fix.check("PASSKEY_REMOVE", { credentialId: k.credentialId });
    } catch (err) {
      if (err instanceof SetupError && STRING_REFUSED.has(err.code)) return failed(err, () => removeKey(k));
      return showPasskeys(err.message);
    }
    showConfirm("Remove this passkey?", a, "Remove passkey", async () => {
      const done = await fix.run("PASSKEY_REMOVE", { credentialId: k.credentialId });
      if (k.rpId === "localhost") await signalRemoved(env.pkc, k.rpId, k.credentialId);
      if (done.remaining === 0) {
        return showDone("Passkey removed", "Add a passkey so your agents' writes and undos can be approved again.", [], () => startFix("PASSKEY_ADD"), "Add a passkey");
      }
      await fix.doctor();
      showPasskeys("");
    });
  };
  $("u-add").addEventListener("click", async () => {
    const stop = working($("u-add"), "Waiting for your passkey…", controlsOf("#u-passkeys"));
    if (!stop) return;
    try {
      await startFix("PASSKEY_ADD");
    } finally {
      stop();
    }
  });

  // ---- the confirmation and the done screen ----
  const showConfirm = (title, answer, action, run) => {
    setText("u-confirm-title", title);
    list2("u-confirm-lines", strings(answer.lines));
    setText("u-confirm-sql", String(answer.sql ?? ""));
    setText("u-confirm-go", action);
    problem("u-confirm-error", "");
    confirmGo = run;
    go("u-confirm");
  };
  $("u-confirm-go").addEventListener("click", async () => {
    if (!confirmGo) return;
    const action = $("u-confirm-go").textContent;
    const stop = working($("u-confirm-go"), action === "Remove passkey" ? "Removing…" : action === "Check it" ? "Checking the certificate…" : "Updating…");
    if (!stop) return;
    try {
      await confirmGo();
    } catch (err) {
      if (err instanceof SetupError && STRING_REFUSED.has(err.code)) {
        pending = confirmGo;
        return showPaste(err.message);
      }
      problem("u-confirm-error", err.message);
    } finally {
      stop();
    }
  });
  $("u-confirm-cancel").addEventListener("click", cancel);
  const showDone = (title, text, codes, then, action = "Continue") => {
    setText("u-done-title", title);
    setText("u-done-text", text);
    $("u-done-codes").replaceChildren(...codes.map((c) => el("li", "row mono", c)));
    show("u-done-codes", codes.length > 0);
    setText("u-done-next", action);
    show("u-done-next", action !== "");
    doneNext = then;
    go("u-done");
  };
  $("u-done-next").addEventListener("click", async () => {
    const stop = working($("u-done-next"), "Checking…");
    if (!stop) return;
    try {
      await doneNext?.();
    } finally {
      stop();
    }
  });

  // ---- Back: to the check, or to the list ----
  $("back").addEventListener("click", () => {
    if (screen === "u-confirm" && $("u-confirm-go").textContent === "Remove passkey") return showPasskeys("");
    cancel();
  });
  globalThis.window?.addEventListener?.("pagehide", () => fix.forget());

  document.body.classList.add("connect-page");
  show("flow");
  start();
  return fix;
}

// showNote fills a note with one line each, hidden when it has none.
export function showNote(id, lines) {
  const box = $(id);
  box.replaceChildren(...lines.map((line) => el("span", "", line)));
  box.hidden = lines.length === 0;
}

function list2(id, lines) {
  const ul = $(id);
  ul.replaceChildren(...lines.map((line) => el("li", "", line)));
  ul.hidden = lines.length === 0;
}

// doneText is the done screen's sentence for job and the run's answer.
export function doneText(job, done) {
  return JOB_TEXT[job.job].done(done.agent || job.agent);
}

function showDone(job, done) {
  $("main").hidden = true;
  $("flow").hidden = true;
  $("done").hidden = false;
  $("done-text").textContent = doneText(job, done);
  $("mcp-command").textContent = done.mcpCommand || "";
  $("mcp-command").hidden = job.job !== "INSTALL" || !done.mcpCommand;
  list("done-lines", done.lines || []);
  list("warnings", done.warnings || []);
  const codes = (done.passkeys || []).map((p) => `${p.label || "Passkey"}: ${p.checkCode}`);
  list("check-codes", codes);
  $("check-codes-box").hidden = codes.length === 0;
}

// showRemoved is the done screen of a removal: the checklist ticks the
// database at once, and this computer when the engine stops answering
// (the removal job stopped it), when the removal took the engine's last
// agent; "BasaltDB is removed" once nothing is left to wait for.
export async function showRemoved(job, done, database, fetchFn, env = {}) {
  showDone(job, done);
  const steps = (computer) => list("removal-steps", removalSteps(database, computer));
  $("done-text").textContent = "";
  list("done-lines", []);
  $("removal-mac").hidden = !(done.engineRemoving && isMac(env.navigator ?? globalThis.navigator));
  // The command is the person's own install: the removal leaves it, and the
  // screen says so only when the engine left this computer. While other agents
  // stay, or the engine still runs, they still need the command.
  $("removal-command").hidden = true;
  if (!done.engineRemoving) {
    steps(done.engineRemoved ? "notAsked" : "kept");
    $("done-title").textContent = JOB_TEXT.REMOVE.removed;
    return;
  }
  steps("removing");
  $("done-title").textContent = "Removing BasaltDB…";
  const gone = await engineGone(fetchFn, env);
  steps(gone ? "removed" : "stuck");
  $("done-title").textContent = gone ? JOB_TEXT.REMOVE.removed : "Removing BasaltDB…";
  if (gone) $("done-text").textContent = REMOVAL_TEXT.done(database);
  $("removal-command").hidden = !gone;
}

if (typeof document !== "undefined") main();
