// The connect page's Remove BasaltDB tab (CONTRACT.md, Connect, Removal on
// the connect page): remove BasaltDB from a database with only its admin
// connection string. One box and one press: the person pastes the string,
// the page checks it by itself and shows what goes (the ledger, the guard,
// the bots by name; their tables stay) with the SQL, and one button,
// "Remove BasaltDB from <db> on <host>", removes it. The admin string is the
// confirmation: there is no typed name.
//
// Opened from a bot's removal link (#remove=<code>, basalt init --remove on
// the bot's computer; CONTRACT.md, Connect, The removal hand-off), RunRemove
// sends the code too, and the page then waits for the bot's engine to
// remove itself (HandoffStatus), ticking a checklist: the database, the
// bot's computer, the agent's connection.
//
// As on the Connect a bot tab, the admin connection string lives only in
// one private field of RemoveFlow: never in storage, the address, a log or
// a message. The input box is emptied as soon as it is read, and the field
// after RunRemove whatever its answer and on every way back.
//
// The calls and refusals are connect.js's, handed in (rpc) so this module
// never loads the page's entry module itself.
import { busy } from "./page.js";
import { hostOf, trustText } from "./picks.js";

// MAX_URL_CHARS and POSTGRES_URL are the Connect a bot tab's.
const MAX_URL_CHARS = 4096;
const POSTGRES_URL = /^postgres(?:ql)?:\/\//i;

// REMOVAL_FRAGMENT starts a removal link's fragment: #remove=<code>.
export const REMOVAL_FRAGMENT = "#remove=";

// CHECK_DELAY_MS is how long the page waits after the admin string changed
// before it checks it by itself: a paste is one change.
export const CHECK_DELAY_MS = 400;

// The wait for the bot's engine after the removal (CONTRACT.md, Connect,
// The removal hand-off): HandoffStatus every POLL_MS for up to WAIT_MS. The
// engine collects every 15 seconds.
export const POLL_MS = 5000;
export const WAIT_MS = 120000;

const UNREADABLE = "The connect service sent an answer this page cannot read.";

const strings = (v) => (Array.isArray(v) ? v.filter((s) => typeof s === "string") : []);

// removalCode is the code of a removal link's fragment, or "".
export function removalCode(hash) {
  return typeof hash === "string" && hash.startsWith(REMOVAL_FRAGMENT) ? hash.slice(REMOVAL_FRAGMENT.length).trim() : "";
}

// removeButtonText is the Remove button: it names the database and its
// host, which the admin string opens.
export function removeButtonText(database, host) {
  return host ? `Remove BasaltDB from ${database} on ${host}` : `Remove BasaltDB from ${database}`;
}

// removalItems are what the review screen lists: what goes, and that the
// person's tables stay.
export function removalItems(check) {
  const items = [
    { kind: "gone", text: "The ledger of every action your bots took (the schema basalt_meta). It is deleted for good." },
    { kind: "gone", text: "The guard: its triggers and row-level security policies." },
  ];
  if (check.bots.length > 0) {
    items.push({ kind: "gone", text: `The bots' access: ${check.bots.join(", ")}. Each bot's database role is dropped, so it can no longer log in.` });
  } else {
    items.push({ kind: "gone", text: "No bot has access to this database." });
  }
  if (check.sampleSchema) items.push({ kind: "gone", text: "The sample schema basalt_demo and its rows." });
  items.push({ kind: "stays", text: check.sampleSchema ? "Your own tables and their rows stay." : "Your tables and their rows stay." });
  return items;
}

// REMOVAL_TEXT is the checklist after a removal: the database, the bot's
// computer and the agent's connection.
export const REMOVAL_TEXT = {
  database: (db) => `✓ Removed from the database ${db}`,
  removing: "Removing from the bot's computer…",
  removed: "✓ Removed from the bot's computer",
  noAnswer: "The bot's computer: no answer yet. Tell your bot \"check your status\" in the chat: it says what is left.",
  noLink: "The bot's computer: this page was not opened from your bot's removal link, so BasaltDB stays there. Ask your bot to remove BasaltDB: its link removes both.",
  kept: {
    OTHER_AGENTS: "The bot's computer: BasaltDB stays there, serving your other bots.",
    CREDENTIAL_FILE_KEPT: "The bot's computer: BasaltDB is removed, except the bot's connection file outside its folder, which it may not delete.",
    SERVICE: "The bot's computer: BasaltDB runs there as a service, which this page cannot remove. Ask your bot to call status.",
    DELETE_FAILED: "The bot's computer: some of BasaltDB's files could not be deleted. Ask your bot to call status.",
  },
  agent: "Agent connection: your bot drops it the next time you talk to it.",
};

// computerLine is the checklist's line for the bot's computer: "removing",
// "removed", "noAnswer", "noLink", or a KEPT reason.
export function computerLine(computer) {
  if (typeof REMOVAL_TEXT[computer] === "string") return REMOVAL_TEXT[computer];
  return REMOVAL_TEXT.kept[computer] ?? REMOVAL_TEXT.kept.DELETE_FAILED;
}

// removalSteps are the checklist's lines.
export function removalSteps(database, computer) {
  return [REMOVAL_TEXT.database(database), computerLine(computer), REMOVAL_TEXT.agent];
}

function defaultSleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// RemoveFlow is the tab's steps: paste (checked by itself), trust (only
// when the database's certificate authority is unknown), review, done.
export class RemoveFlow {
  #databaseUrl = "";
  #trustRoot = "";

  // rpc is { call, Refusal, notPostgres } from connect.js; code is a
  // removal link's code, or "".
  constructor({ fetch: fetchFn, rpc, code = "", sleep = defaultSleep, now = () => Date.now() }) {
    this.fetch = fetchFn;
    this.rpc = rpc;
    this.code = code;
    this.sleep = sleep;
    this.now = now;
    this.step = "paste";
    this.check = null;
    this.asking = null;
    this.done = null;
    this.link = null;
  }

  // describeLink reads a removal link's code: the database it names, for
  // the page's heading. A refused code (expired, damaged) is dropped: the
  // page then removes BasaltDB from the database only.
  async describeLink() {
    if (this.code === "") return null;
    try {
      const out = await this.rpc.call(this.fetch, "DescribeSetup", { code: this.code });
      const t = out?.summary?.target;
      if (!t || typeof t.database !== "string" || typeof t.host !== "string") throw new this.rpc.Refusal("UNKNOWN", UNREADABLE);
      this.link = { database: t.database, host: t.host };
      return this.link;
    } catch (err) {
      this.code = "";
      throw err;
    }
  }

  // checkRemove takes the string the person pasted. On a refusal the string
  // is dropped, unless the refusal offers a certificate authority to trust.
  async checkRemove(databaseUrl) {
    if (this.step !== "paste") throw new Error("not at the paste step");
    const url = String(databaseUrl ?? "").trim();
    if (url === "") throw new this.rpc.Refusal("CONNECTION_STRING_REFUSED", "Paste your database's connection string first.");
    if (url.length > MAX_URL_CHARS) throw new this.rpc.Refusal("CONNECTION_STRING_REFUSED", "That is too long to be a connection string.");
    if (!POSTGRES_URL.test(url)) throw new this.rpc.Refusal("NOT_POSTGRES", this.rpc.notPostgres);
    this.#databaseUrl = url;
    this.#trustRoot = "";
    return this.#checkOrAsk();
  }

  async #checkOrAsk() {
    let out;
    try {
      out = await this.rpc.call(this.fetch, "CheckRemove", this.#request());
    } catch (err) {
      if (err instanceof this.rpc.Refusal && err.trustRoot) {
        this.asking = err.trustRoot;
        this.step = "trust";
      } else {
        this.#forget();
        this.step = "paste";
      }
      throw err;
    }
    if (typeof out.database !== "string" || out.database === "") {
      this.#forget();
      this.step = "paste";
      throw new this.rpc.Refusal("UNKNOWN", UNREADABLE);
    }
    this.check = {
      database: out.database,
      host: hostOf(this.#databaseUrl),
      bots: strings(out.bots),
      lines: strings(out.lines),
      sql: typeof out.sql === "string" ? out.sql : "",
      nothingToRemove: out.nothingToRemove === true,
      sampleSchema: out.sampleSchema === true,
    };
    this.step = "review";
    return this.check;
  }

  #request() {
    const req = { databaseUrl: this.#databaseUrl };
    if (this.#trustRoot !== "") req.trustRoot = this.#trustRoot;
    return req;
  }

  #forget() {
    this.#databaseUrl = "";
    this.#trustRoot = "";
  }

  get trustHost() {
    return hostOf(this.#databaseUrl);
  }

  // trust is "Trust and continue": CheckRemove again with the certificate
  // authority the person was shown.
  async trust() {
    if (this.step !== "trust" || !this.asking) throw new Error("not at the trust step");
    this.#trustRoot = this.asking.sha256;
    this.asking = null;
    return this.#checkOrAsk();
  }

  // back is every way back to the paste step: the string is dropped.
  back() {
    if (this.step === "done" || this.step === "running") throw new Error("cannot go back now");
    this.#forget();
    this.asking = null;
    this.check = null;
    this.step = "paste";
  }

  // remove is RunRemove, with the removal link's code when there is one.
  // The string is dropped whatever the answer.
  async remove() {
    if (this.step !== "review" || !this.check) throw new Error("not at the review step");
    this.step = "running";
    const req = this.#request();
    if (this.code !== "") req.code = this.code;
    let out;
    try {
      out = await this.rpc.call(this.fetch, "RunRemove", req);
    } catch (err) {
      this.#forget();
      this.check = null;
      this.step = "paste";
      throw err;
    }
    this.#forget();
    this.done = {
      database: typeof out.database === "string" ? out.database : this.check.database,
      bots: strings(out.bots),
      lines: strings(out.lines),
      warnings: strings(out.warnings),
      ticket: typeof out.ticket === "string" ? out.ticket : "",
    };
    this.step = "done";
    return this.done;
  }

  // waitComputer waits for the bot's engine after a removal with a code:
  // "removed", a KEPT reason, or "noAnswer" when WAIT_MS pass without its
  // report. On UNKNOWN (the service lost the hold) it offers the ticket
  // back once.
  async waitComputer() {
    let ticket = this.done?.ticket ?? "";
    if (ticket === "") return "noLink";
    const until = this.now() + WAIT_MS;
    let offered = false;
    for (;;) {
      try {
        const st = await this.rpc.call(this.fetch, "HandoffStatus", { ticket });
        if (typeof st.ticket === "string" && st.ticket !== "") ticket = st.ticket;
        const r = st.removed;
        if (r?.result === "REMOVED") return "removed";
        if (r?.result === "KEPT") return typeof r.reason === "string" && r.reason !== "" ? r.reason : "DELETE_FAILED";
        if (st.state === "UNKNOWN" && !offered) {
          offered = true;
          await this.rpc.call(this.fetch, "OfferAddress", { ticket });
        }
      } catch {
        // A call that failed is tried again at the next poll.
      }
      if (this.now() >= until) return "noAnswer";
      await this.sleep(POLL_MS);
    }
  }
}

const $ = (id) => document.getElementById(id);

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

const SCREENS = ["r-paste", "r-trust", "r-checking", "r-review", "r-done"];

// fill replaces node's children with children.
function fill(node, children) {
  node.textContent = "";
  for (const c of children) node.appendChild(c);
}

function showScreen(name) {
  for (const id of SCREENS) $(id).hidden = id !== name;
}

function showError(id, err, rpc) {
  const node = $(id);
  node.textContent = err instanceof rpc.Refusal ? err.message : "Something went wrong on this page. Nothing was sent.";
  node.hidden = false;
}

// startRemove wires the Remove BasaltDB tab. It returns the flow and a
// promise of the link's description (resolved at once without a link).
export function startRemove(env) {
  const flow = new RemoveFlow(env);
  showScreen("r-paste");
  $("r-back").hidden = true;
  let ready = Promise.resolve();
  if (flow.code !== "") {
    $("r-link").hidden = false;
    ready = flow.describeLink().then(
      (link) => {
        $("r-title").textContent = `Remove BasaltDB from ${link.database} on ${link.host}`;
        $("r-link").textContent = "From your bot's removal link: once the database is done, your bot removes BasaltDB from its computer too.";
      },
      (err) => {
        $("r-link").hidden = true;
        showError("r-paste-error", err, env.rpc);
      },
    );
  }

  const toPaste = () => {
    flow.back();
    $("r-back").hidden = true;
    showScreen("r-paste");
  };

  const review = (check) => {
    $("r-db-name").textContent = check.database;
    const list = $("r-items");
    fill(list, removalItems(check).map((i) => el("li", `check ${i.kind === "stays" ? "ok" : "gone"}`, i.text)));
    $("r-nothing").hidden = !check.nothingToRemove;
    $("r-sql").textContent = check.sql;
    fill($("r-lines"), check.lines.map((l) => el("li", "", l)));
    $("r-remove").textContent = removeButtonText(check.database, check.host);
    $("r-remove").disabled = false;
    $("r-review-error").hidden = true;
    $("r-back").hidden = false;
    showScreen("r-review");
  };

  const checked = async (run, button, label) => {
    const done = busy($(button), label);
    if (!done) return;
    $("r-paste-error").hidden = true;
    $("r-trust-error").hidden = true;
    showScreen("r-checking");
    try {
      const check = await run();
      done();
      review(check);
    } catch (err) {
      done();
      if (flow.step === "trust") {
        $("r-trust-text").textContent = trustText(flow.trustHost, flow.asking);
        showScreen("r-trust");
        return;
      }
      showScreen("r-paste");
      showError("r-paste-error", err, env.rpc);
    }
  };

  const checkPasted = () => {
    const url = $("r-database-url").value;
    if (String(url).trim() === "" || flow.step !== "paste") return undefined;
    $("r-database-url").value = "";
    return checked(() => flow.checkRemove(url), "r-check", "Checking…");
  };
  $("r-check").addEventListener("click", () => {
    const url = $("r-database-url").value;
    $("r-database-url").value = "";
    return checked(() => flow.checkRemove(url), "r-check", "Checking…");
  });
  // One box, one press: a pasted string is checked by itself, after a
  // short pause so a paste is one change; Continue stays for typing.
  let pending = null;
  $("r-database-url").addEventListener("input", () => {
    if (pending !== null) clearTimeout(pending);
    pending = setTimeout(() => {
      pending = null;
      checkPasted();
    }, CHECK_DELAY_MS);
  });
  $("r-trust-go").addEventListener("click", () => checked(() => flow.trust(), "r-trust-go", "Checking…"));
  $("r-trust-cancel").addEventListener("click", toPaste);
  $("r-back").addEventListener("click", toPaste);
  $("r-remove").addEventListener("click", async () => {
    const label = $("r-remove").textContent;
    const done = busy($("r-remove"), "Removing BasaltDB…");
    if (!done) return;
    $("r-back").hidden = true;
    let result;
    try {
      result = await flow.remove();
    } catch (err) {
      done();
      $("r-remove").textContent = label;
      showScreen("r-paste");
      showError("r-paste-error", err, env.rpc);
      return;
    }
    done();
    const steps = (computer) => fill($("r-steps"), removalSteps(result.database, computer).map((l) => el("li", "", l)));
    $("r-done-bots").textContent = result.bots.length > 0 ? `Bots that lost their access: ${result.bots.join(", ")}.` : "";
    fill($("r-done-warnings"), result.warnings.map((w) => el("li", "", w)));
    $("r-done-warnings").hidden = result.warnings.length === 0;
    if (result.ticket === "") {
      steps("noLink");
      $("r-done-title").textContent = `BasaltDB is removed from ${result.database}`;
      showScreen("r-done");
      return;
    }
    steps("removing");
    $("r-done-title").textContent = "Removing BasaltDB…";
    showScreen("r-done");
    const computer = await flow.waitComputer();
    steps(computer);
    $("r-done-title").textContent = computer === "removed" ? "BasaltDB is removed" : `BasaltDB is removed from ${result.database}`;
  });
  return { flow, ready };
}

// startTabs wires the two tabs: Connect a bot (the default) and Remove
// BasaltDB. Each tab keeps its own steps; switching shows the other.
// rpc is { call, Refusal, notPostgres } from connect.js; code is a removal
// link's code (#remove=<code>), which opens the Remove tab.
export function startTabs(env, { removeOnly = false, code = "", rpc }) {
  env = { ...env, rpc, code };
  let removeStarted = null;
  const pick = (tab) => {
    const remove = tab === "remove";
    $("tab-connect").setAttribute("aria-selected", String(!remove));
    $("tab-remove").setAttribute("aria-selected", String(remove));
    $("main").hidden = remove;
    $("remove").hidden = !remove;
    if (remove && removeStarted === null) removeStarted = startRemove(env);
  };
  $("tab-connect").addEventListener("click", () => pick("connect"));
  $("tab-remove").addEventListener("click", () => pick("remove"));
  $("tabs").hidden = false;
  pick(removeOnly || code !== "" ? "remove" : "connect");
  return removeStarted;
}
