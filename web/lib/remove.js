// The connect page's Remove BasaltDB tab (CONTRACT.md, Connect, Removal on
// the connect page): remove BasaltDB from a database with only its admin
// connection string, no setup code and no bot. The person pastes the
// string, sees what goes (the ledger, the guard, the bots by name; their
// tables stay) with the SQL, types the database's name, and removes.
//
// As on the Connect a bot tab, the admin connection string lives only in
// one private field of RemoveFlow: never in storage, the address, a log or
// a message. The input box is emptied as soon as it is read, and the field
// after RunRemove whatever its answer and on every way back.
//
// The calls and refusals are connect.js's, handed in (rpc) so this module
// never loads the page's entry module itself.
import { hostOf, trustText } from "./picks.js";

// MAX_URL_CHARS and POSTGRES_URL are the Connect a bot tab's.
const MAX_URL_CHARS = 4096;
const POSTGRES_URL = /^postgres(?:ql)?:\/\//i;
// MAX_DATABASE_NAME: Postgres names are at most 63 bytes.
const MAX_DATABASE_NAME = 63;

const UNREADABLE = "The connect service sent an answer this page cannot read.";

const strings = (v) => (Array.isArray(v) ? v.filter((s) => typeof s === "string") : []);

// removeConfirmed reports whether the typed text is the database's name,
// exactly: the Remove button waits for it.
export function removeConfirmed(typed, database) {
  return typeof typed === "string" && typeof database === "string" && database !== "" && typed === database;
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

// RemoveFlow is the tab's steps: paste, trust (only when the database's
// certificate authority is unknown), review, done.
export class RemoveFlow {
  #databaseUrl = "";
  #trustRoot = "";

  // rpc is { call, Refusal, notPostgres } from connect.js.
  constructor({ fetch: fetchFn, rpc }) {
    this.fetch = fetchFn;
    this.rpc = rpc;
    this.step = "paste";
    this.check = null;
    this.asking = null;
    this.done = null;
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

  // remove is RunRemove with the name the person typed. The string is
  // dropped whatever the answer.
  async remove(typed) {
    if (this.step !== "review" || !this.check) throw new Error("not at the review step");
    if (!removeConfirmed(typed, this.check.database) || typed.length > MAX_DATABASE_NAME) {
      throw new this.rpc.Refusal("ANSWERS_INVALID", "Type the database's name exactly as the page shows it to remove BasaltDB from it. Nothing changed.");
    }
    this.step = "running";
    let out;
    try {
      out = await this.rpc.call(this.fetch, "RunRemove", { ...this.#request(), confirmName: typed });
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
    };
    this.step = "done";
    return this.done;
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

// startRemove wires the Remove BasaltDB tab.
export function startRemove(env) {
  const flow = new RemoveFlow(env);
  showScreen("r-paste");
  $("r-back").hidden = true;

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
    $("r-confirm-name").textContent = check.database;
    $("r-confirm").value = "";
    $("r-remove").disabled = true;
    $("r-review-error").hidden = true;
    $("r-back").hidden = false;
    showScreen("r-review");
  };

  const checked = async (run) => {
    $("r-paste-error").hidden = true;
    $("r-trust-error").hidden = true;
    showScreen("r-checking");
    try {
      review(await run());
    } catch (err) {
      if (flow.step === "trust") {
        $("r-trust-text").textContent = trustText(flow.trustHost, flow.asking);
        showScreen("r-trust");
        return;
      }
      showScreen("r-paste");
      showError("r-paste-error", err, env.rpc);
    }
  };

  $("r-check").addEventListener("click", () => {
    const url = $("r-database-url").value;
    $("r-database-url").value = "";
    return checked(() => flow.checkRemove(url));
  });
  $("r-trust-go").addEventListener("click", () => checked(() => flow.trust()));
  $("r-trust-cancel").addEventListener("click", toPaste);
  $("r-back").addEventListener("click", toPaste);
  $("r-confirm").addEventListener("input", () => {
    $("r-remove").disabled = !removeConfirmed($("r-confirm").value, flow.check?.database);
  });
  $("r-remove").addEventListener("click", async () => {
    $("r-remove").disabled = true;
    $("r-back").hidden = true;
    try {
      const done = await flow.remove($("r-confirm").value);
      $("r-done-db").textContent = done.database;
      $("r-done-bots").textContent = done.bots.length > 0 ? `Bots that lost their access: ${done.bots.join(", ")}.` : "";
      fill($("r-done-warnings"), done.warnings.map((w) => el("li", "", w)));
      $("r-done-warnings").hidden = done.warnings.length === 0;
      showScreen("r-done");
    } catch (err) {
      showScreen("r-paste");
      showError("r-paste-error", err, env.rpc);
    }
  });
  return flow;
}

// startTabs wires the two tabs: Connect a bot (the default) and Remove
// BasaltDB. Each tab keeps its own steps; switching shows the other.
// rpc is { call, Refusal, notPostgres } from connect.js.
export function startTabs(env, { removeOnly = false, rpc }) {
  env = { ...env, rpc };
  let removeStarted = false;
  const pick = (tab) => {
    const remove = tab === "remove";
    $("tab-connect").setAttribute("aria-selected", String(!remove));
    $("tab-remove").setAttribute("aria-selected", String(remove));
    $("main").hidden = remove;
    $("remove").hidden = !remove;
    if (remove && !removeStarted) {
      removeStarted = true;
      startRemove(env);
    }
  };
  $("tab-connect").addEventListener("click", () => pick("connect"));
  $("tab-remove").addEventListener("click", () => pick("remove"));
  $("tabs").hidden = false;
  pick(removeOnly ? "remove" : "connect");
}
