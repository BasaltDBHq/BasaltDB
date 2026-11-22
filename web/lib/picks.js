// The steps the connect page and the local setup page share: the tables
// the agent gets, the column labels and the certificate authority to
// trust (CONTRACT.md, Tables on the connect page, Column labels on the
// connect page, Trusting a certificate authority on the page, and The
// install of a real database). Pure functions and state only: no page.

// columnClasses holds at most 500 entries; past that, "Mark the rest as not
// personal" goes as restPublic.
export const MAX_LABELS = 500;

// The refusals that may carry a certificate authority to trust.
const TRUST_REASONS = new Set(["CERTIFICATE_NOT_VERIFIED", "TRUST_ROOT_MISMATCH"]);
const SHA256_HEX = /^[0-9a-f]{64}$/;
// The server chooses the subject; the service cuts it to 512 characters.
const MAX_SUBJECT_CHARS = 512;
const RFC3339_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;

// trustRootFrom is a Refusal detail's trustRoot, checked: its subject as
// text, its SHA-256 as 64 lowercase hex digits and its expiry as RFC 3339
// UTC. null when there is none or any part is unreadable: the refusal is
// then shown as it is.
export function trustRootFrom(reason, t) {
  if (!TRUST_REASONS.has(reason) || !t || typeof t !== "object") return null;
  const { subject, sha256: fp, expiresAt } = t;
  if (typeof subject !== "string" || subject === "" || [...subject].length > MAX_SUBJECT_CHARS) return null;
  if (typeof fp !== "string" || !SHA256_HEX.test(fp)) return null;
  if (typeof expiresAt !== "string" || !RFC3339_UTC.test(expiresAt) || Number.isNaN(Date.parse(expiresAt))) return null;
  return { subject, sha256: fp, expiresAt };
}

// fingerprintText is a SHA-256 as the laptop command shows it: uppercase
// hex pairs with colons.
export function fingerprintText(fp) {
  return fp.toUpperCase().match(/../g).join(":");
}

// trustText is the question the page asks about trustRoot for host.
export function trustText(host, trustRoot) {
  const date = trustRoot.expiresAt.slice(0, 10);
  return `${host} presents a certificate authority Basalt does not know: ${trustRoot.subject}, SHA-256 ${fingerprintText(trustRoot.sha256)}, valid until ${date}. Check it against your provider's console. Trust it for this host only?`;
}

// hostOf is the host a pasted connection string names, or a plain word.
export function hostOf(url) {
  try {
    const h = new URL(url).hostname;
    if (h !== "") return h.replace(/^\[|\]$/g, "");
  } catch {
    // Fall through.
  }
  return "This database";
}

// tableName is a table as the page shows it: without public., which most
// databases put everything in.
export function tableName(t) {
  return t.startsWith("public.") ? t.slice("public.".length) : t;
}

// answersFor answers every row-level security question for an included
// table with ALL_ROWS (CONTRACT.md, The connect page, step 6): a ticked
// table gives the bot every row. included is null when every table is.
export function answersFor(questions, included) {
  const out = [];
  for (const q of Array.isArray(questions) ? questions : []) {
    if (included && !included.includes(q.table)) continue;
    out.push({ kind: q.kind, table: q.table, choice: "ALL_ROWS" });
  }
  return out;
}

// ---- Column labels (CONTRACT.md, Column labels on the connect page) ----

export const ENTITY_WORDS = { EMAIL: "email", PHONE: "phone", PERSON_NAME: "name", ADDRESS: "address", OTHER: "other" };
export const FIXED_WORDS = { PUBLIC: "Not personal", FREE_TEXT: "Free text" };
const REGION = /^[A-Z]{2}$/;

const key = (table, column) => `${table}\u0000${column}`;

// labelOf is a column's class as CheckSetup read it, UNCLASSIFIED when it
// has none.
export function labelOf(c) {
  const cls = typeof c?.class === "string" && c.class !== "" ? c.class : "UNCLASSIFIED";
  // As CheckSetup sent it: the service compares all three fields with what
  // is stored, so was echoes them unchanged.
  return {
    class: cls,
    entityType: typeof c.entityType === "string" ? c.entityType : "",
    phoneRegion: typeof c.phoneRegion === "string" ? c.phoneRegion : "",
  };
}

const sameLabel = (a, b) => a.class === b.class && a.entityType === b.entityType && a.phoneRegion === b.phoneRegion;

// Labels is screen 5's state: the columns of the included tables, each with
// its class now, and what the person chose.
export class Labels {
  constructor(columns) {
    this.columns = (Array.isArray(columns) ? columns : []).filter((c) => typeof c?.table === "string" && typeof c?.column === "string");
    this.chosen = new Map();
  }

  // set records the person's choice for a column: a class with its entity
  // type and region, or null for blank (only offered on a column without a
  // class, so it never erases one).
  set(table, column, label) {
    if (label === null) this.chosen.delete(key(table, column));
    else this.chosen.set(key(table, column), { class: label.class, entityType: label.entityType ?? "", phoneRegion: label.phoneRegion ?? "" });
  }

  current(c) {
    return this.chosen.get(key(c.table, c.column)) ?? labelOf(c);
  }

  of(included) {
    const set = new Set(included);
    return this.columns.filter((c) => set.has(c.table));
  }

  // changes are the columns of the included tables the person changed, as
  // columnClasses entries, each with the class it had (was).
  changes(included) {
    const out = [];
    for (const c of this.of(included)) {
      const was = labelOf(c);
      const now = this.chosen.get(key(c.table, c.column));
      if (!now || sameLabel(now, was)) continue;
      const entry = { table: c.table, column: c.column, class: now.class, was: { class: was.class } };
      if (was.entityType) entry.was.entityType = was.entityType;
      if (was.phoneRegion) entry.was.phoneRegion = was.phoneRegion;
      if (now.class === "IDENTIFIER") entry.entityType = now.entityType;
      if (now.class === "IDENTIFIER" && now.entityType === "PHONE") entry.phoneRegion = now.phoneRegion;
      out.push(entry);
    }
    return out;
  }

  // unlabeled are the columns of the included tables that have no class
  // and that the person left blank: what "Mark the rest as not personal"
  // marks, folded tables included.
  unlabeled(included) {
    return this.of(included).filter((c) => this.current(c).class === "UNCLASSIFIED");
  }

  // problem is what stops Continue: a phone without its country.
  problem(included) {
    for (const e of this.changes(included)) {
      if (e.class === "IDENTIFIER" && e.entityType === "PHONE" && !REGION.test(e.phoneRegion ?? "")) {
        return `Enter the country of the phone numbers in ${tableName(e.table)}.${e.column} as two letters, such as US.`;
      }
    }
    if (this.changes(included).length > MAX_LABELS) return `Label at most ${MAX_LABELS} columns at once.`;
    return "";
  }

  // request is what RunSetup carries: nothing on Skip, the changes on
  // Continue, and with "Mark the rest" the rest as PUBLIC entries when all
  // fit in 500, else restPublic.
  request(included, mode) {
    if (mode === "skip") return {};
    const changes = this.changes(included);
    const out = {};
    if (mode === "rest") {
      const rest = this.unlabeled(included).map((c) => ({ table: c.table, column: c.column, class: "PUBLIC", was: { class: "UNCLASSIFIED" } }));
      if (changes.length + rest.length <= MAX_LABELS) changes.push(...rest);
      else if (rest.length > 0) out.restPublic = true;
    }
    if (changes.length > 0) out.columnClasses = changes;
    return out;
  }
}

// restQuestion is the confirm before "Mark the rest as not personal", with
// the count of what it marks.
export function restQuestion(columns) {
  const tables = new Set(columns.map((c) => c.table)).size;
  const n = columns.length;
  return `Mark ${n} ${n === 1 ? "column" : "columns"} in ${tables} ${tables === 1 ? "table" : "tables"} as not personal?`;
}
