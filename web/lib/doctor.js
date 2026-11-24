// The Update check's words (CONTRACT.md, The Update check): the check
// screen's rows from a doctor answer, the passkey list's lines, and the
// browser's hint after a removal. Pure functions only, so the local setup
// page and the connect page (persona 2) show the same screens.

// MAX_NAMED is how many unlabeled columns doctor names.
export const MAX_NAMED = 20;

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const DAY_MS = 86400000;
const WEEK_DAYS = 7;

const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;

// columnName is schema.table.column as the page shows it: without public.
export function columnName(name) {
  return String(name).startsWith("public.") ? String(name).slice("public.".length) : String(name);
}

// The words both pages' check screens share (the local page's rows here,
// the connect page's in connectupdate.js).

// needTitle is the check screen's title when n rows need the person.
export const needTitle = (n) => (n === 1 ? "1 thing needs you" : `${n} things need you`);

// ALL_GOOD is the check screen with nothing to fix: its title, the line
// under it and its ✓ rows before Passkeys.
export const ALL_GOOD = {
  title: "All good",
  sub: "BasaltDB is running and your agents can connect.",
  rows: ["Every column has a label", "Database certificate checked"],
};

// devicesText is the Passkeys row's line for n devices.
export const devicesText = (n) => plural(n, "device can approve", "devices can approve");

// unlabeledRow is the row for count unlabeled columns, names the first
// MAX_NAMED of them as the page shows them.
export function unlabeledRow(count, names) {
  const listed = names.slice(0, MAX_NAMED).join(", ");
  return { title: count === 1 ? "1 new column has no label" : `${count} new columns have no label`, text: count > MAX_NAMED ? `${listed}, …` : listed };
}

// NO_PASSKEY is the row for no passkey that can approve on the page's site.
export const NO_PASSKEY = { title: "No passkey can approve", text: "Your agents' larger writes wait until you add one." };

// certificateRow is the row for a new certificate on the database (doctor's
// CHANGED): the confirm step is its fix.
export function certificateRow(database) {
  return { title: `${database || "Your database"} renewed its security certificate`, text: "Your agents are paused until you confirm." };
}

// FIX_ORDER are the fixes a critical row's action starts, in the order the
// rows list them. UPDATE is the guard update, which opens its own job.
export const FIX_ORDER = ["TRUST", "UPDATE", "PASSKEY_ADD", "REPAIR"];

export const MAX_WARNINGS = 3;
export const READY_SUB = "BasaltDB is running and your agents can connect.";
export const ALL_SET = { title: "All set", text: "Close this tab and go back to your agent. It can work now.", later: "Run `basalt init` to change it." };
export const LEFT_NOTE = "you chose to leave them for now";

// localPasskeys counts the passkeys of origin: the devices that approve on
// this page's pages.
export function localPasskeys(passkeys, origin) {
  return (passkeys?.items ?? []).filter((k) => k?.origin === origin).length;
}

// columnKey is a column as doctor names it, schema.table.column: the
// labels page's table is schema.table, and a bare table is in public.
export function columnKey(table, column) {
  return `${String(table).includes(".") ? table : `public.${table}`}.${column}`;
}

// allLeft: every unlabeled column is one the person chose to leave.
const allLeft = (columns, left) => columns.length > 0 && columns.every((c) => left.includes(c));

// checkView is the check-up. Critical rows stop BasaltDB working and each
// carries its own fix; warning rows do not block and carry a link; OK rows
// have a check. left lists the unlabeled columns the person chose to leave
// (saved by the page). done is the Done button: enabled only with nothing
// critical open, else it says what unlocks it.
export function checkView(d, origin, left = []) {
  const crit = [];
  const warn = [];
  const unknown = d.passkeys?.state === "UNKNOWN";
  const critical = (job, title, text, action, why) => crit.push({ job, mark: "✕", tone: "critical", title, text, action, why });
  const cert = d.certificate?.state;
  if (cert === "CHANGED") {
    const r = certificateRow(d.certificate.database || d.database);
    critical("TRUST", r.title, r.text, "Check", "Confirm the certificate to finish. Until then, your agents are paused.");
  }
  if (cert === "MISMATCH") critical("TRUST", "The certificate BasaltDB trusts doesn't match its records", "Check it before BasaltDB connects again.", "Check", "Check the certificate to finish. Until then, BasaltDB may not connect.");
  if (d.guard?.state === "OUTDATED") {
    critical("UPDATE", "BasaltDB needs an update in your database", `A newer BasaltDB is running than the one installed in ${d.database ?? "your database"}.`, "Update", "Update BasaltDB in your database to finish.");
  }
  if (d.passkeys?.state === "NONE") critical("PASSKEY_ADD", NO_PASSKEY.title, NO_PASSKEY.text, "Add a passkey", "Add a passkey to finish. Until then, writes over 10 rows wait.");
  if (d.login?.code === "CREDENTIAL_REJECTED") critical("REPAIR", "Your agent can't log in", "Its database password was changed or removed.", "Fix", "Fix your agent's login to finish. Until then, it can't connect.");
  else if (d.login) critical(null, "Your agent can't connect", String(d.login.message ?? ""), "", "Your agent has to connect before setup is done.");
  // BasaltDB could not read the database and nothing else says why: it
  // cannot say it is running, so setup is not done.
  const cannotCheck = unknown && crit.length === 0;
  if (cannotCheck) critical(null, "BasaltDB can't check your database yet", "The rest is checked once BasaltDB can connect.", "", "BasaltDB has to reach your database before setup is done.");
  const labelCols = d.labels?.state === "UNLABELED" ? (d.labels.columns ?? []) : [];
  let leftNote = false;
  if (d.labels?.state === "UNLABELED") {
    const r = unlabeledRow(Number(d.labels.count) || 0, labelCols.map(columnName));
    leftNote = allLeft(labelCols, left);
    warn.push({ job: "LABELS", mark: "!", tone: "warning", title: r.title.replace(" new ", " "), text: leftNote ? `${r.text} · ${LEFT_NOTE}` : r.text, action: "Label", later: r.title.replace(" new ", " ") });
  }
  const devices = localPasskeys(d.passkeys, origin);
  const ok = [];
  if (!unknown && !d.login && cert === "OK") {
    if (d.labels?.state === "OK") ok.push({ job: null, mark: "✓", tone: "good", title: ALL_GOOD.rows[0], text: "", action: "" });
    ok.push({ job: null, mark: "✓", tone: "good", title: ALL_GOOD.rows[1], text: "", action: "" });
  }
  if (d.passkeys?.state === "OK") ok.push({ job: "MANAGE", mark: "✓", tone: "good", title: "Passkeys", text: devicesText(devices), action: "Manage" });
  const later = (title) => ({ job: null, mark: "·", tone: "later", title, text: "Checked once BasaltDB can connect.", action: "" });
  if (d.passkeys?.state === "UNKNOWN" && !cannotCheck) ok.push(later("Passkeys"));
  const shown = [...crit, ...warn.slice(0, MAX_WARNINGS), ...ok];
  const more = warn.slice(MAX_WARNINGS);
  const ready = crit.length === 0;
  return {
    title: ready ? "Ready" : needTitle(crit.length),
    sub: ready ? READY_SUB : unknown ? "The rest is checked once BasaltDB can connect." : "Fix it to finish setup.",
    rows: shown,
    more,
    need: crit.length,
    warnings: warn.length,
    done: { enabled: ready, why: ready ? "" : crit[0].why },
    allSet: { lines: ok.filter((r) => r.tone === "good").map((r) => (r.job === "MANAGE" ? `${r.title}: ${r.text}` : r.title)), later: warn.map((w) => w.later) },
  };
}

// laterText is the "Left for later" line of the All set screen.
export function laterText(later) {
  return later.length === 0 ? "" : `Left for later: ${later.join(", ")}. ${ALL_SET.later}`;
}

// fixQueue is the critical fixes for a doctor answer, in order. Warnings
// (the unlabeled columns) have no fix of their own to run.
export function fixQueue(d, origin) {
  const jobs = checkView(d, origin).rows.filter((r) => r.tone === "critical").map((r) => r.job).filter((j) => FIX_ORDER.includes(j));
  return FIX_ORDER.filter((j) => jobs.includes(j));
}

// dayMonth is a date as the list shows it: "3 Nov".
export function dayMonth(t) {
  const d = new Date(t);
  return `${d.getDate()} ${MONTHS[d.getMonth()]}`;
}

const startOfDay = (t) => {
  const d = new Date(t);
  d.setHours(0, 0, 0, 0);
  return d.getTime();
};

// usedText is when a passkey was last used: today, N days ago, N weeks
// ago or never.
export function usedText(lastUsedAt, now) {
  if (!lastUsedAt) return "never";
  const days = Math.max(0, Math.round((startOfDay(now) - startOfDay(lastUsedAt)) / DAY_MS));
  if (days === 0) return "today";
  if (days < WEEK_DAYS) return plural(days, "day ago", "days ago");
  return plural(Math.floor(days / WEEK_DAYS), "week ago", "weeks ago");
}

// originHost is the host of an origin, or the origin as it is.
function originHost(origin) {
  try {
    return new URL(origin).host;
  } catch {
    return String(origin ?? "");
  }
}

// passkeyLine is a passkey's line under its label. One of another origin
// than the page's names that site: it signs on its pages, not this one's.
export function passkeyLine(k, origin, now) {
  const on = k.origin && k.origin !== origin ? ` on ${originHost(k.origin)}` : "";
  return `Added ${dayMonth(k.createdAt)}${on} · used ${usedText(k.lastUsedAt, now)}`;
}

// passkeyItems are doctor's passkeys as the list shows them, oldest first.
export function passkeyItems(passkeys, origin, now) {
  return (passkeys?.items ?? [])
    .filter((k) => typeof k?.credentialId === "string")
    .map((k) => ({ credentialId: k.credentialId, rpId: String(k.rpId ?? ""), label: String(k.label || "Passkey"), line: passkeyLine(k, origin, now) }));
}

// PASSKEYS_NOTE is the note under the list.
export const PASSKEYS_NOTE =
  "Removing asks for the database's admin connection string, so it works even if the lost device was your only passkey. If you remove the last one, the page asks you to add one before agents can be approved again.";

// signalRemoved tells the browser a passkey of rpId is gone, so a password
// manager may hide it. It is a hint: a browser without it, or a call that
// fails, is a no-op.
export async function signalRemoved(pkc, rpId, credentialId) {
  if (!pkc || typeof pkc.signalUnknownCredential !== "function") return false;
  try {
    await pkc.signalUnknownCredential({ rpId, credentialId });
    return true;
  } catch {
    return false;
  }
}

// ---- Not your database (CONTRACT.md, Not your database) ----

// targetView is the confirm step's view (paintConfirm) of the databases the
// engine serves, as the reset's check names them from its own files.
export function targetView(databases) {
  const rows = [];
  for (const d of databases ?? []) {
    const port = Number.isInteger(d?.port) && d.port > 0 ? d.port : 5432;
    rows.push({ label: "Database", value: String(d?.database ?? ""), tone: "" });
    rows.push({ label: "Host", value: `${String(d?.host ?? "")}:${port}`, tone: "" });
  }
  return {
    title: "Is this your database?",
    sub: "Check these, then continue.",
    rows,
    ok: "",
    before: "",
    go: "Yes, this is it",
    weak: false,
    back: "No, this isn't mine",
    fingerprint: "",
  };
}

// RESET is what the page says after the person's No: the page resets
// nothing, basalt init asks for the administrator password.
export const RESET = {
  title: "Your computer asks for your password next",
  text: "You answered that this database isn't yours. To reset BasaltDB on this computer, type your computer's administrator password in the system dialog that opens. It deletes BasaltDB's setup on this computer and touches no database. If no dialog opens, ask your agent to run basalt init again.",
};
