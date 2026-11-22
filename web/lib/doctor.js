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

// FIX_JOBS are the fixes a row's action starts, in the order "Fix these"
// walks them. UPDATE is the guard update, which opens its own job.
export const FIX_ORDER = ["TRUST", "UPDATE", "LABELS", "PASSKEY_ADD", "REPAIR"];

// localPasskeys counts the passkeys of origin: the devices that approve on
// this page's pages.
export function localPasskeys(passkeys, origin) {
  return (passkeys?.items ?? []).filter((k) => k?.origin === origin).length;
}

// checkView is the check screen for a doctor answer: its title, the line
// under it, and one row per finding, each { job, mark, title, text,
// action } (job null for a row without a fix). need counts the rows that
// need the person.
export function checkView(d, origin) {
  const rows = [];
  const unknown = d.labels?.state === "UNKNOWN" && d.passkeys?.state === "UNKNOWN";
  const need = (job, title, text, action) => rows.push({ job, mark: "!", title, text, action });
  const cert = d.certificate?.state;
  if (cert === "CHANGED") need("TRUST", "Your database has a new certificate", "BasaltDB stopped connecting until you check it.", "Check");
  if (cert === "MISMATCH") need("TRUST", "The certificate BasaltDB trusts doesn't match its records", "Check it before BasaltDB connects again.", "Check");
  if (d.guard?.state === "OUTDATED") {
    need("UPDATE", "BasaltDB needs an update in your database", `A newer BasaltDB is running than the one installed in ${d.database ?? "your database"}.`, "Update");
  }
  if (d.labels?.state === "UNLABELED") {
    const n = Number(d.labels.count) || 0;
    const names = (d.labels.columns ?? []).map(columnName).join(", ") + (n > MAX_NAMED ? ", …" : "");
    need("LABELS", n === 1 ? "1 new column has no label" : `${n} new columns have no label`, names, "Label");
  }
  if (d.passkeys?.state === "NONE") need("PASSKEY_ADD", "No passkey can approve", "Your agents' larger writes wait until you add one.", "Add");
  if (d.login?.code === "CREDENTIAL_REJECTED") need("REPAIR", "Your agent can't log in", "Its database password was changed or removed.", "Fix");
  else if (d.login) need(null, "Your agent can't connect", String(d.login.message ?? ""), "");
  const count = rows.length;
  const devices = localPasskeys(d.passkeys, origin);
  const passkeysRow = { job: "MANAGE", mark: "✓", title: "Passkeys", text: plural(devices, "device can approve", "devices can approve"), action: "Manage" };
  const later = (title) => ({ job: null, mark: "·", title, text: "Checked once BasaltDB can connect.", action: "" });
  if (count === 0) {
    return {
      title: "All good",
      sub: "BasaltDB is running and your agents can connect.",
      rows: [
        { job: null, mark: "✓", title: "Every column has a label", text: "", action: "" },
        { job: null, mark: "✓", title: "Database certificate checked", text: "", action: "" },
        passkeysRow,
      ],
      need: 0,
    };
  }
  if (d.labels?.state === "UNKNOWN") rows.push(later("Column labels"));
  if (d.passkeys?.state === "UNKNOWN") rows.push(later("Passkeys"));
  if (d.passkeys?.state === "OK") rows.push(passkeysRow);
  return {
    title: count === 1 ? "1 thing needs you" : `${count} things need you`,
    sub: unknown ? "The rest is checked once BasaltDB can connect." : "Everything else is working.",
    rows,
    need: count,
  };
}

// fixQueue is the fixes "Fix these" walks for a doctor answer, in order.
export function fixQueue(d, origin) {
  const jobs = checkView(d, origin).rows.map((r) => r.job).filter((j) => FIX_ORDER.includes(j));
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
