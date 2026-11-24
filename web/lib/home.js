// The home page at the root of the local pages: whether BasaltDB is running,
// with counts and health. The page has no login, so what it reads
// (GET /api/v1/home) holds counts, enum states and the check-up links only,
// and the words below never name a database or an agent. Text only goes into
// the page through textContent.

import { sameOriginSession } from "./transport.js";

const PROVIDERS = { SUPABASE: "Supabase", AMAZON_RDS: "Amazon RDS", POSTGRES: "Postgres" };

const UNREADABLE = "Checked once BasaltDB can reach your database";

const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;

export const providerName = (p) => PROVIDERS[p] ?? PROVIDERS.POSTGRES;

// guardRow is the Guard row: "ok", "need" or "unknown", and its words.
export function guardRow(guard) {
  if (guard === "CURRENT") return { mark: "ok", text: "Up to date in your database" };
  if (guard === "NEEDS_UPDATE") return { mark: "need", text: "Needs an update in your database" };
  return { mark: "unknown", text: UNREADABLE };
}

// passkeysRow is the Passkeys row for n devices, or null when unreadable.
export function passkeysRow(n) {
  if (!Number.isInteger(n)) return { mark: "unknown", text: UNREADABLE };
  if (n === 0) return { mark: "need", text: "No device can approve yet" };
  return { mark: "ok", text: `${plural(n, "device", "devices")} can approve` };
}

// checkLabels are the check-up buttons' labels: the provider's, with a
// number when several databases are of one kind.
export function checkLabels(checks) {
  const total = {};
  for (const c of checks) total[c.provider] = (total[c.provider] ?? 0) + 1;
  const seen = {};
  return checks.map((c) => {
    seen[c.provider] = (seen[c.provider] ?? 0) + 1;
    const label = `Check your ${providerName(c.provider)} setup`;
    return { label: total[c.provider] > 1 ? `${label} (${seen[c.provider]})` : label, href: c.href };
  });
}

// homeView is the page for the engine's answer: its title, the line under
// it as { bold, plain } parts, the health rows and the setup card.
export function homeView(h) {
  if (h?.state === "NOT_SET_UP") {
    return { title: "BasaltDB is installed", dot: false, sub: [{ plain: "Ask your agent to run " }, { code: "basalt init" }, { plain: " to set it up." }], rows: [], setup: null, changes: false };
  }
  if (h?.state === "STARTING") {
    return { title: "BasaltDB is starting", dot: false, sub: [{ plain: "Reload this page in a moment." }], rows: [], setup: null, changes: false };
  }
  if (h?.state !== "RUNNING") {
    return { title: "BasaltDB", dot: false, sub: [{ plain: "This page could not read the engine's state. Reload it." }], rows: [], setup: null, changes: false };
  }
  const sub = [{ bold: plural(h.agents, "agent", "agents") }];
  if (h.databases > 0) {
    sub.push({ plain: " on " }, { bold: plural(h.databases, "database", "databases") });
    if (h.providers?.length) sub.push({ plain: ` (${h.providers.map(providerName).join(", ")})` });
  }
  sub.push({ plain: ". Your agent sends you links here when a change needs your passkey." });
  const rows = [
    { title: "Engine", ...{ mark: "ok", text: `Running, ${h.version}` } },
    { title: "Guard", ...guardRow(h.guard) },
    { title: "Passkeys", ...passkeysRow(h.passkeys) },
  ];
  const checks = checkLabels(h.checks ?? []);
  const setup = checks.length
    ? { text: "Opens the check-up: certificate, passkeys and updates. Changes there need your passkey or the database admin string.", checks }
    : { text: "Ask your agent to run basalt init. It opens the check-up: certificate, passkeys and updates.", checks };
  return { title: "BasaltDB is running", dot: true, sub, rows, setup, changes: true };
}

const MARKS = { ok: "✓", need: "!", unknown: "–" };

function render(view) {
  const $ = (id) => document.getElementById(id);
  const el = (tag, className, text) => {
    const n = document.createElement(tag);
    if (className) n.className = className;
    if (text !== undefined) n.textContent = text;
    return n;
  };
  $("home-title").textContent = view.title;
  $("home-dot").hidden = !view.dot;
  const sub = $("home-sub");
  sub.replaceChildren(...view.sub.map((p) => (p.bold ? el("strong", "", p.bold) : p.code ? el("code", "", p.code) : document.createTextNode(p.plain))));
  const rows = $("home-rows");
  rows.replaceChildren(
    ...view.rows.map((r) => {
      const li = el("li", `home-row ${r.mark}`);
      const body = el("div");
      body.append(el("b", "", r.title), el("span", "muted", r.text));
      li.append(el("span", "home-mark", MARKS[r.mark]), body);
      return li;
    }),
  );
  rows.hidden = view.rows.length === 0;
  $("home-setup").hidden = !view.setup;
  if (view.setup) {
    $("home-setup-text").textContent = view.setup.text;
    $("home-checks").replaceChildren(
      ...view.setup.checks.map((c) => {
        const a = el("a", "button", c.label);
        a.href = c.href;
        return a;
      }),
    );
  }
  $("home-changes").hidden = !view.changes;
}

// REFRESH_MS is how often a page that is not showing a running engine asks
// again: right after the setup page finishes, the engine switches from its
// setup-only server to the full one within a second, and the page that was
// opened in between must not stay on "installed".
export const REFRESH_MS = 2000;

// stillChanging is true for an answer that is about to change by itself: no
// config yet, starting, or none at all.
export const stillChanging = (h) => h?.state !== "RUNNING";

async function read() {
  try {
    const session = sameOriginSession();
    const res = await session.request("GET", "/api/v1/home");
    session.close();
    if (res.status === 200) return JSON.parse(res.body);
  } catch {
    // the page says it could not read the state
  }
  return null;
}

async function main() {
  for (;;) {
    const answer = await read();
    render(homeView(answer));
    if (!stillChanging(answer)) return;
    await new Promise((resolve) => setTimeout(resolve, REFRESH_MS));
  }
}

if (typeof document !== "undefined") main();
