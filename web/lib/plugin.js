// The plugin approval page (CONTRACT.md, Plugins, The plugin approval
// page): read the binding text and the settings text (from a long link's
// fragment, a hash link's request file, or the engine for a short link
// /plugins/<id>), check them, show what the binding says at one of three
// levels, and sign the binding with the person's passkey.
//
// The page takes nothing else as input. The level and every sentence are
// derived here from the binding; the settings are shown only once they hash
// to settingsSha256. A link that is not a plugin approval, settings that do
// not match, a value the contract does not know or an expired approval show
// an error and no approve button. From a long link the page sends nothing
// anywhere and shows a code for the agent; from a short link it posts the
// signature to the engine that served it, which relays it to Postgres.
import {
  CodeError,
  ENDPOINT_LOCAL,
  ENDPOINT_REMOTE,
  PluginLinkError,
  SETTINGS_MISMATCH,
  PORTAL,
  SIGNER_KNOWN,
  WRONG_KIND,
  checkPluginRequest,
  parsePluginRequest,
  pluginResponseJSON,
  relyingParty,
  storeText,
  visibleText,
} from "./codec.js";
import { fetchRequest, isLongLink, linkSecret, pageId, postResponse, RelayError, relayPaths } from "./local.js";
import { $, NO_CARRIER, el, fail, loadOrPaste, openSession, personText, relayFailure, setPill, showDone, showEngine, showRelayFailed, showWithdrawn, webauthnError, whenText, withdrawnText } from "./page.js";
import { BUSY, ENGINE_NOT_CONNECTED, VAULT_UNREACHABLE } from "./relay.js";
import { agentName } from "./scope.js";
import { pageTransport } from "./transport.js";

const PROMPT_TIMEOUT_MS = 120000;

// The page's fixed sentences, word for word as CONTRACT.md writes them
// (The plugin approval page); only the <…> parts are filled in, from the
// binding.
export const SENTENCES = Object.freeze({
  changeOnAgain: "You approved <name> before, and it was turned off. Turning it on again needs your approval.",
  change: "This changes <name>, which you approved before.",
  changeVersion: "Version <fromVersion> becomes <version>.",
  changeFiles: "Its files change, but its version stays <version>.",
  changeSigner: "Its publisher was <fromPublisher>; now it is <publisher>.",
  changeEndpoint: "It moves from <fromWhere> to <where>.",
  changeIsolation: "How it is kept apart from Basalt changes.",
  hooksAdded: "It gets new access to: <hookLabels>.",
  hooksRemoved: "It no longer gets: <hookLabels>.",
  namesAdded: "It now also looks for names in the text.",
  valuesAdded: "It now also looks for private values in the text.",
  namesRemoved: "It no longer looks for names in the text.",
  valuesRemoved: "It no longer looks for private values in the text.",
  egressAdded: "It now also connects to <hosts>.",
  egressRemoved: "It no longer connects to <hosts>.",
  agentsAdded: "It will now also be used for <agents>.",
  agentsRemoved: "It will no longer be used for <agents>.",
  settingsChanged: "Its settings change.",
  level1: "Published by Basalt.",
  level2: "Nobody vouches for this plugin. Add it only if you trust where it came from.",
  level3: "Nobody vouches for this plugin. It runs a stranger's program on the computer Basalt runs on, with the same access as Basalt itself, so it could read your database password and the key Basalt uses to hide private values.",
  tick: "I know who made this plugin and I trust them with my data.",
  remote: "It runs at <host>. Everything it sees is sent there.",
  remoteOnward: "Basalt cannot check what runs there or where it sends things next.",
  ownUser: "It runs on the computer Basalt runs on, as its own user, so it cannot read Basalt's files.",
  sameAccess: "It runs on the computer Basalt runs on, with the same access as Basalt itself.",
  noNetwork: "It says it needs no network. That is not enforced on the computer Basalt runs on.",
  egressLimit: "It says it connects only to <hosts>. That is not enforced on the computer Basalt runs on.",
  nameCue: "It also sees values from your database that appear in that text.",
  usedFor: "Used for: <agents>.",
  askedBy: "Asked by <agent>.",
  fingerprint: "Plugin fingerprint: <fingerprint>",
  portalSameUser: "Basalt runs on the agent's own computer, as the same user as the agent. Your approval decides whether Basalt runs this plugin. It cannot stop the agent from reading what Basalt can.",
  approved: "Approved. The plugin starts within a few seconds.",
});

// What each hook sees, in plain words, and the label of that access in a
// change's list (CONTRACT.md, The plugin approval page, What it sees).
export const HOOK_SEES = Object.freeze({
  "wire.detect": "It reads the text your agents send to the AI provider, before Basalt hides private values in it.",
  "feed.observe": "It is told what your agents do in the database, such as which tables they change and how many rows, never the values.",
  "approval.deliver": "It delivers your approval links. Anyone who can read where it delivers them can see the rows of writes waiting for your approval. Some links carry the whole request, so they can also see what the agent asked to run and why.",
  "classify.suggest": "It reads the names and types of your tables and columns, never their values, and suggests which ones hold private data.",
});
export const HOOK_LABELS = Object.freeze({
  "wire.detect": "the text your agents send to the AI provider",
  "feed.observe": "what your agents do in the database",
  "approval.deliver": "your approval links",
  "classify.suggest": "the names of your tables and columns",
});

const ROLES_ADDED = { NAME_CUE: SENTENCES.namesAdded, VALUE: SENTENCES.valuesAdded };
const ROLES_REMOVED = { NAME_CUE: SENTENCES.namesRemoved, VALUE: SENTENCES.valuesRemoved };
const LEVEL_LINES = { 1: SENTENCES.level1, 2: SENTENCES.level2, 3: SENTENCES.level3 };
const COMPUTER = "the computer Basalt runs on";
const FINGERPRINT_GROUP = 4;
const FINGERPRINT_GROUPS = 4;

// fill puts values into a template's <key> parts. A part with no value
// stays as it is, so a missing value shows rather than vanishes.
function fill(template, values) {
  return template.replace(/<(\w+)>/g, (part, key) => (key in values ? values[key] : part));
}

const publisher = (signer) => (signer === SIGNER_KNOWN ? "Basalt" : "unknown");
const where = (endpoint) => (endpoint.kind === ENDPOINT_LOCAL ? COMPUTER : endpoint.host);
const hosts = (list) => list.join(", ");
const agents = (roles) => roles.map(agentName).join(", ");
const hookLabels = (hooks) => hooks.map((h) => HOOK_LABELS[h]).join("; ");

// pluginLevel is the page's level, from signer, endpoint and isolation
// only: 1 for a known publisher; 2 for an unknown one that is fenced in
// (it runs at a URL, or locally as its own OS user); 3 for anything else.
// Nothing falls through to a calmer level than 3.
export function pluginLevel(b) {
  if (b.signer === SIGNER_KNOWN) return 1;
  if (b.endpoint.kind === ENDPOINT_REMOTE) return 2;
  if (b.endpoint.kind === ENDPOINT_LOCAL && b.isolation?.files === "OS_USER") return 2;
  return 3;
}

// changeLines are what a change binding leads with, in the contract's
// order; null for a binding without change.
export function changeLines(b) {
  if (!("change" in b)) return null;
  const c = b.change;
  if (Object.keys(c).length === 0) return [fill(SENTENCES.changeOnAgain, { name: b.name })];
  const out = [fill(SENTENCES.change, { name: b.name })];
  if ("fromVersion" in c) out.push(fill(SENTENCES.changeVersion, { fromVersion: c.fromVersion, version: b.version }));
  else if ("fromManifestSha256" in c) out.push(fill(SENTENCES.changeFiles, { version: b.version }));
  if ("fromSigner" in c) out.push(fill(SENTENCES.changeSigner, { fromPublisher: publisher(c.fromSigner), publisher: publisher(b.signer) }));
  if ("fromEndpoint" in c) out.push(fill(SENTENCES.changeEndpoint, { fromWhere: where(c.fromEndpoint), where: where(b.endpoint) }));
  // fromIsolation is null when the earlier entry was REMOTE: still a change.
  if ("fromIsolation" in c) out.push(SENTENCES.changeIsolation);
  if ("hooksAdded" in c) out.push(fill(SENTENCES.hooksAdded, { hookLabels: hookLabels(c.hooksAdded) }));
  if ("hooksRemoved" in c) out.push(fill(SENTENCES.hooksRemoved, { hookLabels: hookLabels(c.hooksRemoved) }));
  for (const r of c.rolesAdded ?? []) out.push(ROLES_ADDED[r]);
  for (const r of c.rolesRemoved ?? []) out.push(ROLES_REMOVED[r]);
  if ("egressAdded" in c) out.push(fill(SENTENCES.egressAdded, { hosts: hosts(c.egressAdded) }));
  if ("egressRemoved" in c) out.push(fill(SENTENCES.egressRemoved, { hosts: hosts(c.egressRemoved) }));
  if ("agentsAdded" in c) out.push(fill(SENTENCES.agentsAdded, { agents: agents(c.agentsAdded) }));
  if ("agentsRemoved" in c) out.push(fill(SENTENCES.agentsRemoved, { agents: agents(c.agentsRemoved) }));
  if (c.settingsChanged === true) out.push(SENTENCES.settingsChanged);
  return out;
}

// whereLines say where it runs, then, on the portal, that Basalt and the
// agent share one OS user, then a declared limit this machine does not
// enforce. At level 3 the warning already says it runs with Basalt's
// access.
function whereLines(b, level, portal) {
  const out = [];
  if (b.endpoint.kind === ENDPOINT_REMOTE) out.push(fill(SENTENCES.remote, { host: b.endpoint.host }), SENTENCES.remoteOnward);
  else if (b.isolation.files === "OS_USER") out.push(SENTENCES.ownUser);
  else if (level === 1) out.push(SENTENCES.sameAccess);
  // The one sentence not derived from the binding (CONTRACT.md, Plugin
  // approval through the portal): only an agent-operated engine hands over
  // a portal plugin link, and its agent could choose the binding's detail.
  if (portal) out.push(SENTENCES.portalSameUser);
  if (b.endpoint.kind === ENDPOINT_LOCAL && b.isolation.network !== "ENFORCED") {
    out.push(b.egress.length === 0 ? SENTENCES.noNetwork : fill(SENTENCES.egressLimit, { hosts: hosts(b.egress) }));
  }
  return out;
}

function seesLines(b) {
  const out = [];
  for (const h of b.hooks) {
    out.push(HOOK_SEES[h]);
    if (h === "wire.detect" && b.roles.includes("NAME_CUE")) out.push(SENTENCES.nameCue);
  }
  return out;
}

function fingerprint(sha) {
  const groups = [];
  for (let i = 0; i < FINGERPRINT_GROUPS; i++) groups.push(sha.slice(i * FINGERPRINT_GROUP, (i + 1) * FINGERPRINT_GROUP));
  return groups.join(" ");
}

// pluginView is everything the page says about a checked binding, by
// section: the change first, then the level's line, the tick (level 3),
// where it runs, what it sees, and who. portal is true on the portal's
// origin, where the page adds the shared-user sentence at every level.
export function pluginView(b, { portal = false } = {}) {
  const level = pluginLevel(b);
  return {
    level,
    change: changeLines(b),
    levelLine: LEVEL_LINES[level],
    tick: level === 3 ? SENTENCES.tick : null,
    where: whereLines(b, level, portal),
    sees: seesLines(b),
    who: [
      fill(SENTENCES.usedFor, { agents: agents(b.agents) }),
      fill(SENTENCES.askedBy, { agent: agentName(b.requestedBy) }),
      fill(SENTENCES.fingerprint, { fingerprint: fingerprint(b.manifestSha256) }),
    ],
  };
}

// pluginSentences are the page's sentences in the order it shows them.
export function pluginSentences(view) {
  return [...(view.change ?? []), view.levelLine, ...(view.tick ? [view.tick] : []), ...view.where, ...view.sees, ...view.who];
}

// The page's own words for a link it cannot use. The settings and kind
// ones are the contract's (Checks before anything is shown).
const NOT_A_PLUGIN = "This link is not a plugin approval. Nothing here can be approved.";
const SETTINGS_DIFFER = "The settings in this link do not match what would be approved. Ask the agent for a new link.";
const LINK_GONE = "This plugin approval link is incomplete, was replaced by a newer one, or the approval is gone. Ask the agent for a new link.";
const PLUGIN_REFUSALS = { [WRONG_KIND]: NOT_A_PLUGIN, [SETTINGS_MISMATCH]: SETTINGS_DIFFER };

// A session through the Vault that cannot be opened, in a plugin
// approval's words (CONTRACT.md, Close codes): engine offline, broken, or
// try later. A plugin approval has no long link to offer instead.
export const PLUGIN_SESSION_TEXT = Object.freeze({
  vault: "This page cannot reach the BasaltDB Vault (relay.basaltvault.app), which carries it to your engine. Wait a minute and open the link again.",
  offline: "Your engine is not connected to the BasaltDB Vault right now. Ask the agent to check its status, then open the link again.",
  busy: "Your engine or the BasaltDB Vault is busy. Wait a minute and open the link again.",
  broken: "The secure session to your engine failed, and this page used nothing from it. Open the link again. If it keeps failing, ask the agent to check its status.",
});
const SESSION_TEXTS = new Map([[VAULT_UNREACHABLE, PLUGIN_SESSION_TEXT.vault], [ENGINE_NOT_CONNECTED, PLUGIN_SESSION_TEXT.offline], [BUSY, PLUGIN_SESSION_TEXT.busy]]);

function sessionText(told) {
  if (SESSION_TEXTS.has(told)) return SESSION_TEXTS.get(told);
  if (told.startsWith("The secure session to your engine failed")) return PLUGIN_SESSION_TEXT.broken;
  return told;
}

// describe is the sentence the page shows when its link cannot be used.
export function describe(err) {
  if (err?.name === "PluginLinkError") return PLUGIN_REFUSALS[err.reason] ?? `This plugin approval link cannot be used: ${err.message}`;
  const told = err?.name === "RelayError" ? sessionText(personText(err)) : "";
  if (told) return told;
  if (err?.name === "RelayError" && err.code === "NOT_FOUND") return LINK_GONE;
  if (err?.name === "RelayError") return `This plugin approval cannot be shown: ${err.message}`;
  if (err?.name === "TruncatedLinkError") {
    return `This plugin approval link looks cut short (${err.message}). Long links often break when copied from a chat. ` +
      "Ask the agent to send the link again, or to send the request file.";
  }
  return `This plugin approval link cannot be used: ${err?.message ?? err}`;
}

export function expiredText(at) {
  return `This plugin approval expired at ${at.toLocaleString()}. Nothing was approved; ask the agent for a new link.`;
}

// loadRequest reads the request: from the fragment of a long link (or the
// request file of a hash link, which page.js turns into one), or from the
// engine for a short link. relay holds the path to post the signature to,
// the link's secret and the session to the engine, null for a long link.
// A link the page refuses for what it says (another kind, settings that do
// not match) comes back as refused, so no paste box offers to read another.
async function loadRequest(hash) {
  const id = pageId(window.location.pathname, "plugins");
  try {
    if (isLongLink(hash)) {
      const req = await parsePluginRequest(hash);
      if (req.approvalId !== id) throw new CodeError("the link is for another plugin approval than its path");
      return { req, relay: null };
    }
    const paths = relayPaths("plugins", id);
    const secret = linkSecret(hash);
    // On the engine's own pages the same origin; on the portal a session
    // through the Vault to an agent-operated engine (CONTRACT.md, Plugin
    // approval through the portal).
    const session = await openSession(pageTransport(), { page: "plugins", id, secret });
    const req = await checkPluginRequest(await fetchRequest(session, paths.request, secret));
    if (req.approvalId !== id) throw new CodeError("the engine sent another plugin approval than this link's");
    return { req, relay: { path: paths.relay, secret, session } };
  } catch (err) {
    if (err instanceof PluginLinkError) return { refused: err };
    throw err;
  }
}

function sayAll(id, lines, className = "say") {
  $(id).replaceChildren(...lines.map((text) => el("p", className, visibleText(text))));
}

const ID_SHOWN = 8;

function render(req, view) {
  const b = req.binding;
  $("item-id").textContent = req.approvalId.slice(-ID_SHOWN);
  $("item-id").title = req.approvalId;
  $("plugin").textContent = `${b.name} ${b.version}`;
  $("instance").textContent = b.instance;
  $("store").textContent = visibleText(storeText(b.store));
  $("expires").textContent = b.expiresAt.toLocaleString();
  if (view.change !== null) {
    const [lead, ...rest] = view.change;
    $("change-lines").replaceChildren(el("p", "say plugin-change-lead", visibleText(lead)), ...rest.map((t) => el("p", "say", visibleText(t))));
    $("change").hidden = false;
  }
  $("level").className = `panel plugin-level level-${view.level}`;
  $("level-line").textContent = view.levelLine;
  // The tick starts unticked, whatever the browser restored.
  $("tick").checked = false;
  $("tick-box").hidden = view.tick === null;
  $("tick-text").textContent = view.tick ?? "";
  sayAll("where", view.where);
  sayAll("sees", view.sees);
  sayAll("who", view.who);
  // The settings text exactly as it hashed to settingsSha256.
  $("settings").textContent = visibleText(req.settingsText);
}

// allowed: the approve button works only on a short link (a long link has
// no engine to send the signature to), before the approval expires and, at
// level 3, only once the tick is set.
function allowed(state) {
  if (state.relay === null) return false;
  if (state.req.binding.expiresAt.getTime() <= state.now().getTime()) return false;
  return state.view.level !== 3 || $("tick").checked === true;
}

const TICK_FIRST = "Set the tick above to approve.";

function gate(state) {
  const ok = allowed(state);
  $("approve").disabled = !ok;
  if (state.relay === null) $("status").textContent = NO_CARRIER;
  else $("status").textContent = !ok && state.view.level === 3 && !$("tick").checked ? TICK_FIRST : "";
  return ok;
}

// finish relays the signed response to the engine that served the short
// link. Nothing is ever shown to paste: when the relay fails, the person
// opens the link again or asks the agent for a new one.
async function finish(response, relay) {
  try {
    await postResponse(relay.session, relay.path, relay.secret, pluginResponseJSON(response));
    showDone(SENTENCES.approved);
    setPill("state", "Approved", "ok");
  } catch (err) {
    // Withdrawn after the page opened: nothing is left to approve.
    const text = withdrawnText(err);
    if (text !== null) {
      showWithdrawn("state", text);
      return;
    }
    showRelayFailed(relayFailure(err, "approval"));
    setPill("state", "Not approved", "bad");
  }
}

async function approve(rp, state) {
  if (!gate(state)) return;
  const { req, relay } = state;
  $("approve").disabled = true;
  try {
    const cred = await navigator.credentials.get({
      publicKey: {
        challenge: req.challenge,
        rpId: rp.rpId,
        allowCredentials: req.credentialIds.map((id) => ({ type: "public-key", id })),
        userVerification: "required",
        timeout: PROMPT_TIMEOUT_MS,
      },
    });
    const r = cred.response;
    await finish(
      {
        approvalId: req.approvalId,
        credentialId: new Uint8Array(cred.rawId),
        authenticatorData: new Uint8Array(r.authenticatorData),
        clientDataJson: new Uint8Array(r.clientDataJSON),
        signature: new Uint8Array(r.signature),
      },
      relay,
    );
  } catch (err) {
    gate(state);
    $("status").textContent = webauthnError(err, req.credentialIds.length);
  }
}

// main runs the page; now is the clock, which tests set.
export async function main({ now = () => new Date() } = {}) {
  let rp;
  let loaded;
  try {
    rp = relyingParty(window.location);
    loaded = await loadOrPaste(loadRequest, describe);
  } catch (err) {
    const text = withdrawnText(err);
    if (text !== null) showWithdrawn("state", text);
    else fail(describe(err));
    return;
  }
  if (loaded.refused) {
    fail(describe(loaded.refused));
    return;
  }
  const { req, relay } = loaded;
  if (req.binding.expiresAt.getTime() <= now().getTime()) {
    setPill("state", "Expired", "bad");
    fail(expiredText(req.binding.expiresAt));
    return;
  }
  const state = { req, relay, now, view: pluginView(req.binding, { portal: window.location.origin === PORTAL }) };
  render(req, state.view);
  showEngine(relay?.session);
  setPill("state", `Waiting · expires ${whenText(req.binding.expiresAt, now())}`, "hold");
  $("main").hidden = false;
  gate(state);
  $("tick").addEventListener("change", () => gate(state));
  $("approve").addEventListener("click", () => approve(rp, state));
}

// Tests load the module without a document; only a page runs main.
if (typeof document !== "undefined") main();
