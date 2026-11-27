// Runs with `node --test web/lib/*.test.mjs` (make web-check). The plugin
// approval page (CONTRACT.md, The plugin approval page) runs on a fake DOM
// built from web/plugin/index.html, on the links Go writes for the shared
// vectors (api/plugin/approval/vectors.json, through
// internal/core/approval/testdata/plugin-links.json). What it shows must come
// only from the binding and the checked settings, at the level the binding
// warrants, and the approve button must work only when the contract lets
// it.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { deflateRawSync } from "node:zlib";

import { b64urlDecode, b64urlEncode, sha256, utf8 } from "./codec.js";
// Imported before any document exists, so the page's main() does not run.
import { HOOK_LABELS, HOOK_SEES, PLUGIN_SESSION_TEXT, SENTENCES, describe, main, pluginLevel, pluginSentences, pluginView } from "./plugin.js";
import { NO_CARRIER } from "./page.js";

const read = (path) => readFileSync(new URL(path, import.meta.url), "utf8");
const vectors = JSON.parse(read("../../api/plugin/approval/vectors.json")).vectors;
const goLinks = new Map(JSON.parse(read("../../internal/core/approval/testdata/plugin-links.json")).map((l) => [l.name, l]));
// The contract is CONTRACT.md, an index, and the section files it lists.
const contractIndex = read("../../CONTRACT.md");
const contract = [
  contractIndex,
  ...[...new Set([...contractIndex.matchAll(/\]\(contract\/([a-z0-9-]+\.md)\)/g)].map((m) => m[1]))].map((f) =>
    read(`../../contract/${f}`),
  ),
].join("\n");
const PAGE = read("../plugin/index.html");
const ORIGIN = "http://localhost:8787";
const vector = (name) => vectors.find((v) => v.name === name);

// A time before every vector expires, and one after.
const BEFORE = () => new Date("2026-11-19T12:00:00Z");
const AFTER = () => new Date("2026-11-22T00:00:00Z");

// fakeNode is one element of the page, from its tag in index.html.
function fakeNode(id, attrs) {
  const node = {
    id,
    hidden: /\shidden(\s|$|>)/.test(attrs),
    disabled: /\sdisabled(\s|$|>)/.test(attrs),
    className: /class="([^"]*)"/.exec(attrs)?.[1] ?? "",
    textContent: "",
    value: "",
    title: "",
    checked: false,
    files: [],
    children: [],
    listeners: {},
  };
  node.addEventListener = (type, fn) => {
    node.listeners[type] = fn;
  };
  node.replaceChildren = (...children) => {
    node.children = children;
  };
  node.setAttribute = () => {};
  node.select = () => {};
  node.classList = { toggle: () => {} };
  return node;
}

// fakePage builds the page's elements by id, in document order, and the
// browser around them: the location, fetch for a short link's engine, and
// the passkey prompt.
function fakePage({ href, fetch = null, WebSocket = undefined }) {
  const nodes = new Map();
  for (const m of PAGE.matchAll(/<[a-z0-9]+(\s[^>]*?\bid="([^"]+)"[^>]*)>/g)) nodes.set(m[2], fakeNode(m[2], m[1]));
  globalThis.document = {
    getElementById: (id) => nodes.get(id) ?? null,
    createElement: (tag) => Object.assign(fakeNode("", ""), { tag }),
    querySelector: () => null,
  };
  const url = new URL(href);
  globalThis.window = {
    location: { protocol: url.protocol, hostname: url.hostname, port: url.port, pathname: url.pathname, hash: url.hash, origin: url.origin },
    fetch,
    WebSocket,
  };
  const prompts = [];
  Object.defineProperty(globalThis, "navigator", {
    configurable: true,
    writable: true,
    value: {
      credentials: {
        get: async (options) => {
          prompts.push(options);
          return {
            rawId: new Uint8Array([1, 2, 3]).buffer,
            response: {
              authenticatorData: new Uint8Array([4]).buffer,
              clientDataJSON: utf8('{"type":"webauthn.get"}').buffer,
              signature: new Uint8Array([5, 6]).buffer,
            },
          };
        },
      },
    },
  });
  return { nodes, prompts, $: (id) => nodes.get(id) };
}

// shown are the page's sentences as a person reads them: every "say"
// element of a visible section, in document order.
function shown(nodes) {
  const out = [];
  const visible = (id) => !nodes.get(id).hidden;
  for (const [id, node] of nodes) {
    if (!visible("main")) break;
    if (id === "change-lines" && !visible("change")) continue;
    if (id === "tick-text" && !visible("tick-box")) continue;
    if (node.className.split(" ").includes("say") && node.textContent !== "") out.push(node.textContent);
    for (const child of node.children) {
      if (child.className.split(" ").includes("say")) out.push(child.textContent);
    }
  }
  return out;
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const SETTLE_MS = 5000;

// settle waits until the page shows something: its binding, an error, or
// the request box of a hash link.
async function settle(page) {
  const start = Date.now();
  while (["main", "error", "request-box"].every((id) => page.$(id).hidden)) {
    if (Date.now() - start > SETTLE_MS) throw new Error("the page showed nothing");
    await sleep(5);
  }
  // Let the last writes after the first one land.
  await sleep(5);
}

// open runs the page on a link and waits until it settled: a page that
// shows a paste box waits for the person, so main is not awaited.
async function open(href, { now = BEFORE, fetch = null, WebSocket = undefined } = {}) {
  const page = fakePage({ href, fetch, WebSocket });
  main({ now });
  await settle(page);
  return page;
}

function assertNoApprove(page, message) {
  assert.equal(page.$("main").hidden, true, "nothing of the binding is shown");
  assert.equal(page.$("error").hidden, false, "an error is shown");
  if (message) assert.equal(page.$("error-text").textContent, message);
  assert.equal(page.$("approve").disabled, true, "no approve button");
  assert.equal(page.$("approve").listeners.click, undefined, "the button is never wired");
  assert.equal(page.prompts.length, 0, "no passkey prompt");
}

for (const v of vectors.filter((x) => x.expect.settingsMatch === true)) {
  test(`${v.name}: level ${v.expect.level} and its sentences, word for word`, async () => {
    const page = await open(goLinks.get(v.name).url);
    assert.equal(page.$("error").hidden, true, page.$("error-text").textContent);
    assert.equal(page.$("main").hidden, false);
    assert.match(page.$("level").className, new RegExp(`\\blevel-${v.expect.level}\\b`));
    assert.deepEqual(shown(page.nodes), v.expect.sentences);
    assert.equal(page.$("tick-box").hidden, !v.expect.tick);
    // The settings exactly as they hashed to settingsSha256.
    assert.equal(page.$("settings").textContent, v.settings);
    const b = JSON.parse(v.binding);
    assert.equal(page.$("plugin").textContent, `${b.name} ${b.version}`);
    assert.equal(page.$("store").textContent, `Postgres \u00b7 ${b.store.name}`);
    if ("change" in b) {
      assert.equal(page.$("change").hidden, false, "a change leads with what changes");
      assert.equal(shown(page.nodes)[0], v.expect.sentences[0]);
      assert.match(page.$("change-lines").children[0].className, /plugin-change-lead/);
    } else {
      assert.equal(page.$("change").hidden, true);
    }
  });

  test(`${v.name}: a long link shows the approval but cannot be signed`, async () => {
    const page = await open(goLinks.get(v.name).url);
    assert.equal(page.$("main").hidden, false, "the approval is shown for review");
    assert.equal(page.$("approve").disabled, true, "no engine to send a signature to");
    assert.equal(page.$("status").textContent, NO_CARRIER);
    await page.$("approve").listeners.click();
    assert.equal(page.prompts.length, 0, "no passkey prompt");
  });

  test(`${v.name}: the approve button ${v.expect.tick ? "waits for the tick" : "works without a tick"}`, async () => {
    const id = JSON.parse(v.binding).approvalId;
    const e = engine({ approvalId: id, binding: v.binding, settings: v.settings, credentialIds: goLinks.get(v.name).credentialIds },
      { status: 200, body: JSON.stringify({ approvalId: id, status: "APPROVED", approvedAt: "2026-11-19T12:00:01Z" }) });
    const page = await open(`${ORIGIN}/plugins/${id}#s=q3Jv8sLk2mT0xYp1aBcD9w`, { fetch: e.fetch });
    const approve = page.$("approve");
    if (v.expect.tick) {
      assert.equal(approve.disabled, true, "level 3: off until the tick is set");
      await approve.listeners.click();
      assert.equal(page.prompts.length, 0, "a click on the disabled button asks for no passkey");
      page.$("tick").checked = true;
      page.$("tick").listeners.change();
      assert.equal(approve.disabled, false);
      page.$("tick").checked = false;
      page.$("tick").listeners.change();
      assert.equal(approve.disabled, true, "unticking turns it off again");
      page.$("tick").checked = true;
      page.$("tick").listeners.change();
    } else {
      assert.equal(approve.disabled, false);
    }
    await approve.listeners.click();
    assert.equal(page.prompts.length, 1);
    const prompt = page.prompts[0].publicKey;
    assert.equal(b64urlEncode(prompt.challenge), v.challenge, "the passkey signs sha256 of the binding text");
    assert.equal(prompt.userVerification, "required");
    assert.deepEqual(prompt.allowCredentials.map((c) => b64urlEncode(c.id)), goLinks.get(v.name).credentialIds);
    // The page posts the signature to the engine; nothing to paste.
    const body = JSON.parse(e.seen[1].init.body);
    assert.deepEqual(Object.keys(body), ["approvalId", "credentialId", "authenticatorData", "clientDataJson", "signature"]);
    assert.equal(body.approvalId, id);
    assert.ok(!page.$("code"), "the page has no code to copy");
  });
}

test("a reloaded page that kept the tick starts unticked", async () => {
  const v = vector("level-3-unknown-local");
  const page = fakePage({ href: goLinks.get(v.name).url });
  page.$("tick").checked = true;
  main({ now: BEFORE });
  await settle(page);
  assert.equal(page.$("tick").checked, false);
  assert.equal(page.$("approve").disabled, true);
});

test("settings that do not match settingsSha256: the contract's error, no approve button", async () => {
  const page = await open(goLinks.get("settings-mismatch").url);
  assertNoApprove(page, "The settings in this link do not match what would be approved. Ask the agent for a new link.");
  assert.equal(page.$("paste-box").hidden, true, "no other link would make these settings match");
});

test("a binding of another kind: not a plugin approval, no approve button", async () => {
  const page = await open(goLinks.get("wrong-kind").url);
  assertNoApprove(page, "This link is not a plugin approval. Nothing here can be approved.");
});

test("an expired binding shows an error and no approve button", async () => {
  const page = await open(goLinks.get("level-2-unknown-remote").url, { now: AFTER });
  assertNoApprove(page);
  assert.match(page.$("error-text").textContent, /^This plugin approval expired at .+\. Nothing was approved; ask the agent for a new link\.$/);
});

test("a link whose id is not its path's is refused", async () => {
  const link = goLinks.get("level-1-known-local").url.replace("/plugins/0193b2c4-5d6e-7f80-9a1b-2c3d4e5f6a7b", "/plugins/0193b2c4-5d6e-7f80-9a1b-2c3d4e5f6a70");
  assertNoApprove(await open(link));
});

// fragmentOf builds a format 2 link fragment for any two texts, as the
// compact form allows (plain strings, no shapes).
function fragmentOf(binding, settings) {
  return "2." + b64urlEncode(deflateRawSync(Buffer.from(JSON.stringify([[], [binding, settings]]))));
}

function linkFor(binding, settings) {
  return `${ORIGIN}/plugins/${JSON.parse(binding).approvalId}#${fragmentOf(binding, settings)}`;
}

// mutate rewrites a vector's binding, keeping its settings hash.
function mutate(name, change) {
  const v = vector(name);
  const b = JSON.parse(v.binding);
  change(b);
  return { binding: JSON.stringify(b), settings: v.settings };
}

test("the page reads a link it did not get from Go the same way", async () => {
  const v = vector("level-3-unknown-local");
  const page = await open(linkFor(v.binding, v.settings));
  assert.deepEqual(shown(page.nodes), v.expect.sentences);
});

const MUTATIONS = {
  "an unknown signer": ["level-3-unknown-local", (b) => { b.signer = "TRUSTED"; }],
  "an unknown files value": ["level-3-unknown-local", (b) => { b.isolation.files = "SANDBOX"; }],
  "an unknown network value": ["level-3-unknown-local", (b) => { b.isolation.network = "OFF"; }],
  "an unknown hook": ["level-3-unknown-local", (b) => { b.hooks = ["wire.detect", "wire.rewrite"]; }],
  "an unknown role": ["level-3-unknown-local", (b) => { b.roles = ["SECRET"]; }],
  "an unknown endpoint kind": ["level-3-unknown-local", (b) => { b.endpoint = { kind: "SANDBOXED" }; }],
  "KNOWN without signerKeyId": ["level-3-unknown-local", (b) => { b.signer = "KNOWN"; }],
  "UNKNOWN with a signerKeyId": ["level-3-unknown-local", (b) => { b.signerKeyId = "jNZPxNG5htlwfhg4ZgknAA"; }],
  "REMOTE with isolation": ["level-2-unknown-remote", (b) => { b.isolation = { files: "NONE", network: "NOT_ENFORCED" }; }],
  "LOCAL without isolation": ["level-3-unknown-local", (b) => { delete b.isolation; }],
  "REMOTE without a host": ["level-2-unknown-remote", (b) => { b.endpoint = { kind: "REMOTE" }; }],
  "LOCAL with a host": ["level-3-unknown-local", (b) => { b.endpoint = { kind: "LOCAL", host: "x.example:443" }; }],
  "a host that is not host:port": ["level-2-unknown-remote", (b) => { b.endpoint.host = "ner.acme.example:443 and more"; }],
  "wire.detect without roles": ["level-3-unknown-local", (b) => { delete b.roles; }],
  "roles without wire.detect": ["level-1-known-local", (b) => { b.roles = ["VALUE"]; }],
  "an unknown key": ["level-3-unknown-local", (b) => { b.trusted = true; }],
  "an unknown key in isolation": ["level-3-unknown-local", (b) => { b.isolation.sandbox = true; }],
  "a missing key": ["level-3-unknown-local", (b) => { delete b.requestedBy; }],
  "no agents": ["level-3-unknown-local", (b) => { b.agents = []; }],
  "an agent twice": ["level-3-unknown-local", (b) => { b.agents = ["agent:a", "agent:a"]; }],
  "a version that is not semantic": ["level-3-unknown-local", (b) => { b.version = "latest"; }],
  "an unknown change key": ["change-unknown-local", (b) => { b.change.trustChanged = true; }],
  "settingsChanged false": ["change-unknown-local", (b) => { b.change.settingsChanged = false; }],
  "an empty change list": ["change-unknown-local", (b) => { b.change.agentsAdded = []; }],
  "a change hook nobody knows": ["change-unknown-local", (b) => { b.change.hooksAdded = ["wire.rewrite"]; }],
};

// The control: every base the mutations start from renders when nothing
// is changed, so a refusal below is the mutation's.
for (const base of new Set(Object.values(MUTATIONS).map(([b]) => b))) {
  test(`unmutated ${base} renders through the same path`, async () => {
    const { binding, settings } = mutate(base, () => {});
    const page = await open(linkFor(binding, settings));
    assert.equal(page.$("main").hidden, false, page.$("error-text").textContent);
    assert.deepEqual(shown(page.nodes), vector(base).expect.sentences);
  });
}

for (const [name, [base, change]] of Object.entries(MUTATIONS)) {
  test(`refused, no approve button: ${name}`, async () => {
    const { binding, settings } = mutate(base, change);
    assertNoApprove(await open(linkFor(binding, settings)));
  });
}

test("a format 1 link is refused: a plugin approval link is format 2 only", async () => {
  const v = vector("level-3-unknown-local");
  const json = JSON.stringify({ approvalId: JSON.parse(v.binding).approvalId, binding: v.binding, settings: v.settings });
  const f1 = "1." + b64urlEncode(deflateRawSync(Buffer.from(json)));
  assertNoApprove(await open(`${ORIGIN}/plugins/${JSON.parse(v.binding).approvalId}#${f1}`));
});

test("settings with a key the contract does not know are refused", async () => {
  const v = vector("level-3-unknown-local");
  const settings = '{"endpoint": "https://elsewhere.example"}';
  const hash = Array.from(await sha256(utf8(settings)), (x) => x.toString(16).padStart(2, "0")).join("");
  const binding = v.binding.replace(/"settingsSha256": "[0-9a-f]{64}"/, `"settingsSha256": "${hash}"`);
  assertNoApprove(await open(linkFor(binding, settings)));
});

test("a hash link loads the request file the agent sent", async () => {
  const l = goLinks.get("change-unknown-local");
  const page = await open(l.hashLink);
  assert.equal(page.$("request-box").hidden, false);
  assert.equal(page.$("main").hidden, true);
  page.$("request-file").files = [{ size: l.requestText.length, text: async () => l.requestText }];
  await page.$("request-file").listeners.change();
  for (let i = 0; i < SETTLE_MS / 5 && page.$("main").hidden; i++) await sleep(5);
  assert.equal(page.$("main").hidden, false);
  assert.deepEqual(shown(page.nodes), vector("change-unknown-local").expect.sentences);
});

// engine is a fake engine for a short link: it serves request and records
// what the page posts, answering post (status, body).
function engine(request, post = { status: 200, body: "{}" }) {
  const seen = [];
  const fetch = async (path, init) => {
    seen.push({ path, init });
    const answer = init.method === "GET" ? { status: 200, body: JSON.stringify(request) } : post;
    return { status: answer.status, headers: [], text: async () => answer.body };
  };
  return { fetch, seen };
}

test("a short link reads the request from the engine and relays the signature", async () => {
  const v = vector("level-2-unknown-remote");
  const id = JSON.parse(v.binding).approvalId;
  const secret = "q3Jv8sLk2mT0xYp1aBcD9w";
  const e = engine({ approvalId: id, binding: v.binding, settings: v.settings, credentialIds: ["AQID"] },
    { status: 200, body: JSON.stringify({ approvalId: id, status: "APPROVED", approvedAt: "2026-11-19T12:00:01Z" }) });
  const page = await open(`${ORIGIN}/plugins/${id}#s=${secret}`, { fetch: e.fetch });
  assert.deepEqual(shown(page.nodes), v.expect.sentences);
  assert.equal(e.seen[0].path, `/api/v1/plugins/${id}`);
  assert.equal(e.seen[0].init.headers["basalt-link-secret"], secret);
  await page.$("approve").listeners.click();
  const post = e.seen[1];
  assert.equal(post.path, `/api/v1/plugins/${id}/approve`);
  assert.equal(post.init.method, "POST");
  assert.equal(post.init.headers["content-type"], "application/json");
  assert.equal(JSON.parse(post.init.body).approvalId, id);
  assert.equal(page.$("done-text").textContent, SENTENCES.approved);
  assert.ok(!page.$("code"), "no code to give: the engine took it");
});

test("a relay the engine refuses shows its error, and nothing to give by hand", async () => {
  const v = vector("level-1-known-local");
  const id = JSON.parse(v.binding).approvalId;
  const e = engine({ approvalId: id, binding: v.binding, settings: v.settings },
    { status: 409, body: JSON.stringify({ code: "APPROVAL_INVALID", message: "a newer approval replaced this one" }) });
  const page = await open(`${ORIGIN}/plugins/${id}#s=q3Jv8sLk2mT0xYp1aBcD9w`, { fetch: e.fetch });
  await page.$("approve").listeners.click();
  assert.match(page.$("done-text").textContent, /a newer approval replaced this one/);
  assert.match(page.$("done-text").textContent, /Open the link again/);
  assert.ok(!page.$("code"));
});

const WITHDRAWN_ANSWER = {
  status: 409,
  body: JSON.stringify({
    code: "APPROVAL_INVALID", reason: "WITHDRAWN", message: "plugin approval withdrawn by the agent",
    personMessage: "The agent withdrew this request: wrong plugin. Nothing changed.",
  }),
};

test("a plugin approval the agent withdrew shows Withdrawn and its line, with no approve button", async () => {
  const v = vector("level-1-known-local");
  const id = JSON.parse(v.binding).approvalId;
  const fetch = async () => ({ status: WITHDRAWN_ANSWER.status, headers: [], text: async () => WITHDRAWN_ANSWER.body });
  const page = await open(`${ORIGIN}/plugins/${id}#s=q3Jv8sLk2mT0xYp1aBcD9w`, { fetch });
  assert.equal(page.$("state").textContent, "Withdrawn");
  assert.equal(page.$("state").className, "pill bad");
  assert.equal(page.$("error-text").textContent, "The agent withdrew this request: wrong plugin. Nothing changed.");
  assert.equal(page.$("main").hidden, true, "nothing to approve");
  assert.equal(page.$("paste-box").hidden, true);
});

test("a page opened before the agent withdrew refuses the signature with the same line", async () => {
  const v = vector("level-1-known-local");
  const id = JSON.parse(v.binding).approvalId;
  const e = engine({ approvalId: id, binding: v.binding, settings: v.settings }, WITHDRAWN_ANSWER);
  const page = await open(`${ORIGIN}/plugins/${id}#s=q3Jv8sLk2mT0xYp1aBcD9w`, { fetch: e.fetch });
  await page.$("approve").listeners.click();
  assert.equal(page.$("state").textContent, "Withdrawn");
  assert.equal(page.$("error-text").textContent, "The agent withdrew this request: wrong plugin. Nothing changed.");
  assert.equal(page.$("main").hidden, true, "the approve button is gone");
});

test("the engine's request is checked as a link's: settings that do not match are refused", async () => {
  const v = vector("settings-mismatch");
  const id = JSON.parse(v.binding).approvalId;
  const e = engine({ approvalId: id, binding: v.binding, settings: v.settings });
  assertNoApprove(await open(`${ORIGIN}/plugins/${id}#s=q3Jv8sLk2mT0xYp1aBcD9w`, { fetch: e.fetch }),
    "The settings in this link do not match what would be approved. Ask the agent for a new link.");
});

test("the engine's request may carry nothing the contract does not list", async () => {
  const v = vector("level-2-unknown-remote");
  const id = JSON.parse(v.binding).approvalId;
  const e = engine({ approvalId: id, binding: v.binding, settings: v.settings, level: 1 });
  assertNoApprove(await open(`${ORIGIN}/plugins/${id}#s=q3Jv8sLk2mT0xYp1aBcD9w`, { fetch: e.fetch }));
});

// The branches the vectors do not reach, from bindings built here.
function binding(over) {
  return {
    kind: "PLUGIN", name: "p", hooks: ["feed.observe"], agents: ["agent:a"], egress: [], signer: "UNKNOWN",
    version: "2.0.0", store: { kind: "POSTGRES", name: "app" }, endpoint: { kind: "LOCAL" }, instance: "default", expiresAt: new Date(),
    isolation: { files: "NONE", network: "NOT_ENFORCED" }, approvalId: "x", requestedBy: "agent:a",
    manifestSha256: "c".repeat(64), settingsSha256: "d".repeat(64), ...over,
  };
}

test("the level comes from signer, endpoint and isolation, never calmer than warranted", () => {
  assert.equal(pluginLevel(binding({})), 3, "unknown, local, not fenced in");
  assert.equal(pluginLevel(binding({ isolation: { files: "OS_USER", network: "ENFORCED" } })), 2, "unknown, local, its own user");
  assert.equal(pluginLevel(binding({ endpoint: { kind: "REMOTE", host: "h:1" }, isolation: undefined })), 2);
  assert.equal(pluginLevel(binding({ signer: "KNOWN" })), 1);
});

test("where it runs, and a limit this machine does not enforce", () => {
  const ownUser = pluginSentences(pluginView(binding({ isolation: { files: "OS_USER", network: "ENFORCED" } })));
  assert.ok(ownUser.includes(SENTENCES.ownUser));
  assert.ok(!ownUser.includes(SENTENCES.noNetwork), "an enforced limit needs no line");
  const known = pluginSentences(pluginView(binding({ signer: "KNOWN" })));
  assert.ok(known.includes(SENTENCES.sameAccess), "a known publisher still gets the plain line");
  assert.ok(!known.includes(SENTENCES.tick));
  const declared = pluginSentences(pluginView(binding({ egress: ["a.example:443", "b.example:443"], isolation: { files: "OS_USER", network: "DECLARED" } })));
  assert.ok(declared.includes("It says it connects only to a.example:443, b.example:443. That is not enforced on the computer Basalt runs on."));
  const level3 = pluginSentences(pluginView(binding({})));
  assert.ok(!level3.includes(SENTENCES.sameAccess), "at level 3 the warning says it");
  assert.equal(level3[0], SENTENCES.level3);
  assert.equal(level3[1], SENTENCES.tick);
});

test("what each hook sees, in the binding's order", () => {
  const s = pluginSentences(pluginView(binding({ hooks: ["classify.suggest", "wire.detect"], roles: ["VALUE"] })));
  assert.ok(s.indexOf(HOOK_SEES["classify.suggest"]) < s.indexOf(HOOK_SEES["wire.detect"]));
  assert.ok(!s.includes(SENTENCES.nameCue), "only NAME_CUE sees database values");
});

test("every change key leads with its sentence, in the contract's order", () => {
  const view = pluginView(binding({
    signer: "KNOWN",
    endpoint: { kind: "REMOTE", host: "new.example:443" },
    isolation: undefined,
    agents: ["agent:a"],
    change: {
      fromManifestSha256: "a".repeat(64),
      fromSigner: "UNKNOWN",
      fromEndpoint: { kind: "LOCAL" },
      fromIsolation: { files: "NONE", network: "NOT_ENFORCED" },
      hooksAdded: ["approval.deliver", "classify.suggest"],
      hooksRemoved: ["wire.detect"],
      rolesRemoved: ["NAME_CUE", "VALUE"],
      egressRemoved: ["old.example:443"],
      agentsRemoved: ["agent:b", "agent:c"],
    },
  }));
  assert.deepEqual(view.change, [
    "This changes p, which you approved before.",
    "Its files change, but its version stays 2.0.0.",
    "Its publisher was unknown; now it is Basalt.",
    "It moves from the computer Basalt runs on to new.example:443.",
    "How it is kept apart from Basalt changes.",
    "It gets new access to: your approval links; the names of your tables and columns.",
    "It no longer gets: the text your agents send to the AI provider.",
    "It no longer looks for names in the text.",
    "It no longer looks for private values in the text.",
    "It no longer connects to old.example:443.",
    "It will no longer be used for b, c.",
  ]);
  // fromIsolation is null when the earlier entry ran at a URL: still a change.
  const fromRemote = pluginView(binding({ change: { fromIsolation: null } }));
  assert.ok(fromRemote.change.includes(SENTENCES.changeIsolation));
});

test("every fixed sentence is written in CONTRACT.md word for word", () => {
  for (const s of [...Object.values(SENTENCES), ...Object.values(HOOK_SEES), ...Object.values(HOOK_LABELS)]) {
    assert.ok(contract.includes(s), `CONTRACT.md does not state: ${s}`);
  }
});

test("on the portal the page says, at every level, that Basalt and the agent share one user, between where it runs and a declared limit", () => {
  for (const b of [binding({}), binding({ signer: "KNOWN" }), binding({ endpoint: { kind: "REMOTE", host: "ner.example:443" }, isolation: undefined })]) {
    const here = pluginView(b, { portal: true });
    assert.ok(here.where.includes(SENTENCES.portalSameUser), JSON.stringify(b.endpoint));
    assert.ok(!pluginView(b).where.includes(SENTENCES.portalSameUser), "not on the engine's own pages");
    const limit = here.where.findIndex((s) => s === SENTENCES.noNetwork || s.startsWith("It says it connects only to"));
    if (limit >= 0) assert.ok(here.where.indexOf(SENTENCES.portalSameUser) < limit, "before the declared limit");
  }
  assert.equal(SENTENCES.fingerprint, "Plugin fingerprint: <fingerprint>", "named apart from the engine's fingerprint");
});

const PORTAL_ORIGIN = "https://portal.basaltvault.app";

test("on the portal the page shows the shared-user sentence in its slot, and names the plugin's fingerprint apart", async () => {
  for (const name of ["level-1-known-local", "level-3-unknown-local", "level-2-unknown-remote"]) {
    const v = vector(name);
    const page = await open(goLinks.get(name).url.replace(ORIGIN, PORTAL_ORIGIN));
    assert.equal(page.$("error").hidden, true, page.$("error-text").textContent);
    const got = shown(page.nodes);
    const at = got.indexOf(SENTENCES.portalSameUser);
    assert.ok(at >= 0, name);
    // Every other sentence is the vector's, in its order.
    assert.deepEqual(got.filter((s) => s !== SENTENCES.portalSameUser), v.expect.sentences, name);
    const limit = got.findIndex((s) => s === SENTENCES.noNetwork || s.startsWith("It says it connects only to"));
    if (limit >= 0) assert.equal(at, limit - 1, `${name}: right before the declared limit`);
    const firstSees = got.findIndex((s) => Object.values(HOOK_SEES).includes(s));
    assert.ok(at < firstSees, `${name}: before what it sees`);
    assert.ok(got.some((s) => s.startsWith("Plugin fingerprint: ")), name);
    // A long link has no session, so no engine line.
    assert.equal(page.$("engine").hidden, true);
  }
  const local = await open(goLinks.get("level-3-unknown-local").url);
  assert.ok(!shown(local.nodes).includes(SENTENCES.portalSameUser), "not on the engine's own pages");
});

test("on the portal a short link opens a session through the Vault, and a Vault it cannot reach shows an error and no approve button", async () => {
  const sockets = [];
  class NoVault {
    constructor(url) {
      sockets.push(url);
      throw new Error("the Vault is not reachable");
    }
  }
  const id = vectors[0].binding.match(/"approvalId": "([^"]+)"/)[1];
  const page = await open(`${PORTAL_ORIGIN}/plugins/${id}#s=AAAAAAAAAAAAAAAAAAAAAA`, { WebSocket: NoVault });
  assert.equal(sockets.length, 1, "one socket, to the Vault");
  assert.match(sockets[0], /^wss:\/\/relay\.basaltvault\.app\/v1\/links\//);
  assertNoApprove(page, PLUGIN_SESSION_TEXT.vault);
});

test("a session that fails says so in a plugin approval's words, never offering a long link", async () => {
  const { BUSY, ENGINE_NOT_CONNECTED, VAULT_UNREACHABLE } = await import("./relay.js");
  const { RelayError } = await import("./local.js");
  const told = (personMessage) => describe(new RelayError("x", "UNAVAILABLE", 0, { personMessage }));
  assert.equal(told(VAULT_UNREACHABLE), PLUGIN_SESSION_TEXT.vault);
  assert.equal(told(ENGINE_NOT_CONNECTED), PLUGIN_SESSION_TEXT.offline);
  assert.equal(told(BUSY), PLUGIN_SESSION_TEXT.busy);
  assert.equal(told("The secure session to your engine failed (PROTOCOL), and this page used nothing from it."), PLUGIN_SESSION_TEXT.broken);
  for (const text of Object.values(PLUGIN_SESSION_TEXT)) assert.doesNotMatch(text, /long link|basalt approve|basalt revert/);
});
