// node --test scripts/web-sri.test.mjs (run by make web-check)
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { imports, run } from "./web-sri.mjs";

const web = join(dirname(fileURLToPath(import.meta.url)), "..", "web");
const sri = (b) => "sha384-" + createHash("sha384").update(b).digest("base64");

// check copies web/ to a temp dir, lets edit change the approve page, and
// returns the exit code of --check and what it printed.
function check(edit) {
  const root = mkdtempSync(join(tmpdir(), "web-sri-"));
  const logged = [];
  const orig = console.error;
  try {
    cpSync(web, root, { recursive: true });
    const page = join(root, "approve", "index.html");
    const out = edit(readFileSync(page, "utf8"), root);
    writeFileSync(page, typeof out === "string" ? out : Buffer.from(out));
    console.error = (m) => logged.push(String(m));
    return { code: run("--check", root), out: logged.join("\n") };
  } finally {
    console.error = orig;
    rmSync(root, { recursive: true, force: true });
  }
}

const notEmbedded = (root) =>
  `<script type="module" src="../portal.sha256" integrity="${sri(readFileSync(join(root, "portal.sha256")))}"></script>`;

test("the pages as committed pass", () => {
  assert.deepEqual(check((h) => h), { code: 0, out: "" });
});

test("a script naming a file that is not embedded fails, after the sri block", () => {
  const r = check((h, root) => h.replace("<!-- sri:end -->", "<!-- sri:end -->\n  " + notEmbedded(root)));
  assert.equal(r.code, 1);
  assert.match(r.out, /\.\.\/portal\.sha256 is not an embedded file/);
});

test("a script naming a file that is not embedded fails, before the sri block", () => {
  const r = check((h, root) => h.replace("<!-- sri:begin", notEmbedded(root) + "\n  <!-- sri:begin"));
  assert.equal(r.code, 1);
  assert.match(r.out, /is not an embedded file/);
});

test("a modulepreload naming a file that is not embedded fails", () => {
  const r = check((h, root) => h.replace("<!-- sri:begin",
    `<link rel="modulepreload" href="../portal.sha256" integrity="${sri(readFileSync(join(root, "portal.sha256")))}">\n  <!-- sri:begin`));
  assert.equal(r.code, 1);
  assert.match(r.out, /is not an embedded file/);
});

test("a reference outside web/ or to another origin fails", () => {
  let r = check((h) => h.replace("<!-- sri:end -->", '<!-- sri:end -->\n  <script type="module" src="../../go.mod" integrity="sha384-AAAA"></script>'));
  assert.equal(r.code, 1);
  assert.match(r.out, /leaves the embedded files/);
  r = check((h) => h.replace("<!-- sri:end -->", '<!-- sri:end -->\n  <script type="module" src="https://example.com/x.js" integrity="sha384-AAAA"></script>'));
  assert.equal(r.code, 1);
  assert.match(r.out, /not relative/);
});

test("a script after the sri block without integrity, or with a stale hash, fails", () => {
  let r = check((h) => h.replace("<!-- sri:end -->", '<!-- sri:end -->\n  <script type="module" src="../lib/approve.js"></script>'));
  assert.equal(r.code, 1);
  assert.match(r.out, /not in a checked form/);
  r = check((h) => h.replace("<!-- sri:end -->", '<!-- sri:end -->\n  <script type="module" src="../lib/approve.js" integrity="sha384-AAAA"></script>'));
  assert.equal(r.code, 1);
  assert.match(r.out, /stale integrity/);
});

test("a decoy attribute cannot point the check at another file", () => {
  const decoys = [
    (h, root) => `<script type="module" data-src="../lib/approve.js" data-integrity="${sri(readFileSync(join(root, "lib", "approve.js")))}" src="../portal.sha256" integrity="${sri(readFileSync(join(root, "portal.sha256")))}"></script>`,
    (h, root) => `<script type="module" title='src="../lib/approve.js" integrity="${sri(readFileSync(join(root, "lib", "approve.js")))}"' src="../portal.sha256" integrity="${sri(readFileSync(join(root, "portal.sha256")))}"></script>`,
    (h, root) => `<SCRIPT type="module" src="../portal.sha256" integrity="${sri(readFileSync(join(root, "portal.sha256")))}"></SCRIPT>`,
    () => `<link rel="module&#112;reload" href="../portal.sha256">`,
  ];
  for (const tag of decoys) {
    const r = check((h, root) => h.replace("<!-- sri:end -->", "<!-- sri:end -->\n  " + tag(h, root)));
    assert.equal(r.code, 1);
    assert.match(r.out, /not in a checked form/);
  }
});

test("a stylesheet naming a file that is not embedded fails", () => {
  const r = check((h) => h.replace('href="../style.css"', 'href="../portal.sha256"'));
  assert.equal(r.code, 1);
  assert.match(r.out, /is not an embedded file/);
});

test("a modulepreload after the script fails", () => {
  const r = check((h, root) => h.replace("<!-- sri:end -->", `<!-- sri:end -->\n  <link rel="modulepreload" href="../lib/approve.js" integrity="${sri(readFileSync(join(root, "lib", "approve.js")))}">`));
  assert.equal(r.code, 1);
  assert.match(r.out, /after the module script/);
});

test("a page the browser could decode differently fails", () => {
  const withRepro = (h, root) => h.replace("<!-- sri:end -->", "<!-- sri:end -->\n  " + notEmbedded(root));
  const utf16 = (s) => Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(s, "utf16le")]);
  const cases = [
    [(h, root) => utf16(withRepro(h, root)), /not valid UTF-8/],
    [(h) => "\uFEFF" + h, /byte-order mark/],
    [(h) => h.replace("<!-- sri:end -->", "<!-- sri:end -->\n<scr\x1b(Bipt>"), /control byte 0x1b/],
    [(h) => h.replace('<meta charset="utf-8">', '<meta charset="utf-8">\n<meta charset="ISO-2022-JP">'), /exactly one charset/],
    [(h) => h.replace('<meta charset="utf-8">', ""), /exactly one charset/],
  ];
  for (const [edit, want] of cases) {
    const r = check(edit);
    assert.equal(r.code, 1);
    assert.match(r.out, want);
  }
});

test("a reference not in clean form fails", () => {
  const r = check((h) => h.replace('href="../lib/changes.js"', 'href="../lib//changes.js"'));
  assert.equal(r.code, 1);
  assert.match(r.out, /not in clean form/);
});

test("a second entry script must have its imports preloaded", () => {
  const r = check((h, root) => h.replace("<!-- sri:end -->",
    `<!-- sri:end -->\n  <script type="module" src="../lib/revert.js" integrity="${sri(readFileSync(join(root, "lib", "revert.js")))}"></script>`));
  assert.equal(r.code, 1);
  assert.match(r.out, /has no modulepreload with integrity/);
});

test("a block made inert by its context fails", () => {
  const entry = (root) => `<script type="module" src="../lib/approve.js" integrity="${sri(readFileSync(join(root, "lib", "approve.js")))}"></script>`;
  const wraps = [
    ["<template>", "</template>"],
    ["<noscript>", "</noscript>"],
    ["<meta name='x' content='", "'>"],
  ];
  for (const [open, close] of wraps) {
    const r = check((h, root) => h.replace("<!-- sri:begin", open + "\n  <!-- sri:begin").replace("<!-- sri:end -->", "<!-- sri:end -->\n  " + close + "\n  " + entry(root)));
    assert.equal(r.code, 1, open);
    assert.match(r.out, /head line is not in a checked form/, open);
  }
});

test("a meta tag after the head fails", () => {
  const r = check((h) => h.replace("</body>", '<meta http-equiv="content-type" content="text/html; ch&#97;rset=Shift_JIS">\n</body>'));
  assert.equal(r.code, 1);
  assert.match(r.out, /<meta after the head/);
});

const CSP = /^ *<meta http-equiv="Content-Security-Policy"[^\n]*\n/m;

test("a page without the fixed meta CSP line (default-src 'none') fails", () => {
  const edits = [
    (h) => h.replace(CSP, ""),
    (h) => h.replace("default-src 'none'", "default-src 'self'"),
    (h) => h.replace("form-action 'none'\">", "form-action 'none'; frame-src 'self'\">"),
    (h) => { const l = h.match(CSP)[0]; return h.replace(l, "").replace("<!-- sri:end -->\n", "<!-- sri:end -->\n" + l); },
    (h) => h.replace("  <!-- sri:begin", h.match(CSP)[0] + "  <!-- sri:begin"),
  ];
  for (const edit of edits) {
    const r = check(edit);
    assert.equal(r.code, 1, edit.toString());
    assert.match(r.out, /meta CSP line/, edit.toString());
  }
});

test("an iframe, object, embed or frame in the body fails", () => {
  const tags = [
    ['<iframe srcdoc="&lt;script type=module src=../portal.sha256&gt;&lt;/script&gt;"></iframe>', /<iframe after the head/],
    ['<object data="../portal.sha256"></object>', /<object after the head/],
    ['<EMBED src="../portal.sha256">', /<EMBED after the head/],
    ['<frameset><frame src="../portal.sha256"></frameset>', /<frame/],
  ];
  for (const [tag, want] of tags) {
    const r = check((h) => h.replace("</body>", tag + "\n</body>"));
    assert.equal(r.code, 1, tag);
    assert.match(r.out, want, tag);
  }
});

// scan runs the module scanner on one module (lib/m.js, next to lib/a.js).
function scan(src) {
  const root = mkdtempSync(join(tmpdir(), "web-sri-mod-"));
  try {
    mkdirSync(join(root, "lib"));
    writeFileSync(join(root, "lib", "a.js"), "export const a = 1;\n");
    writeFileSync(join(root, "lib", "m.js"), src);
    imports(root, new Set(["lib/a.js", "lib/m.js"]), join(root, "lib", "m.js"));
    return "";
  } catch (e) {
    return e.message;
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

test("the module scanner reads ordinary modules", () => {
  for (const src of [
    'import { a } from "./a.js";\nexport const b = a;\n',
    'import {\n  a,\n} from "./a.js";\n',
    'export { a } from "./a.js";\n',
    "// Tests import this module without a document.\nimport { a } from \"./a.js\";\n",
    '  // WebAuthn does not tell "x" from "y".\nconst k = await subtle.importKey("raw", s, "HKDF", false, []);\nif (typeof v === "object") {}\n',
  ]) assert.equal(scan(src), "", src);
});

test("the module scanner refuses what it cannot account for", () => {
  const cases = [
    ['const x = 1; import { a } from "./a.js";\n', /cannot account for/],
    ['const x = 1; export { a } from "./a.js";\n', /cannot account for/],
    ['/* x */ import { a } from "./a.js";\n', /cannot account for/],
    ['import(x)\nfrom\n"./a.js";\n', /dynamic import/],
    ['await import("./a.js");\n', /dynamic import/],
    ['await import/**/("./a.js");\n', /dynamic import/],
    ['await import /* a */ /* b */ ("./a.js");\n', /dynamic import/],
    ["const u = import.meta.url;\n", /cannot account for/],
    ['const s = "x"; const t = "import";\n', /cannot account for/],
    ['// note await import("./a.js");\n', /line terminator/],
    ['// note\rawait import("./a.js");\n', /line terminator/],
    ['const s = `\n// ${await import("./a.js")}\n`;\n', /dynamic import/],
    ['const s = `\n// ${new Worker("./a.js")}\n`;\n', /SRI does not cover/],
    ['new Worker("./a.js", { type: "module" });\n', /SRI does not cover/],
    ['new SharedWorker("./a.js");\n', /SRI does not cover/],
    ['new self["Worker"]("./a.js");\n', /SRI does not cover/],
    ['navigator.serviceWorker.register("./a.js");\n', /SRI does not cover/],
    ['importScripts("./a.js");\n', /SRI does not cover/],
    ['CSS.paintWorklet.addModule("./a.js");\n', /SRI does not cover/],
    ['document.body.append(el("iframe"));\n', /SRI does not cover/],
    ["f.srcdoc = s;\n", /SRI does not cover/],
    ['document.createElement("object");\n', /SRI does not cover/],
    ["document.createElement('embed');\n", /SRI does not cover/],
    ['d.innerHTML = "<embed src=x>";\n', /SRI does not cover/],
    ["d.innerHTML = `<object data=x>`;\n", /SRI does not cover/],
    ['d.innerHTML = "< frame src=x>";\n', /SRI does not cover/],
  ];
  for (const [src, want] of cases) assert.match(scan(src), want, src);
});

test("the portal manifest lists exactly the files web/embed.go embeds", () => {
  const root = mkdtempSync(join(tmpdir(), "web-manifest-"));
  const manifest = (mode) => spawnSync(process.execPath, [join(dirname(fileURLToPath(import.meta.url)), "web-manifest.mjs"), mode, root], { encoding: "utf8" });
  try {
    cpSync(web, root, { recursive: true });
    assert.equal(manifest("--check").status, 0);
    writeFileSync(join(root, "extra.txt"), "x\n");
    const embed = readFileSync(join(root, "embed.go"), "utf8");
    writeFileSync(join(root, "embed.go"), embed.replace("fonts/OFL.txt", "fonts/OFL.txt extra.txt"));
    assert.equal(manifest("--check").status, 1);
    assert.equal(manifest("--write").status, 0);
    assert.match(readFileSync(join(root, "portal.sha256"), "utf8"), /  extra\.txt\n/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
