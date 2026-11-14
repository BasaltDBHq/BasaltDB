# Deploy the portal on Cloudflare Pages

The portal is the static copy of the approval, revert and passkey pages (`web/`) served at `https://portal.basaltvault.app`. There is no server code, no database and no accounts. A passkey made on the portal belongs to the `basaltvault.app` relying party, so the host has to be locked down: whoever can change these files can change what a person signs.

The pages run only at `https://portal.basaltvault.app` (`PORTAL` in `web/lib/codec.js`) or `http://localhost:<port>`, and refuse any other origin before they touch a passkey.

Design: [chat-only operator, section 5](redesign/specs/2026-11-12-chat-only-operator.md#5-the-portal-cloudflare-pages).

## What gets served

- `make portal-build` copies only the served files into `dist/portal`: `approve/`, `revert/`, `register/`, `passkeys/` (each `index.html`), `lib/*.js` (no `*.test.mjs`), `style.css`, `_headers` and `_redirects`. These are the files the engine embeds (`web/embed.go`); `embed.go`, `embed_test.go` and the tests are not published. Cloudflare serves `dist/portal`, not `web/`.
- Every script is pinned with subresource integrity. Each page lists its entry `<script type="module">` and one `<link rel="modulepreload">` per module it imports (directly or not), all with a `sha384` `integrity` hash, between `sri:begin` and `sri:end` comments, preloads first. The preload links are what make the browser check imported modules; an import map would need an inline script, which the CSP forbids. After editing `web/lib/*.js`, run `make web-sri` to refresh the hashes; `make web-check` and `go test ./web` fail on a missing or stale hash.
- `web/_redirects` rewrites (status 200) the engine's page paths to the page files: `/approvals/<id>` to `approve/`, `/reverts/<id>` to `revert/`, `/passkeys/register` to `register/`, `/passkeys/check` and `/passkeys/forget` to `passkeys/`. The pages load their scripts with `../lib/...`, which resolves to `/lib/...` from those paths. A test (`go test ./internal/engine/pages`) fails if the rules drift from the routes the engine serves.
- `web/_headers` sets the same headers the engine's own pages send (`internal/websec`): `Content-Security-Policy: default-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`, `Cross-Origin-Opener-Policy: same-origin`, and `.js` as `text/javascript`. On top it sets `Strict-Transport-Security: max-age=31536000; includeSubDomains` (portal only; the engine serves plain http). It is sent by `portal.basaltvault.app`, so `includeSubDomains` covers only that host's subdomains, never the rest of `basaltvault.app`. There is no `preload`.
- The policy allows scripts, styles and `fetch` from the page's own origin only. The pages have no inline scripts, inline styles or event handlers, and a test (`go test ./internal/websec`) fails if one is added or if `_headers` drifts from the engine's headers.
- `same-origin` COOP is safe here: the pages open no other windows, and the passkey calls (`navigator.credentials`) are same-origin WebAuthn in the page itself.

## 1. Lock down the accounts first

Do this before creating the project.

1. Turn on 2FA (a hardware key or authenticator app, not SMS) on the **Cloudflare** account that will own the project and the domain.
2. Turn on 2FA on the **GitHub** account(s) with write access to this repository, and on the GitHub organization (require 2FA for members).
3. Add a branch protection rule (or ruleset) for `master`: pull request required, no force pushes, no deletions, applies to admins.
4. Keep the number of people who can change DNS or the Pages project to the minimum, each with 2FA.

## 2. Create the Pages project

In the Cloudflare dashboard: Workers & Pages, Create, Pages, Connect to Git.

1. Install the Cloudflare Pages GitHub app on `BasaltDBHq/BasaltDB` **only** (choose "Only select repositories", never "All repositories"), and pick that repository.
2. Project name: `basalt-portal` (any name works; it only decides the `*.pages.dev` address).
3. Production branch: `master`.
4. Framework preset: None. Build command: `make portal-build`. Build output directory: `dist/portal`.
5. Save and deploy.

Then in the project settings, Builds and deployments:

- Turn **off** preview deployments for non-production branches (set "Branch control" to None for preview), so only `master` ever builds.
- Do not add environment variables or secrets. Nothing needs them.

## 3. Custom domain

1. Project, Custom domains, Set up a custom domain: `portal.basaltvault.app`.
2. Let Cloudflare create the CNAME to `<project>.pages.dev` (the `basaltvault.app` zone has to be on this Cloudflare account).
3. Wait until the domain shows Active and the certificate is issued.
4. Do not add a second custom domain. The engine accepts one portal origin only.

## 4. Lock the DNS

- Enable DNSSEC for the `basaltvault.app` zone and add the DS record at the registrar.
- Turn on the registrar lock (transfer lock) for the domain, with 2FA on the registrar account.
- Add a CAA record so only the certificate authorities you use can issue for `basaltvault.app`.
- If the plan has it, restrict who can edit the zone (Cloudflare account members, roles least privilege).
- Do not leave dangling records pointing at services you no longer use.

## 5. Ignore `*.pages.dev`

Cloudflare also serves the project at `<project>.pages.dev`, plus a URL per deployment. Those are **not page origins**. A passkey made there would not belong to `basaltvault.app`, and the compiled-in origin list refuses them: the pages will not run there, and the engine and the CLI refuse a `*.pages.dev` `pagesUrl`, `--pages-url` or `--passkey-origin`. Never put one in a link, a doc or a chat message. Optionally add a Cloudflare redirect rule from the `*.pages.dev` host to `https://portal.basaltvault.app`.

## 6. Verify

Use a real approval path (any UUID: the rewrite serves the page, which then reads its request from the engine). A 404 here means `_redirects` was not published. Links never end in a slash (`/approvals/<id>/` is not a route): on Pages such a path is not rewritten to a page, and the relative `../lib/` paths would break, so do not hand-write one. Pages `_redirects` cannot return a 404 rule to block it.

```sh
ID=0199c0de-0000-7000-8000-000000000000
[ "$(curl -s -o /dev/null -w '%{http_code}' "https://portal.basaltvault.app/approvals/$ID")" = 200 ] || { echo 'FAIL: /approvals/<id> is not 200'; exit 1; }
curl -sI "https://portal.basaltvault.app/approvals/$ID" | grep -iE 'content-security-policy|x-frame-options|referrer-policy|x-content-type-options|cross-origin-opener-policy|strict-transport-security'
curl -sI https://portal.basaltvault.app/lib/codec.js | grep -i content-type
curl -s -o /dev/null -w '%{http_code}\n' https://portal.basaltvault.app/lib/codec.test.mjs
```

Or let the binary check the files for you. `basalt portal verify` fetches every file embedded in the `basalt` binary (the four pages, `lib/*.js`, `style.css`, the fonts) from `https://portal.basaltvault.app`, compares their bytes, checks that each response carries the engine's `Content-Security-Policy` and that scripts are `text/javascript`, and fetches the routes people load (`/approvals/<id>`, `/reverts/<id>`, `/passkeys/...`, the ones `_redirects` rewrites to the pages) and compares those too, and flags a few paths the build never publishes (`embed.go`, the `*.test.mjs` files) if the host serves them. It prints one line per file (`OK`, `DIFFERS`, `MISSING`, `HEADER`, `UNEXPECTED`, `ERROR`) and exits `0` only when all is well; `--json` gives the same data. It needs no database and no engine, and with `--manifest FILE` it also checks the binary's pages against a release manifest (`web/portal.sha256` in the repository, a `sha256  path` list).

```sh
basalt portal verify
```

What it cannot catch: a portal that serves the right files to most people and different ones to one person, or different ones to a command-line client than to a browser (it sees only what it is served to it), a host that serves extra files under names it does not probe (a static host has no listing), and a compromised `basalt` download, since it trusts the pages inside the binary. After editing anything under `web/`, run `make web-sri`: it refreshes the integrity hashes in the pages and the manifest, and `make web-check` fails when they are stale.

Expected: `200` on the first line, all six headers above, `content-type: text/javascript` on modules, and `404` for `codec.test.mjs`. Repeat for `/reverts/$ID` and `/passkeys/register`. Open `/passkeys/register` in a browser and confirm the console shows no CSP violations.

## Changing the portal

A change goes in by pull request to `master` and deploys from there. Roll back by reverting the commit on `master` (or promoting an earlier deployment in the Cloudflare dashboard). If the account is ever in doubt, rotate the Cloudflare credentials, review the deployment history and the DNS records, and tell people to re-register their passkeys.
