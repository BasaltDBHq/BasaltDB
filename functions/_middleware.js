// Cloudflare Pages Functions middleware for the portal (docs/deploy-portal.md):
// the connect page's policy. The logic and its tests are in
// web/edge/portal.js; web/_routes.json limits it to that page.
export { onRequest } from "../web/edge/portal.js";
