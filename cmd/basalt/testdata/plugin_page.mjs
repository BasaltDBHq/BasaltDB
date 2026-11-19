// Runs the plugin approval page's own code (web/lib/codec.js and
// web/lib/plugin.js) on what a running engine or a command gave: the
// request GET /api/v1/plugins/{id} answered ("request" and its JSON), or a
// long link's fragment ("fragment" and the text after '#'). Prints what the
// page would show: its checks, level and sentences, and the settings text.
// Importing plugin.js with no document does not start the page.
import { checkPluginRequest, parsePluginRequest } from "../../../web/lib/codec.js";
import { pluginSentences, pluginView } from "../../../web/lib/plugin.js";

const [kind, input] = process.argv.slice(2);
const req = kind === "fragment" ? await parsePluginRequest(input) : await checkPluginRequest(JSON.parse(input));
const view = pluginView(req.binding);
process.stdout.write(
  JSON.stringify({ approvalId: req.approvalId, level: view.level, tick: view.tick, sentences: pluginSentences(view), settings: req.settingsText }),
);
