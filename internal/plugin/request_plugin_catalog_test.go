package plugin

import (
	"sort"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
	"github.com/basaltdbhq/basaltdb/internal/platform/mcpserver"
	"github.com/basaltdbhq/basaltdb/internal/testkit/stepcatalogtest"
)

// The request_plugin cases of the error and result catalogs run here, on the
// plugin use case: each builds the error or the result with the use case's
// own builders, and gets its steps from the use case's step builders, the way
// the agent's Failure gives them. Their keys are stepcatalogtest's
// PluginErrorKeys and PluginResultKeys; the agent's tests cover the rest of
// the catalog and require these keys beside their own.

// The plugin keeps its own copy of the protocol's upload key and value; they
// must not drift.
func TestUploadCopiesMatchTheProtocol(t *testing.T) {
	t.Parallel()
	require.Equal(t, mcpserver.MetaPluginUpload, MetaPluginUpload)
	require.Equal(t, mcpserver.PluginUpload(PluginUpload{UploadID: "a"}).UploadID, "a", "the same fields as the protocol's")
}

// withOperatedBy is an engine whose operatedBy is by.
func withOperatedBy(by string) option {
	return func(s *serviceSettings) {
		s.core.Commands = s.core.Commands.OperatedBy(by)
		s.links.Commands = s.core.Commands
	}
}

type catalogCase struct {
	tool string
	args map[string]any
	fail func(t *testing.T, s *testService) error
}

// step is the tool call the case answers, for the shared catalog checks.
func (c catalogCase) step() stepcatalogtest.Case {
	return stepcatalogtest.Case{Tool: c.tool, Args: c.args}
}

// failure is what the agent's Failure does with err for the plugin's cases:
// the error body, with the next steps and person message the catalog
// prescribes, which the use case's own refusals already carry.
func (s *Service) failure(t *testing.T, tool string, err error) *toolresult.ToolError {
	t.Helper()
	te := s.core.Errors.ToolError(err)
	entry, ok := guidance.Catalog().ErrorEntry(te.Code, te.Reason, tool)
	require.True(t, ok, "no catalog entry for %s %s %s", te.Code, te.Reason, tool)
	require.NotEmpty(t, te.NextSteps, "the plugin use case builds the steps of its refusals")
	require.NoError(t, guidance.CheckPersonMessage(te.PersonMessage))
	require.Equal(t, entry.PersonMessage, te.PersonMessage != "", "person message agrees with the catalog")
	return te
}

// pluginCatalogCases raise each PLUGIN_REFUSED reason: the tool's own
// refusals by the engine they are refused on, the engine's through the
// fake.
func pluginCatalogCases() map[string]catalogCase {
	source := map[string]any{"source": "/home/me/local-ner"}
	own := func(set ...option) func(*testing.T, *testService) error {
		return func(t *testing.T, s *testService) error {
			_, err := callPlugin(t, s.with(append([]option{withRequests(&fakePluginRequests{})}, set...)...), source, uploadMeta())
			return err
		}
	}
	engine := func(reason string) func(*testing.T, *testService) error {
		return func(t *testing.T, s *testService) error {
			refused := &PluginRefusedError{Reason: reason, Message: "refused: " + reason}
			_, err := callPlugin(t, s.with(withPagesOrigin("http://localhost:7878"), withRequests(&fakePluginRequests{err: refused})), source, uploadMeta())
			return err
		}
	}
	cases := map[string]catalogCase{
		stepcatalogtest.CaseKey(codePluginRefused, ReasonPluginAgentOperated, toolRequestPlugin): {toolRequestPlugin, source, own(agentOperated)},
		stepcatalogtest.CaseKey(codePluginRefused, ReasonPluginSameUserMode, toolRequestPlugin):  {toolRequestPlugin, source, own(withSameUser)},
		stepcatalogtest.CaseKey(codePluginRefused, ReasonPluginNoLocalPages, toolRequestPlugin):  {toolRequestPlugin, source, own(withoutLocalPages)},
		stepcatalogtest.CaseKey(codePluginRefused, ReasonPluginNoPortalLink, toolRequestPlugin):  {toolRequestPlugin, source, own(agentOperated, withSameUser, withPagesOrigin(""))},
	}
	for _, reason := range []string{
		ReasonPluginAgentNotAllowed, "BAD_MANIFEST", "NOT_TRUSTED", "UNKNOWN_AGENT", "UNSAFE_PATH", "TOO_MANY_PENDING", "GUARD_OUTDATED",
		"DATABASE_UNREACHABLE", "NAME_TAKEN", "CONFIG_ENTRY", "TOO_LARGE", "TOO_MANY_UPLOADS", "ENGINE_IS_ROOT",
	} {
		cases[stepcatalogtest.CaseKey(codePluginRefused, reason, toolRequestPlugin)] = catalogCase{toolRequestPlugin, source, engine(reason)}
	}
	return cases
}

func TestPluginCatalogCasesAreTheOnesTheAgentExpects(t *testing.T) {
	t.Parallel()
	keys := make([]string, 0, len(pluginCatalogCases()))
	for k := range pluginCatalogCases() {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	require.Equal(t, stepcatalogtest.PluginErrorKeys(), keys)
	seen := map[string]bool{}
	for _, e := range stepcatalogtest.CatalogOf(t).Errors {
		seen[stepcatalogtest.EntryKey(e)] = true
	}
	for _, k := range keys {
		require.True(t, seen[k], "a case without a catalog entry: %s", k)
	}
}

func TestEveryPluginCatalogErrorGivesTheCatalogsSteps(t *testing.T) {
	t.Parallel()
	for _, variant := range []struct{ name, goos, config, operatedBy string }{
		{"default config", "linux", "", ""},
		{"custom config", "darwin", "/srv/basalt/engine.json", ""},
		{"agent-operated", "linux", "", mcpcontract.OperatedByAgent},
		{"agent-operated custom config", "darwin", "/srv/basalt/engine.json", mcpcontract.OperatedByAgent},
	} {
		for key, kase := range pluginCatalogCases() {
			t.Run(variant.name+"/"+key, func(t *testing.T) {
				t.Parallel()
				s := newTestService(t, variant.goos, variant.config, withOperatedBy(variant.operatedBy))
				te := s.failure(t, kase.tool, kase.fail(t, s))
				stepcatalogtest.RequireObeysCatalog(t, kase.step(), te, variant.operatedBy)
			})
		}
	}
}

// resultCase builds one result of the catalog: the person's message and the
// next steps it carries, for the tool and the call that returned it.
type resultCase struct {
	tool string
	args map[string]any
	// build returns the result's personMessage and nextSteps.
	build func(t *testing.T, s *testService) (string, []toolresult.Link, []toolresult.NextStep)
	// openWithoutURL marks the one OPEN_LINK that names no url: the short
	// link the agent gave earlier.
	openWithoutURL bool
}

func resultKey(tool, kase string) string { return tool + "|" + kase }

func pluginResultCases() map[string]resultCase {
	state := func(st string) func(*testing.T, *testService) (string, []toolresult.Link, []toolresult.NextStep) {
		return func(t *testing.T, s *testService) (string, []toolresult.Link, []toolresult.NextStep) {
			out, err := s.pluginWaited(uuid.MustParse(casePluginApproval), PluginApprovalState{
				Name: "local-ner", Instance: "default", Agents: []string{"bot"}, State: st, ExpiresAt: s.core.Now().Add(time.Hour),
			}, true)
			require.NoError(t, err)
			return out.PersonMessage, out.Links, out.NextSteps
		}
	}
	wait := map[string]any{"approvalId": casePluginApproval}
	call := func(args map[string]any, opened PluginOpened) func(*testing.T, *testService) (string, []toolresult.Link, []toolresult.NextStep) {
		return func(t *testing.T, s *testService) (string, []toolresult.Link, []toolresult.NextStep) {
			out, err := callPlugin(t, s.with(withRequests(&fakePluginRequests{opened: opened}), withPasskeys(1)), args, uploadMeta())
			require.NoError(t, err)
			return out.PersonMessage, out.Links, out.NextSteps
		}
	}
	narrowed := openedPlugin()
	narrowed.Narrowed = true
	source := map[string]any{"source": "/home/me/local-ner"}
	remove := map[string]any{"name": "local-ner", "remove": true}
	return map[string]resultCase{
		resultKey(toolRequestPlugin, "REQUESTED"):  {tool: toolRequestPlugin, args: source, build: call(source, openedPlugin())},
		resultKey(toolRequestPlugin, "WAIT_ENDED"): {tool: toolRequestPlugin, args: wait, build: state(PluginStatePending), openWithoutURL: true},
		resultKey(toolRequestPlugin, "APPROVED"):   {tool: toolRequestPlugin, args: wait, build: state(PluginStateApproved)},
		resultKey(toolRequestPlugin, "RUNNING"):    {tool: toolRequestPlugin, args: wait, build: state(PluginStateRunning)},
		resultKey(toolRequestPlugin, "ENDED"):      {tool: toolRequestPlugin, args: wait, build: state(PluginStateEnded)},
		resultKey(toolRequestPlugin, "NARROWED"):   {tool: toolRequestPlugin, args: source, build: call(source, narrowed)},
		resultKey(toolRequestPlugin, "REMOVED"):    {tool: toolRequestPlugin, args: remove, build: call(remove, PluginOpened{})},
	}
}

func TestPluginResultCasesAreTheOnesTheAgentExpects(t *testing.T) {
	t.Parallel()
	keys := make([]string, 0, len(pluginResultCases()))
	for k := range pluginResultCases() {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	require.Equal(t, stepcatalogtest.PluginResultKeys(), keys)
	seen := map[string]bool{}
	for _, e := range stepcatalogtest.CatalogOf(t).Results {
		seen[resultKey(e.Tool, e.Case)] = true
	}
	for _, k := range keys {
		require.True(t, seen[k], "a case without a catalog entry: %s", k)
	}
}

func TestEveryPluginCatalogResultGivesTheCatalogsSteps(t *testing.T) {
	t.Parallel()
	for _, variant := range []struct{ name, goos, config string }{
		{"default config", "linux", ""},
		{"custom config", "darwin", "/srv/basalt/engine.json"},
	} {
		for _, entry := range stepcatalogtest.CatalogOf(t).Results {
			kase, ok := pluginResultCases()[resultKey(entry.Tool, entry.Case)]
			if !ok {
				continue // another domain's result: it runs in its own package
			}
			t.Run(variant.name+"/"+resultKey(entry.Tool, entry.Case), func(t *testing.T) {
				t.Parallel()
				s := newTestService(t, variant.goos, variant.config)
				person, links, steps := kase.build(t, s)
				stepcatalogtest.RequireObeysCatalogSteps(t, mcpcontract.ErrorSteps{PersonMessage: entry.PersonMessage, Steps: entry.Steps},
					stepcatalogtest.Case{Tool: kase.tool, Args: kase.args}, person, links, steps, kase.openWithoutURL)
			})
		}
	}
}
