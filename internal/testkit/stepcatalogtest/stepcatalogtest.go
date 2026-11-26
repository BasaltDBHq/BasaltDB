// Package stepcatalogtest is the check the engine's next steps catalog
// (api/mcp/errors/next-steps.json) imposes on a failure or a result: the steps
// of an answer are the catalog entry's, and every step obeys the contract's
// rules. Tests of every use case that builds steps share it.
package stepcatalogtest

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
	"github.com/basaltdbhq/basaltdb/internal/platform/mcpserver/mcptest"
)

// Case names the tool call an answer belongs to: a repeated call of it merges
// over Args.
type Case struct {
	Tool string
	Args map[string]any
}

func CaseKey(code, reason, tool string) string { return code + "|" + reason + "|" + tool }

func CatalogOf(t *testing.T) mcpcontract.NextSteps {
	t.Helper()
	c, err := mcpcontract.LoadNextSteps()
	require.NoError(t, err)
	return c
}

func EntryKey(e mcpcontract.ErrorSteps) string { return CaseKey(e.Code, e.Reason, e.Tool) }

// expectedSteps is what the catalog fixes for an entry with steps and
// personMessage on an engine operated by operatedBy: its agentOperated
// variant of kind on an agent-operated engine, if there is one, else its
// own steps with OPERATOR resolved (CONTRACT.md, Next steps on an
// agent-operated engine).
func ExpectedSteps(t *testing.T, kind, code, reason, tool string, steps []mcpcontract.StepKind, personMessage bool, operatedBy string) ([]mcpcontract.StepKind, bool, bool) {
	t.Helper()
	if operatedBy == mcpcontract.OperatedByAgent {
		if v, ok := CatalogOf(t).AgentOperatedEntry(kind, code, reason, tool); ok {
			return v.Steps, v.PersonMessage, true
		}
	}
	return Resolve(steps, operatedBy), personMessage, false
}

// requireOperatorRules checks the agent's commands on an engine operated by
// operatedBy: an AGENT command runs on the engine's machine and never needs
// the admin connection string (CO-9), so it is basalt init (with --remote
// exactly on an agent-operated engine) or, on an agent-operated engine, the
// engine's start; and a variant's personMessage names none of them.
func RequireOperatorRules(t *testing.T, steps []toolresult.NextStep, personMessage string, variant bool, operatedBy, where string) {
	t.Helper()
	for _, st := range steps {
		if st.Actor != toolresult.ActorAgent || st.Action != toolresult.ActionRunCommand {
			continue
		}
		// basalt init prints the link the person opens and never takes the
		// admin connection string (CONTRACT.md, basalt init); on an
		// agent-operated engine it names --remote.
		if strings.HasPrefix(st.Command, "basalt init") {
			require.Regexp(t, initCommand, st.Command, where)
			require.Equal(t, operatedBy == mcpcontract.OperatedByAgent, strings.Contains(st.Command, " --remote"),
				"%s: --remote exactly on an agent-operated engine: %q", where, st.Command)
			continue
		}
		require.Equal(t, mcpcontract.OperatedByAgent, operatedBy, "%s: on a person-operated engine the agent runs only basalt init: %q", where, st.Command)
		machine := serviceManager.MatchString(st.Command) ||
			strings.HasPrefix(st.Command, "basalt engine ")
		require.True(t, machine, "%s: an AGENT command is basalt init, the engine's start or basalt plugin enable, disable or remove: %q", where, st.Command)
		if variant {
			require.NotContains(t, personMessage, st.Command, "%s: personMessage names no command on the agent's machine", where)
		}
	}
	if variant {
		require.NotContains(t, personMessage, "sudo ", where)
		require.NotContains(t, personMessage, "basalt engine", where)
	}
}

func RequireObeysCatalog(t *testing.T, kase Case, te *toolresult.ToolError, operatedBy string) {
	t.Helper()
	entry, ok := CatalogOf(t).ErrorEntry(te.Code, te.Reason, kase.Tool)
	require.True(t, ok, "no catalog entry for %s %s %s", te.Code, te.Reason, kase.Tool)
	require.NotEmpty(t, te.Message, "the message stays")
	require.NotEmpty(t, te.NextSteps, "nextSteps is required")
	got := CatalogKinds(te.NextSteps)
	want, pm, variant := ExpectedSteps(t, mcpcontract.VariantError, entry.Code, entry.Reason, entry.Tool, entry.Steps, entry.PersonMessage, operatedBy)
	require.Equal(t, want, got, "(actor, action) sequence of %s", EntryKey(entry))
	require.Equal(t, pm, te.PersonMessage != "", "personMessage set exactly when the catalog says: %q", te.PersonMessage)
	RequireOperatorRules(t, te.NextSteps, te.PersonMessage, variant, operatedBy, EntryKey(entry))
	RequirePersonMessage(t, te.PersonMessage, te.Links)
	for i, st := range te.NextSteps {
		RequireStepObeysRules(t, st, kase, fmt.Sprintf("%s step %d", EntryKey(entry), i+1))
	}
	if te.Code == guidance.CodeInternal || te.Code == guidance.CodeUnavailable {
		require.NotEmpty(t, te.ErrorID, "errorId on UNAVAILABLE and INTERNAL")
	}
	if te.Code == guidance.CodeRowLimitExceeded {
		require.Equal(t, guidance.MaxRetryRows, te.NextSteps[2].MaxRows)
		require.Contains(t, te.NextSteps[2].Text, "only on an explicit yes", "AE-7")
	}
}

var conditionalWords = regexp.MustCompile(`(?i)\b(if|unless|otherwise)\b`)

var secretPattern = regexp.MustCompile(`(?i)(://|#s=|secret|token|postgres)`)

func RequireStepObeysRules(t *testing.T, st toolresult.NextStep, kase Case, where string) {
	t.Helper()
	require.Contains(t, mcpcontract.ActorActions[st.Actor], st.Action, where)
	require.NotEmpty(t, st.Text, where)
	require.LessOrEqual(t, len([]rune(st.Text)), guidance.MaxStepTextLength, where)
	require.Empty(t, conditionalWords.FindString(st.Text), "%s: no conditional steps: %q", where, st.Text)
	require.Empty(t, RemovedCommand.FindString(st.Text+" "+st.Command), "%s: a step names no removed command: %q %q", where, st.Text, st.Command)
	require.Empty(t, secretPattern.FindString(st.Command), "%s: a command never carries a secret: %q", where, st.Command)
	require.NotContains(t, strings.ReplaceAll(strings.ToLower(st.Command), "--rotate-password", ""), "password", where)
	require.LessOrEqual(t, st.WaitSeconds, guidance.MaxWaitSeconds, where)

	switch st.Action {
	case toolresult.ActionCallTool, toolresult.ActionReviseCall:
		requireToolArguments(t, st, kase, where)
	case toolresult.ActionRetrySmallerBatches:
		require.Positive(t, st.MaxRows, where)
		require.LessOrEqual(t, st.MaxRows, guidance.MaxRetryRows, where)
	case toolresult.ActionRunCommand:
		RequireCommand(t, st.Command, where)
	case toolresult.ActionOpenLink:
		require.NotEmpty(t, st.URL, where)
		if st.Command != "" {
			RequireCommand(t, st.Command, where)
		}
	}
	if st.Action != toolresult.ActionRetrySmallerBatches {
		require.Zero(t, st.MaxRows, where)
	}
	if st.Action != toolresult.ActionRunCommand && st.Action != toolresult.ActionOpenLink {
		require.Empty(t, st.Command, where)
	}
	if st.Action != toolresult.ActionOpenLink {
		require.Empty(t, st.URL, where)
	}
}

// serviceManager is a root command on the engine's machine: the service
// manager, or giving a lock file back to the engine's user
// (LOCK_FILE_UNUSABLE).
var serviceManager = regexp.MustCompile(`^sudo (systemctl|launchctl|chown) `)

// initCommand is the agent's basalt init as a step names it.
var initCommand = regexp.MustCompile(`^basalt init --agent bot( --remote)?$`)

func RequireCommand(t *testing.T, command, where string) {
	t.Helper()
	require.NotEmpty(t, command, where)
	if serviceManager.MatchString(command) {
		return
	}
	require.True(t, strings.HasPrefix(command, "basalt "), "%s: %q", where, command)
	if strings.HasPrefix(command, "basalt init") {
		// The one setup command (CONTRACT.md, Next steps): --agent, and
		// --remote on an agent-operated engine, never --config or a saved
		// flag.
		require.Regexp(t, initCommand, command, where)
		return
	}
	if strings.HasPrefix(command, "basalt engine ") { // the foreground engine names its config itself
		return
	}
	require.Fail(t, "a step names no other basalt command", "%s: %q", where, command)
}

func requireToolArguments(t *testing.T, st toolresult.NextStep, kase Case, where string) {
	t.Helper()
	tool, ok := mcpcontract.Find(mcpcontract.MustLoad(), st.Tool)
	require.True(t, ok, "%s: %q is not a contract tool", where, st.Tool)
	args := jsonMap(t, st.Arguments)
	if st.RepeatCall {
		require.Equal(t, kase.Tool, st.Tool, "%s: a repeated call is a call of the same tool", where)
		merged := jsonMap(t, kase.Args)
		for k, v := range args {
			if v == nil {
				delete(merged, k)
				continue
			}
			merged[k] = v
		}
		require.NoError(t, ValidateSchema(tool.InputSchema, merged), "%s: the repeated call's arguments", where)
		return
	}
	if st.Action == toolresult.ActionReviseCall {
		props, _ := tool.InputSchema["properties"].(map[string]any)
		for k := range args {
			require.Contains(t, props, k, "%s: %s has no argument %q", where, st.Tool, k)
		}
		return
	}
	if st.Tool == "confirm_database" {
		// The one CALL_TOOL whose arguments are not complete (CONTRACT.md,
		// Next steps): the engine never fills in the person's answer.
		require.NotContains(t, args, "answer", "%s: the engine never fills in answer", where)
		args["answer"] = "YES"
	}
	require.NoError(t, ValidateSchema(tool.InputSchema, args), "%s: arguments of %s must validate against its inputSchema", where, st.Tool)
}

func jsonMap(t *testing.T, v map[string]any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(v)
	require.NoError(t, err)
	out := map[string]any{}
	require.NoError(t, json.Unmarshal(raw, &out))
	return out
}

// validateSchema checks v against the subset of JSON Schema the tool input
// schemas use: type, required, properties, additionalProperties false, enum,
// minimum, minLength, maxLength, pattern, format uuid, items, maxItems, and
// oneOf (exactly one branch).
func ValidateSchema(schema map[string]any, v any) error {
	if branches, ok := schema["oneOf"].([]any); ok {
		matched := 0
		for _, b := range branches {
			if sub, ok := b.(map[string]any); ok && ValidateSchema(sub, v) == nil {
				matched++
			}
		}
		if matched != 1 {
			return fmt.Errorf("%v matches %d branches of oneOf, not one", v, matched)
		}
	}
	if types, ok := schemaTypes(schema["type"]); ok && !matchesAnyType(types, v) {
		return fmt.Errorf("%v is not of type %v", v, types)
	}
	if enum, ok := schema["enum"].([]any); ok && !containsValue(enum, v) {
		return fmt.Errorf("%v is not one of %v", v, enum)
	}
	switch x := v.(type) {
	case map[string]any:
		return validateObject(schema, x)
	case []any:
		return validateArray(schema, x)
	case string:
		return validateString(schema, x)
	case float64:
		if lower, ok := schema["minimum"].(float64); ok && x < lower {
			return fmt.Errorf("%v is below %v", x, lower)
		}
	}
	return nil
}

func validateObject(schema map[string]any, obj map[string]any) error {
	props, _ := schema["properties"].(map[string]any)
	if req, ok := schema["required"].([]any); ok {
		for _, r := range req {
			name, _ := r.(string)
			if _, present := obj[name]; !present {
				return fmt.Errorf("missing required argument %q", r)
			}
		}
	}
	for k, val := range obj {
		sub, known := props[k].(map[string]any)
		if !known {
			if schema["additionalProperties"] == false {
				return fmt.Errorf("unknown argument %q", k)
			}
			continue
		}
		if err := ValidateSchema(sub, val); err != nil {
			return fmt.Errorf("%s: %w", k, err)
		}
	}
	return nil
}

func validateArray(schema map[string]any, arr []any) error {
	if most, ok := schema["maxItems"].(float64); ok && float64(len(arr)) > most {
		return fmt.Errorf("%d items, at most %v", len(arr), most)
	}
	items, ok := schema["items"].(map[string]any)
	if !ok {
		return nil
	}
	for _, it := range arr {
		if err := ValidateSchema(items, it); err != nil {
			return err
		}
	}
	return nil
}

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func validateString(schema map[string]any, s string) error {
	n := float64(len([]rune(s)))
	if least, ok := schema["minLength"].(float64); ok && n < least {
		return fmt.Errorf("%q is shorter than %v", s, least)
	}
	if most, ok := schema["maxLength"].(float64); ok && n > most {
		return fmt.Errorf("a string longer than %v", most)
	}
	if p, ok := schema["pattern"].(string); ok && !regexp.MustCompile(p).MatchString(s) {
		return fmt.Errorf("%q does not match %s", s, p)
	}
	if schema["format"] == "uuid" && !uuidPattern.MatchString(s) {
		return fmt.Errorf("%q is not a uuid", s)
	}
	return nil
}

func schemaTypes(v any) ([]string, bool) {
	switch x := v.(type) {
	case string:
		return []string{x}, true
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			name, _ := e.(string)
			out = append(out, name)
		}
		return out, true
	}
	return nil, false
}

func matchesAnyType(types []string, v any) bool {
	for _, t := range types {
		switch {
		case t == "object" && isKind[map[string]any](v), t == "array" && isKind[[]any](v), t == "string" && isKind[string](v),
			t == "boolean" && isKind[bool](v), t == "null" && v == nil:
			return true
		case t == "number" && isKind[float64](v):
			return true
		case t == "integer":
			if f, ok := v.(float64); ok && f == float64(int64(f)) {
				return true
			}
		}
	}
	return false
}

func isKind[T any](v any) bool { _, ok := v.(T); return ok }

func containsValue(list []any, v any) bool {
	for _, e := range list {
		if e == v {
			return true
		}
	}
	return false
}

// requireObeysCatalogSteps checks a result's or warning's person message and
// steps against its catalog entry and the rules every step follows.
func RequireObeysCatalogSteps(t *testing.T, entry mcpcontract.ErrorSteps, kase Case, person string, links []toolresult.Link, steps []toolresult.NextStep, openWithoutURL bool) {
	t.Helper()
	got := CatalogKinds(steps)
	require.Equal(t, Resolve(entry.Steps, mcpcontract.OperatedByPerson), got, "(actor, action) sequence")
	require.Equal(t, entry.PersonMessage, person != "", "personMessage set exactly when the catalog says: %q", person)
	mcptest.Require(t, person, links)
	for i, st := range steps {
		if st.Action == toolresult.ActionOpenLink && st.URL == "" && openWithoutURL {
			st.URL = "http://localhost/the-link-given-earlier"
		}
		RequireStepObeysRules(t, st, kase, "step "+string(rune('1'+i)))
	}
}

// catalogKinds is the (actor, action) sequence of steps as the catalog lists
// it: without the SEND_REQUEST step the engine puts first when a result
// carries requestFile (CONTRACT.md, Next steps).
func CatalogKinds(steps []toolresult.NextStep) []mcpcontract.StepKind {
	got := make([]mcpcontract.StepKind, 0, len(steps))
	for i, st := range steps {
		if i == 0 && st.Action == toolresult.ActionSendRequest {
			continue
		}
		got = append(got, mcpcontract.StepKind{Actor: st.Actor, Action: st.Action})
	}
	return got
}

// requirePersonMessage is the engine's check of CONTRACT.md, Links in
// personMessage, for every personMessage the engine builds.
func RequirePersonMessage(t *testing.T, message string, links []toolresult.Link) {
	t.Helper()
	mcptest.Require(t, message, links)
	require.Empty(t, RemovedCommand.FindString(message), "a personMessage names no removed command (CONTRACT.md, Next steps): %q", message)
}

// removedCommand is a basalt command or init flag the person no longer runs
// ([Removed](contract/cli.md#removed)). --json and --forget count only on
// basalt init: the plugin steps, which the plugin epic replaces, still take
// --json.
var RemovedCommand = regexp.MustCompile(`basalt (approve|revert|upgrade|passkey|trust|access|status|portal|crash|service|log|classify|uninstall|tunnel)\b|--setup-code|--add-passkey|--rotate-password|--agent-rls|--new-code|rotate-key|basalt init\b[^\n]*?--(forget|json)`)

// Resolve returns steps with every OPERATOR step addressed to the agent when
// operatedBy is AGENT and to the person otherwise (PERSON, or a config the
// shim cannot read).
func Resolve(steps []mcpcontract.StepKind, operatedBy string) []mcpcontract.StepKind {
	actor := mcpcontract.ActorPerson
	if operatedBy == mcpcontract.OperatedByAgent {
		actor = mcpcontract.ActorAgent
	}
	out := make([]mcpcontract.StepKind, len(steps))
	for i, s := range steps {
		if s.Actor == mcpcontract.ActorOperator {
			s.Actor = actor
		}
		out[i] = s
	}
	return out
}

// CheckServed compares the tools a server lists with the contracts: every
// served tool needs a contract, and every IMPLEMENTED contract must be served.
func CheckServed(tools []mcpcontract.Tool, served []string) error {
	var errs []error
	servedSet := make(map[string]bool, len(served))
	for _, name := range served {
		servedSet[name] = true
		if _, ok := mcpcontract.Find(tools, name); !ok {
			errs = append(errs, fmt.Errorf("tool %q is served but has no contract in api/mcp/tools", name))
		}
	}
	for _, t := range tools {
		if t.Status == mcpcontract.StatusImplemented && !servedSet[t.Name] {
			errs = append(errs, fmt.Errorf("tool %q is %s but not served", t.Name, mcpcontract.StatusImplemented))
		}
	}
	return errors.Join(errs...)
}
