package agent

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
)

// personMessageKey is the JSON key of every personMessage in a result.
const personMessageKey = "personMessage"

// devLocalMessage puts the DEV_LOCAL_PAGES warning in front of pm, once;
// an empty pm stays empty.
func devLocalMessage(pm string) string {
	if pm == "" || strings.HasPrefix(pm, config.DevLocalPagesWarning) {
		return pm
	}
	return config.DevLocalPagesWarning + "\n\n" + pm
}

// DevLocalError is te with the warning on its personMessage and its held
// approval's, on a copy: te may be shared.
func DevLocalError(te *toolresult.ToolError) *toolresult.ToolError {
	out := *te
	out.PersonMessage = devLocalMessage(out.PersonMessage)
	if out.Approval != nil {
		a := *out.Approval
		a.PersonMessage = devLocalMessage(a.PersonMessage)
		out.Approval = &a
	}
	return &out
}

// DevLocalResult is the result v with the warning on every personMessage
// it holds, at any depth (results, warnings, list items, status problems).
// It goes through JSON so no result type is missed; numbers keep their text.
func DevLocalResult(v any) (any, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var tree any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&tree); err != nil {
		return nil, err
	}
	warnPersonMessages(tree)
	return tree, nil
}

func warnPersonMessages(v any) {
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			if s, ok := x.(string); ok && k == personMessageKey {
				t[k] = devLocalMessage(s)
				continue
			}
			warnPersonMessages(x)
		}
	case []any:
		for _, x := range t {
			warnPersonMessages(x)
		}
	}
}
