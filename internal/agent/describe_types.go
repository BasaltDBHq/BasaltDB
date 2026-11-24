package agent

import (
	"context"
	"errors"
	"maps"
	"slices"
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/agentstore"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
	"github.com/basaltdbhq/basaltdb/internal/lib/pagination"
	"github.com/basaltdbhq/basaltdb/internal/pii"
)

// Catalog reads the structure of the store the agent can see, on the
// agent's own credential (CONTRACT.md, describe), in the store-neutral types
// of core/agentstore. The store's adapter fills the content; the service
// decides what is hidden.
type Catalog interface {
	// Resources lists the readable resources by namespace and name, and
	// counts the ones in user namespaces the agent cannot read.
	Resources(ctx context.Context) ([]agentstore.Resource, int, error)
	// Find returns namespace.name, or false when it is absent or unreadable.
	Find(ctx context.Context, namespace, name string) (agentstore.Resource, bool, error)
	// Describe reads one resource Find or Resources returned.
	Describe(ctx context.Context, ref agentstore.ResourceRef) (agentstore.Detail, error)
	// Guarded reports whether basalt init guards the resource, so its
	// writes run under the write policy; false where the guard predates
	// the record of it.
	Guarded(ctx context.Context, ref agentstore.ResourceRef) (bool, error)
	// Search finds readable resources by name, field or comment; exclude
	// lists fields never matched or named.
	Search(ctx context.Context, q string, exclude []agentstore.FieldRef, after *agentstore.Cursor, limit int) ([]agentstore.Match, error)
	// Structure is the sorted structure lines the catalog fingerprint hashes.
	Structure(ctx context.Context) ([]string, error)
	// Database is the database the credential connects to.
	Database() string
	// Host is the host that database is on (name and host only, never a
	// user, port or credential).
	Host() string
	// Limits are the read limits the agent's statements run within.
	Limits() action.Limits
}

// ClassResolver is the agent's PII classification, by field.
type ClassResolver interface {
	// Resolve is the classes of refs, in their order.
	Resolve(ctx context.Context, refs []agentstore.FieldRef) ([]pii.Class, error)
	// Secrets lists the SECRET fields: describe never lists, matches or
	// names them.
	Secrets(ctx context.Context) ([]agentstore.FieldRef, error)
	// CatalogFingerprint is agent_pii_catalog.fingerprint as hex, empty
	// before the first basalt classify.
	CatalogFingerprint(ctx context.Context) (string, error)
}

// noCatalog serves a service built without a catalog: every describe call
// is an engine defect (INTERNAL).
type noCatalog struct{}

var errNoCatalog = errors.New("describe: no catalog configured")

func (noCatalog) Resources(context.Context) ([]agentstore.Resource, int, error) {
	return nil, 0, errNoCatalog
}

func (noCatalog) Find(context.Context, string, string) (agentstore.Resource, bool, error) {
	return agentstore.Resource{}, false, errNoCatalog
}

func (noCatalog) Describe(context.Context, agentstore.ResourceRef) (agentstore.Detail, error) {
	return agentstore.Detail{}, errNoCatalog
}

func (noCatalog) Guarded(context.Context, agentstore.ResourceRef) (bool, error) {
	return false, errNoCatalog
}

func (noCatalog) Search(context.Context, string, []agentstore.FieldRef, *agentstore.Cursor, int) ([]agentstore.Match, error) {
	return nil, errNoCatalog
}

func (noCatalog) Structure(context.Context) ([]string, error) { return nil, errNoCatalog }

func (noCatalog) Database() string { return "" }

func (noCatalog) Host() string { return "" }

func (noCatalog) Limits() action.Limits { return action.Limits{} }

// noClasses serves a service built without PII classes: it cannot tell a
// SECRET field, so every describe call fails closed (INTERNAL).
type noClasses struct{}

var errNoClasses = errors.New("describe: no pii classes configured")

func (noClasses) Resolve(context.Context, []agentstore.FieldRef) ([]pii.Class, error) {
	return nil, errNoClasses
}

func (noClasses) Secrets(context.Context) ([]agentstore.FieldRef, error) { return nil, errNoClasses }

func (noClasses) CatalogFingerprint(context.Context) (string, error) { return "", errNoClasses }

const (
	// overviewInlineMax is the most visible resources the overview lists
	// inline; above it lists namespaces and points to search.
	overviewInlineMax = 50
	// overviewNamespacesMax is the most namespaces the large overview lists
	// (D-3): the ones with the most visible resources; the rest are counted.
	overviewNamespacesMax = 50
	// resourceCommentMax and searchCommentMax cap comments, in characters
	// (D-4): the full form and a search item.
	resourceCommentMax = 500
	searchCommentMax   = 120
	// describeQueryMax is the longest search query, in characters.
	describeQueryMax = 100
	// policyAllowedUpTo is the most rows a write is allowed without a hold;
	// up to MaxRetryRows it is held for approval, over it refused.
	policyAllowedUpTo = 10

	FormOverview = "OVERVIEW"
	FormSearch   = "SEARCH"
	FormResource = "RESOURCE"
)

// WritePolicy is the guard's write policy (CONTRACT.md, Approvals).
type WritePolicy struct {
	AllowedUpTo         int  `json:"allowedUpTo"`
	HeldUpTo            int  `json:"heldUpTo"`
	RefusedOver         int  `json:"refusedOver"`
	DeleteHeld          bool `json:"deleteHeld"`
	CascadedRowsCounted bool `json:"cascadedRowsCounted"`
}

// writePolicy is the one policy every guarded table has today.
var writePolicy = WritePolicy{
	AllowedUpTo: policyAllowedUpTo, HeldUpTo: guidance.MaxRetryRows, RefusedOver: guidance.MaxRetryRows,
	DeleteHeld: true, CascadedRowsCounted: true,
}

// SearchItem is one resource in the overview or a search page.
type SearchItem struct {
	Resource      string      `json:"resource"`
	Kind          string      `json:"kind"`
	EstimatedRows *int64      `json:"estimatedRows"`
	Matched       string      `json:"matched,omitempty"`
	Access        []action.Op `json:"access"`
	Comment       string      `json:"comment,omitempty"`
}

// StoreInfo names the store the agent is pointed at.
type StoreInfo struct {
	Kind     string `json:"kind"`
	Database string `json:"database"`
	Host     string `json:"host"`
}

// Counts are the overview's counts.
type Counts struct {
	Namespaces int `json:"namespaces"`
	Resources  int `json:"resources"`
	NotGranted int `json:"notGranted"`
}

// OverviewLimits are the read limits and the write policy.
type OverviewLimits struct {
	ReadRowLimit       int         `json:"readRowLimit"`
	StatementTimeoutMs int64       `json:"statementTimeoutMs"`
	WritePolicy        WritePolicy `json:"writePolicy"`
}

// NamespaceCount is one namespace of a large overview.
type NamespaceCount struct {
	Namespace string `json:"schema"`
	Resources int    `json:"tables"`
}

// OtherNamespaces counts the namespaces a large overview leaves out, and the
// visible resources in them.
type OtherNamespaces struct {
	Namespaces int `json:"schemas"`
	Resources  int `json:"tables"`
}

// Overview is describe's first form.
type Overview struct {
	Store           StoreInfo             `json:"store"`
	Fingerprint     string                `json:"fingerprint"`
	Counts          Counts                `json:"counts"`
	Limits          OverviewLimits        `json:"limits"`
	Resources       []SearchItem          `json:"resources,omitzero"`
	Namespaces      []NamespaceCount      `json:"namespaces,omitzero"`
	OtherNamespaces *OtherNamespaces      `json:"otherNamespaces,omitempty"`
	PersonMessage   string                `json:"personMessage,omitempty"`
	NextSteps       []toolresult.NextStep `json:"nextSteps,omitempty"`
	Update          *guidance.UpdateInfo  `json:"update,omitempty"`
}

// DescribeSearchParams are a search's validated arguments.
type DescribeSearchParams struct {
	pagination.Params
	Query string
}

// FieldPII is a field's PII class.
type FieldPII struct {
	Class      string `json:"class"`
	EntityType string `json:"entityType,omitempty"`
}

// Field is one visible field. Its JSON is name, type and nullable, then the
// members of Display, then expressionHidden, comment and pii.
type Field struct {
	Name     string
	Type     string
	Nullable bool
	// Display is what the store shows of the field (for Postgres its
	// default and generated): a value that encodes to a JSON object, or nil.
	Display any
	// ExpressionHidden is set when the field's display reads a hidden
	// field; Display is then the store's masked form.
	ExpressionHidden bool
	Comment          string
	PII              FieldPII
}

// MarshalJSON writes the field with Display's members in place.
func (f Field) MarshalJSON() ([]byte, error) {
	var o jsonObject
	o.add("name", f.Name)
	o.add("type", f.Type)
	o.add("nullable", f.Nullable)
	o.splice(f.Display)
	if f.ExpressionHidden {
		o.add("expressionHidden", true)
	}
	if f.Comment != "" {
		o.add("comment", f.Comment)
	}
	o.add("pii", f.PII)
	return o.close()
}

// FeatureGroup is one group of features in the answer: its visible items
// under Key and the hidden ones counted under hidden<Key>.
type FeatureGroup struct {
	Key    string
	Items  []any
	Hidden int
	// stable are Items as the fingerprint reads them.
	stable []any
}

// ResourceDetail is what the agent may see of one resource: hidden fields,
// and the features and expressions that touch them, only counted.
type ResourceDetail struct {
	Kind         string
	Comment      string
	Fields       []Field
	HiddenFields int
	// PrimaryKey names the identity fields; empty when there are none or
	// one is hidden (HiddenKeys).
	PrimaryKey []string
	HiddenKeys int
	Features   []FeatureGroup
	// Flags are the store's facts, by key, written in key order.
	Flags   map[string]any
	Stats   any
	Actions []action.Op
	// Policy is the write policy on a guarded resource the agent can write;
	// null otherwise.
	Policy *WritePolicy
}

// members writes the detail's members in answer order.
func (d *ResourceDetail) members(o *jsonObject) {
	o.add("kind", d.Kind)
	if d.Comment != "" {
		o.add("comment", d.Comment)
	}
	o.add("fields", d.Fields)
	o.add("hiddenFields", d.HiddenFields)
	if len(d.PrimaryKey) > 0 {
		o.add("primaryKey", d.PrimaryKey)
	}
	o.add("hiddenKeys", d.HiddenKeys)
	for _, g := range d.Features {
		o.add(g.Key, g.Items)
		o.add(hiddenKey(g.Key), g.Hidden)
	}
	for _, k := range slices.Sorted(maps.Keys(d.Flags)) {
		o.add(k, d.Flags[k])
	}
	if d.Stats != nil {
		o.add("stats", d.Stats)
	}
	o.add("actions", d.Actions)
	o.add("policy", d.Policy)
}

// hiddenKey is the key that counts a group's hidden features: indexes is
// counted in hiddenIndexes.
func hiddenKey(group string) string {
	return "hidden" + strings.ToUpper(group[:1]) + group[1:]
}

// Resource is describe's resource form: the detail, or only the name and
// fingerprint with Unchanged when ifFingerprint is current.
type Resource struct {
	// Form is the answer's form, set by the tool; empty leaves it out.
	Form        string
	Resource    string
	Fingerprint string
	Unchanged   bool
	Detail      *ResourceDetail
}

// MarshalJSON writes form, resource, fingerprint and unchanged, then the
// detail's members.
func (r Resource) MarshalJSON() ([]byte, error) {
	var o jsonObject
	if r.Form != "" {
		o.add("form", r.Form)
	}
	o.add("resource", r.Resource)
	o.add("fingerprint", r.Fingerprint)
	if r.Unchanged {
		o.add("unchanged", true)
	}
	if r.Detail != nil {
		r.Detail.members(&o)
	}
	return o.close()
}
