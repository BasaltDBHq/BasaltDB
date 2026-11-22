package pluginhost

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/basaltdbhq/basaltdb/internal/core/pluginproto"
)

// The files of a plugin's directory that are not in its manifest's files.
const (
	ManifestFile  = "basalt-plugin.json"
	SignatureFile = "basalt-plugin.json.sig"
)

// MaxManifestBytes bounds a manifest file. A manifest is a short JSON
// object; the bound keeps a hostile one from being read whole into memory.
const MaxManifestBytes = 1 << 20

// manifestVersion1 is the only manifestVersion this engine reads.
const manifestVersion1 = 1

// Bounds from api/plugin/manifest.schema.json.
const (
	maxPublisherRunes   = 100
	maxDescriptionRunes = 500
	maxArgs             = 64
	maxArgRunes         = 1024
	maxURLRunes         = 2048
	maxRelativePathLen  = 255
	maxEgress           = 64
	minMemoryMB         = 64
	maxMemoryMB         = 65536
	maxJSONDepth        = 64
	defaultHTTPSPort    = "443"
)

// Patterns from api/plugin/manifest.schema.json. ECMA-262 \s, which the
// schema's url pattern uses, also covers \v and the Unicode spaces that RE2's
// \s does not, so they are listed.
var (
	namePattern         = regexp.MustCompile(`^[a-z][a-z0-9-]{1,39}$`)
	versionPattern      = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`)
	protocolPattern     = regexp.MustCompile(`^basalt-plugin/[1-9][0-9]*$`)
	contractPattern     = regexp.MustCompile(`^[a-z][a-z0-9-]*/[1-9][0-9]*$`)
	namespacedPattern   = regexp.MustCompile(`^[a-z][a-z0-9-]{1,39}\.[A-Z][A-Z0-9_]{0,39}$`)
	relativePathPattern = regexp.MustCompile(`^[A-Za-z0-9_-][A-Za-z0-9._-]*(/[A-Za-z0-9_-][A-Za-z0-9._-]*)*$`)
	fileHashPattern     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	hostPortPattern     = regexp.MustCompile(`^(([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*|\[[0-9a-f:.]+\]|[0-9]{1,3}(\.[0-9]{1,3}){3}):[0-9]{1,5}$`)
	remoteURLPattern    = regexp.MustCompile(`^https://(([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*|\[[0-9a-f:.]+\]|[0-9]{1,3}(\.[0-9]{1,3}){3})(:[0-9]{1,5})?(/[^?#@\t\n\v\f\r \p{Z}\x{FEFF}]*)?$`)
)

// hookContracts is the message contract each v1 hook declares. The
// reserved wire.verdict has none: a manifest declaring it is refused.
//
//nolint:exhaustive // wire.verdict is refused before its contract is read
var hookContracts = map[Hook]string{
	HookWireDetect:      "detector/1",
	HookFeedObserve:     "feed/1",
	HookApprovalDeliver: "deliver/1",
	HookClassifySuggest: "classify/1",
}

// wellKnownEntityTypes are the token types any plugin may return.
var wellKnownEntityTypes = []string{"EMAIL", "PHONE", "PERSON_NAME", "ADDRESS", "OTHER", "CARD", "IBAN"}

// The roles a wire.detect plugin may declare.
const (
	RoleValue   = "VALUE"
	RoleNameCue = "NAME_CUE"
)

// The local transports.
var localTransports = []string{"jsonrpc-stdio", "jsonrpc-unix", "connectrpc"}

const remoteTransport = "connectrpc"

// ParseManifest reads a manifest's bytes and checks every rule of CONTRACT.md,
// Plugins, Manifest: the schema's shapes, the hook rules (wire.verdict, an
// unknown hook, wire.detect with feed.observe or approval.deliver are
// refused), a remote manifest without files, and the three rules the schema
// cannot state (the remote host is in egress, a namespaced entity type's
// prefix is the manifest's name, a local command is one of its files).
//
// It reads JSON more strictly than encoding/json: a key that appears twice,
// invalid UTF-8 and trailing data are refused, and keys match exactly, not
// case-insensitively. Unknown fields are ignored where the schema allows
// them. A refusal is a *VerifyError with reason BAD_MANIFEST; its text names
// the field and the rule, never a value from the manifest.
func ParseManifest(b []byte) (Manifest, error) {
	if len(b) > MaxManifestBytes {
		return Manifest{}, badManifest("the manifest is larger than 1 MiB")
	}
	if err := checkStrictJSON(b); err != nil {
		return Manifest{}, badManifest("the manifest is not valid JSON: " + err.Error())
	}
	top, ok := objectOf(b)
	if !ok {
		return Manifest{}, badManifest("the manifest is not a JSON object")
	}
	p := manifestParser{top: top}
	return p.parse()
}

type manifestParser struct {
	top jsonObject
	m   Manifest
}

func (p *manifestParser) parse() (Manifest, error) {
	for _, k := range []string{"manifestVersion", "name", "version", "publisher", "protocol", "hooks", "endpoint", "network"} {
		if _, ok := p.top[k]; !ok {
			return Manifest{}, badManifest(k + " is missing")
		}
	}
	if _, ok := p.top["entitlement"]; ok {
		return Manifest{}, badManifest("entitlement is reserved")
	}
	steps := []func() error{
		p.header, p.protocols, p.hooks, p.endpoint, p.files, p.network, p.resources,
		p.commandInFiles, p.remoteHostInEgress, p.recordFits,
	}
	for _, step := range steps {
		if err := step(); err != nil {
			return Manifest{}, err
		}
	}
	return p.m, nil
}

func (p *manifestParser) header() error {
	if v, ok := integerOf(p.top["manifestVersion"]); !ok || v != manifestVersion1 {
		return badManifest("manifestVersion must be 1")
	}
	p.m.ManifestVersion = manifestVersion1
	var ok bool
	if p.m.Name, ok = stringOf(p.top["name"]); !ok || !namePattern.MatchString(p.m.Name) {
		return badManifest("name must be lowercase letters, digits and dashes, 2 to 40 characters, starting with a letter")
	}
	if p.m.Version, ok = stringOf(p.top["version"]); !ok || !versionPattern.MatchString(p.m.Version) {
		return badManifest("version must be a semantic version")
	}
	if p.m.Publisher, ok = stringOf(p.top["publisher"]); !ok || p.m.Publisher == "" || utf8.RuneCountInString(p.m.Publisher) > maxPublisherRunes {
		return badManifest("publisher must be a string of 1 to 100 characters")
	}
	if raw, present := p.top["description"]; present {
		if p.m.Description, ok = stringOf(raw); !ok || utf8.RuneCountInString(p.m.Description) > maxDescriptionRunes {
			return badManifest("description must be a string of at most 500 characters")
		}
	}
	return nil
}

func (p *manifestParser) protocols() error {
	list, ok := stringsOf(p.top["protocol"])
	if !ok || len(list) == 0 || !unique(list) {
		return badManifest("protocol must be a non-empty list of distinct protocol versions")
	}
	for _, v := range list {
		if !protocolPattern.MatchString(v) {
			return badManifest("protocol lists a value that is not a basalt-plugin/N version")
		}
	}
	if !slices.Contains(list, pluginproto.Version1) {
		return badManifest("protocol must include " + pluginproto.Version1)
	}
	p.m.Protocol = list
	return nil
}

func (p *manifestParser) hooks() error {
	obj, ok := objectOf(p.top["hooks"])
	if !ok || len(obj) == 0 {
		return badManifest("hooks must be an object with at least one hook")
	}
	p.m.Hooks = make(map[string]pluginproto.HookDecl, len(obj))
	for name, raw := range obj {
		h := Hook(name)
		if h == HookWireVerdict {
			return badManifest("hooks: wire.verdict is reserved and refused")
		}
		if !h.Allowed() {
			return badManifest("hooks: names a hook this engine does not know")
		}
		decl, err := p.hookDecl(h, raw)
		if err != nil {
			return err
		}
		p.m.Hooks[name] = decl
	}
	if p.has(HookWireDetect) && p.has(HookFeedObserve) {
		return badManifest("hooks: wire.detect may not share a manifest with feed.observe")
	}
	if p.has(HookWireDetect) && p.has(HookApprovalDeliver) {
		return badManifest("hooks: wire.detect may not share a manifest with approval.deliver")
	}
	return nil
}

func (p *manifestParser) has(h Hook) bool {
	_, ok := p.m.Hooks[string(h)]
	return ok
}

func (p *manifestParser) hookDecl(h Hook, raw json.RawMessage) (pluginproto.HookDecl, error) {
	where := "hooks." + string(h)
	obj, ok := objectOf(raw)
	if !ok {
		return pluginproto.HookDecl{}, badManifest(where + " must be an object")
	}
	var d pluginproto.HookDecl
	rawContract, present := obj["contract"]
	if !present {
		return d, badManifest(where + ".contract is missing")
	}
	if d.Contract, ok = stringOf(rawContract); !ok || !contractPattern.MatchString(d.Contract) || d.Contract != hookContracts[h] {
		return d, badManifest(where + ".contract must be " + hookContracts[h])
	}
	rawRoles, hasRoles := obj["roles"]
	rawTypes, hasTypes := obj["entityTypes"]
	if hasRoles {
		if d.Roles, ok = stringsOf(rawRoles); !ok || len(d.Roles) == 0 || !unique(d.Roles) {
			return d, badManifest(where + ".roles must be a non-empty list of distinct roles")
		}
		for _, r := range d.Roles {
			if r != RoleValue && r != RoleNameCue {
				return d, badManifest(where + ".roles lists a role other than VALUE and NAME_CUE")
			}
		}
	}
	if hasTypes {
		if d.EntityTypes, ok = stringsOf(rawTypes); !ok || !unique(d.EntityTypes) {
			return d, badManifest(where + ".entityTypes must be a list of distinct entity types")
		}
		if err := p.entityTypes(where, d.EntityTypes); err != nil {
			return d, err
		}
	}
	switch h {
	case HookWireDetect:
		if !hasRoles || !hasTypes || len(d.EntityTypes) == 0 {
			return d, badManifest(where + " needs roles and at least one entity type")
		}
	case HookFeedObserve, HookApprovalDeliver:
		if hasRoles || hasTypes {
			return d, badManifest(where + " takes no roles or entity types")
		}
	case HookClassifySuggest:
		if hasRoles {
			return d, badManifest(where + " takes no roles")
		}
	case HookWireVerdict:
		return d, badManifest("hooks: wire.verdict is reserved and refused")
	}
	return d, nil
}

// entityTypes checks each type is well known or namespaced by this plugin's
// own name, so two plugins never share a type or a token key.
func (p *manifestParser) entityTypes(where string, types []string) error {
	for _, t := range types {
		if slices.Contains(wellKnownEntityTypes, t) {
			continue
		}
		if !namespacedPattern.MatchString(t) {
			return badManifest(where + ".entityTypes lists a type that is neither well known nor namespaced")
		}
		if prefix, _, _ := strings.Cut(t, "."); prefix != p.m.Name {
			return badManifest(where + ".entityTypes lists a type namespaced by another name than the plugin's")
		}
	}
	return nil
}

func (p *manifestParser) endpoint() error {
	obj, ok := objectOf(p.top["endpoint"])
	if !ok || len(obj) != 1 {
		return badManifest("endpoint must hold exactly one of local and remote")
	}
	if raw, ok := obj["local"]; ok {
		return p.localEndpoint(raw)
	}
	if raw, ok := obj["remote"]; ok {
		return p.remoteEndpoint(raw)
	}
	return badManifest("endpoint must hold exactly one of local and remote")
}

func (p *manifestParser) localEndpoint(raw json.RawMessage) error {
	obj, ok := objectOf(raw)
	if !ok {
		return badManifest("endpoint.local must be an object")
	}
	var e LocalEndpoint
	if e.Transport, ok = stringOf(obj["transport"]); !ok || !slices.Contains(localTransports, e.Transport) {
		return badManifest("endpoint.local.transport must be jsonrpc-stdio, jsonrpc-unix or connectrpc")
	}
	if e.Command, ok = stringOf(obj["command"]); !ok || !relativePath(e.Command) {
		return badManifest("endpoint.local.command must be a relative path inside the plugin's directory")
	}
	if rawArgs, present := obj["args"]; present {
		if e.Args, ok = stringsOf(rawArgs); !ok || len(e.Args) > maxArgs {
			return badManifest("endpoint.local.args must be a list of at most 64 strings")
		}
		for _, a := range e.Args {
			if utf8.RuneCountInString(a) > maxArgRunes {
				return badManifest("endpoint.local.args holds a string longer than 1024 characters")
			}
		}
	}
	p.m.Endpoint = Endpoint{Local: &e}
	return nil
}

func (p *manifestParser) remoteEndpoint(raw json.RawMessage) error {
	obj, ok := objectOf(raw)
	if !ok {
		return badManifest("endpoint.remote must be an object")
	}
	var e RemoteEndpoint
	if e.Transport, ok = stringOf(obj["transport"]); !ok || e.Transport != remoteTransport {
		return badManifest("endpoint.remote.transport must be connectrpc")
	}
	if e.URL, ok = stringOf(obj["url"]); !ok || utf8.RuneCountInString(e.URL) > maxURLRunes || !remoteURLPattern.MatchString(e.URL) {
		return badManifest("endpoint.remote.url must be an https URL with no user name, password, query or fragment")
	}
	p.m.Endpoint = Endpoint{Remote: &e}
	return nil
}

func (p *manifestParser) files() error {
	raw, present := p.top["files"]
	if p.m.Endpoint.IsRemote() {
		if present {
			return badManifest("files: a remote plugin ships no files")
		}
		return nil
	}
	if !present {
		return badManifest("files is missing: a local plugin lists every file it ships")
	}
	obj, ok := objectOf(raw)
	if !ok || len(obj) == 0 {
		return badManifest("files must be an object with at least one file")
	}
	p.m.Files = make(map[string]string, len(obj))
	for path, rawHash := range obj {
		if !relativePath(path) {
			return badManifest("files lists a path that is not a relative path inside the plugin's directory")
		}
		h, ok := stringOf(rawHash)
		if !ok || !fileHashPattern.MatchString(h) {
			return badManifest("files lists a file without a sha256: hash in lowercase hex")
		}
		p.m.Files[path] = h
	}
	return nil
}

func (p *manifestParser) network() error {
	obj, ok := objectOf(p.top["network"])
	if !ok {
		return badManifest("network must be an object")
	}
	raw, present := obj["egress"]
	if !present {
		return badManifest("network.egress is missing")
	}
	list, ok := stringsOf(raw)
	if !ok || len(list) > maxEgress || !unique(list) {
		return badManifest("network.egress must be a list of at most 64 distinct host:port entries")
	}
	for _, hp := range list {
		if len(hp) > 260 || !hostPortPattern.MatchString(hp) {
			return badManifest("network.egress lists an entry that is not a lowercase host:port")
		}
	}
	p.m.Network = Network{Egress: list}
	return nil
}

func (p *manifestParser) resources() error {
	raw, present := p.top["resources"]
	if !present {
		return nil
	}
	obj, ok := objectOf(raw)
	if !ok {
		return badManifest("resources must be an object")
	}
	var r Resources
	if rawMem, present := obj["memoryMB"]; present {
		v, ok := integerOf(rawMem)
		if !ok || v < minMemoryMB || v > maxMemoryMB {
			return badManifest("resources.memoryMB must be a whole number from 64 to 65536")
		}
		r.MemoryMB = int(v)
	}
	p.m.Resources = &r
	return nil
}

// commandInFiles: a local endpoint's command is one of the files the
// manifest pins, so the binary that runs is a hashed one.
func (p *manifestParser) commandInFiles() error {
	if l := p.m.Endpoint.Local; l != nil {
		if _, ok := p.m.Files[l.Command]; !ok {
			return badManifest("endpoint.local.command is not one of files")
		}
	}
	return nil
}

// remoteHostInEgress: a remote endpoint's host and port, 443 when the URL
// names none, are exactly one network.egress entry.
func (p *manifestParser) remoteHostInEgress() error {
	r := p.m.Endpoint.Remote
	if r == nil {
		return nil
	}
	hp, ok := RemoteHostPort(r.URL)
	if !ok || !slices.Contains(p.m.Network.Egress, hp) {
		return badManifest("endpoint.remote.url's host and port are not in network.egress")
	}
	return nil
}

// RemoteHostPort is the host:port a remote endpoint's URL reaches, with port
// 443 when the URL names none and an IPv6 host in brackets, as
// network.egress writes it.
func RemoteHostPort(rawURL string) (string, bool) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Hostname() == "" {
		return "", false
	}
	port := u.Port()
	if port == "" {
		port = defaultHTTPSPort
	}
	return net.JoinHostPort(u.Hostname(), port), true
}

func relativePath(p string) bool {
	return len(p) <= maxRelativePathLen && relativePathPattern.MatchString(p)
}

// ValidRelativePath reports whether p follows the manifest's path rules: a
// relative slash-separated path of at most 255 characters, with no segment
// that starts with "." (so no "..") and no character outside letters,
// digits, ".", "_" and "-".
func ValidRelativePath(p string) bool { return relativePath(p) }

func unique(list []string) bool {
	seen := make(map[string]struct{}, len(list))
	for _, s := range list {
		if _, dup := seen[s]; dup {
			return false
		}
		seen[s] = struct{}{}
	}
	return true
}

func badManifest(why string) *VerifyError {
	return &VerifyError{Reason: RefusedBadManifest, File: ManifestFile, Why: why}
}

// --- strict JSON ---

type jsonObject map[string]json.RawMessage

var (
	errInvalidUTF8  = errors.New("invalid UTF-8")
	errDuplicateKey = errors.New("a key appears twice in one object")
	errTooDeep      = errors.New("nested too deeply")
	errTrailingData = errors.New("data after the value")
	errSyntax       = errors.New("syntax error")
)

// checkStrictJSON accepts exactly one JSON value of valid UTF-8 in which no
// object repeats a key. Its errors are fixed texts, never the input.
func checkStrictJSON(b []byte) error {
	if !utf8.Valid(b) {
		return errInvalidUTF8
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := walkJSON(dec, 0); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errTrailingData
	}
	return nil
}

func walkJSON(dec *json.Decoder, depth int) error {
	if depth > maxJSONDepth {
		return errTooDeep
	}
	tok, err := dec.Token()
	if err != nil {
		return errSyntax
	}
	switch tok {
	case json.Delim('{'):
		seen := map[string]struct{}{}
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return errSyntax
			}
			key, ok := kt.(string)
			if !ok {
				return errSyntax
			}
			if _, dup := seen[key]; dup {
				return errDuplicateKey
			}
			seen[key] = struct{}{}
			if err := walkJSON(dec, depth+1); err != nil {
				return err
			}
		}
	case json.Delim('['):
		for dec.More() {
			if err := walkJSON(dec, depth+1); err != nil {
				return err
			}
		}
	default:
		return nil
	}
	if _, err := dec.Token(); err != nil {
		return errSyntax
	}
	return nil
}

// objectOf decodes a JSON object into its exact keys. null and any other
// type are not an object.
func objectOf(raw json.RawMessage) (jsonObject, bool) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] != '{' {
		return nil, false
	}
	var o jsonObject
	if err := json.Unmarshal(raw, &o); err != nil {
		return nil, false
	}
	return o, true
}

// stringOf decodes a JSON string. null and any other type are not a string.
func stringOf(raw json.RawMessage) (string, bool) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] != '"' {
		return "", false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", false
	}
	return s, true
}

// stringsOf decodes a JSON array of strings; a null element is refused.
func stringsOf(raw json.RawMessage) ([]string, bool) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] != '[' {
		return nil, false
	}
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, false
	}
	out := make([]string, 0, len(items))
	for _, it := range items {
		s, ok := stringOf(it)
		if !ok {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

// integerOf decodes a JSON number with no fractional part, as JSON Schema's
// integer: 1 and 1.0 are both 1.
func integerOf(raw json.RawMessage) (int64, bool) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || (raw[0] != '-' && (raw[0] < '0' || raw[0] > '9')) {
		return 0, false
	}
	var n json.Number
	if err := json.Unmarshal(raw, &n); err != nil {
		return 0, false
	}
	f, err := n.Float64()
	if err != nil || f != math.Trunc(f) || math.Abs(f) > math.MaxInt32 {
		return 0, false
	}
	return int64(f), true
}
