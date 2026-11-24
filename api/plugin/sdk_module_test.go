package plugincontract_test

import (
	"bytes"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	plugincontract "github.com/basaltdbhq/basaltdb/api/plugin"
	"github.com/basaltdbhq/basaltdb/internal/plugin/out/plugintransport/dial"
)

// sdkModule is the Go plugin SDK. It lives in its own repository and holds
// copies of the protocol's definition; this repository is their source.
const sdkModule = "github.com/basaltdbhq/basalt-plugin-go"

var (
	protoHeader    = regexp.MustCompile(`(?s)\A.*?(syntax = )`)
	protoGoPackage = regexp.MustCompile(`(?m)^option go_package = "[^"]*";\n`)
	sdkInstallID   = regexp.MustCompile(`(?m)^const CheckInstallID = "([^"]+)"$`)
	sdkSocketEnv   = regexp.MustCompile(`(?m)^const SocketEnv = "([^"]+)"$`)
	sampleSource   = regexp.MustCompile(`"source":\s*"urn:uuid:([^"]+)"`)
)

// TestSDKModuleMatchesTheContract: the SDK module go.mod pins holds the same
// protocol as this repository. It fails when the module's service definition,
// its copies of the contract's samples, its protocol types, or the constants
// it repeats differ from the engine's. After a protocol change here, the SDK
// takes the same change and gets a new version, and go.mod pins that version.
func TestSDKModuleMatchesTheContract(t *testing.T) {
	t.Parallel()
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", sdkModule).Output()
	require.NoError(t, err, "go.mod requires %s", sdkModule)
	sdk := strings.TrimSpace(string(out))
	require.DirExists(t, sdk)
	read := func(t *testing.T, elem ...string) string {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(elem...))
		require.NoError(t, err)
		return string(b)
	}

	t.Run("service definition", func(t *testing.T) {
		rel := filepath.Join("proto", "basalt", "plugin", "v1", "plugin.proto")
		// The header comment and go_package are each repository's own.
		body := func(s string) string {
			require.Regexp(t, protoGoPackage, s)
			return protoGoPackage.ReplaceAllString(protoHeader.ReplaceAllString(s, "$1"), "")
		}
		require.Equal(t, body(read(t, rel)), body(read(t, sdk, rel)), "plugin.proto differs from the SDK module's")
	})

	t.Run("samples", func(t *testing.T) {
		files, err := os.ReadDir(filepath.Join(sdk, "testdata"))
		require.NoError(t, err)
		require.NotEmpty(t, files)
		for _, f := range files {
			require.Equal(t, read(t, "testdata", f.Name()), read(t, sdk, "testdata", f.Name()), "sample %s differs from the SDK module's", f.Name())
		}
	})

	t.Run("protocol types", func(t *testing.T) {
		engine := filepath.Join("..", "..", "internal", "core", "pluginproto")
		names := func(dir string) []string {
			all, err := filepath.Glob(filepath.Join(dir, "*.go"))
			require.NoError(t, err)
			var out []string
			for _, f := range all {
				if !strings.HasSuffix(f, "_test.go") {
					out = append(out, filepath.Base(f))
				}
			}
			return out
		}
		require.NotEmpty(t, names(engine))
		require.Equal(t, names(engine), names(filepath.Join(sdk, "protocol")), "the protocol package's files")
		for _, name := range names(engine) {
			require.Equal(t, goCode(t, filepath.Join(engine, name)), goCode(t, filepath.Join(sdk, "protocol", name)),
				"internal/core/pluginproto/%s differs from the SDK module's, comments aside", name)
		}
	})

	t.Run("constants the SDK repeats", func(t *testing.T) {
		id := sdkInstallID.FindStringSubmatch(read(t, sdk, "events.go"))
		require.NotNil(t, id, "the SDK's CheckInstallID")
		for _, sample := range [][]byte{plugincontract.CheckFeedSample(), plugincontract.CheckDeliverSample()} {
			sources := sampleSource.FindAllSubmatch(sample, -1)
			require.NotEmpty(t, sources)
			for _, s := range sources {
				require.Equal(t, string(s[1]), id[1], "the install id of check's samples")
			}
		}
		env := sdkSocketEnv.FindStringSubmatch(read(t, sdk, "sdk.go"))
		require.NotNil(t, env, "the SDK's SocketEnv")
		require.Equal(t, dial.SocketEnv, env[1])
	})
}

// goCode is a Go file's code with every comment dropped and the package
// name left out: the engine's package is pluginproto, the SDK's is protocol.
func goCode(t *testing.T, path string) string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
	require.NoError(t, err)
	f.Name.Name = "_"
	var b bytes.Buffer
	require.NoError(t, printer.Fprint(&b, fset, f))
	return b.String()
}
