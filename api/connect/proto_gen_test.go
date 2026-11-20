package connectcontract_test

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"

	connectv1 "github.com/basaltdbhq/basaltdb/api/connect/proto/basalt/connect/v1"
)

var (
	protoMsgBlock = regexp.MustCompile(`(?m)^message (\w+) \{([^}]*)\}`)
	protoField    = regexp.MustCompile(`(?m)^\s*(repeated\s+)?([\w.]+)\s+(\w+)\s*=\s*(\d+)\s*(\[[^\]]*\])?;`)
	protoRPC      = regexp.MustCompile(`(?m)^\s*rpc (\w+)\((\w+)\) returns \((\w+)\);`)
	protoService  = regexp.MustCompile(`(?m)^service (\w+) \{`)
	protoPackage  = regexp.MustCompile(`(?m)^package ([\w.]+);`)
)

func readProto(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("proto", "basalt", "connect", "v1", "connect.proto"))
	require.NoError(t, err)
	return string(raw)
}

// TestGeneratedCodeMatchesProto: the checked-in Go code under proto/ was
// generated from the current connect.proto. It compares the generated file
// descriptor with the .proto read as text: the package, every message with
// its fields (name, number, type, repeated, whether it is marked
// sensitive), and the service's methods. CI has no protoc, so this is the
// drift guard; regenerate with `make proto`.
func TestGeneratedCodeMatchesProto(t *testing.T) {
	t.Parallel()
	text := readProto(t)
	fd := connectv1.File_basalt_connect_v1_connect_proto

	pkg := protoPackage.FindStringSubmatch(text)
	require.NotNil(t, pkg)
	require.Equal(t, pkg[1], string(fd.Package()), "package")

	var want, got []string
	for _, m := range protoMsgBlock.FindAllStringSubmatch(text, -1) {
		want = append(want, "message "+m[1])
		for _, f := range protoField.FindAllStringSubmatch(m[2], -1) {
			sensitive := strings.Contains(f[5], "(sensitive) = true")
			want = append(want, fmt.Sprintf("%s.%s=%s %s%s sensitive=%t", m[1], f[3], f[4], strings.TrimSpace(f[1]), f[2], sensitive))
		}
	}
	msgs := fd.Messages()
	for i := range msgs.Len() {
		md := msgs.Get(i)
		got = append(got, "message "+string(md.Name()))
		fields := md.Fields()
		for j := range fields.Len() {
			f := fields.Get(j)
			got = append(got, fmt.Sprintf("%s.%s=%d %s sensitive=%t", md.Name(), f.Name(), f.Number(), protoTypeName(f), isSensitive(f)))
		}
	}
	sort.Strings(want)
	sort.Strings(got)
	require.Equal(t, want, got, "the generated messages differ from connect.proto: run make proto")

	want, got = make([]string, 0, 6), make([]string, 0, 6)
	svc := protoService.FindStringSubmatch(text)
	require.NotNil(t, svc)
	for _, r := range protoRPC.FindAllStringSubmatch(text, -1) {
		want = append(want, fmt.Sprintf("%s.%s(%s) %s", svc[1], r[1], r[2], r[3]))
	}
	svcs := fd.Services()
	for i := range svcs.Len() {
		sd := svcs.Get(i)
		methods := sd.Methods()
		for j := range methods.Len() {
			m := methods.Get(j)
			got = append(got, fmt.Sprintf("%s.%s(%s) %s", sd.Name(), m.Name(), m.Input().Name(), m.Output().Name()))
		}
	}
	sort.Strings(want)
	sort.Strings(got)
	require.Equal(t, []string{
		"SetupService.CheckSetup(CheckSetupRequest) CheckSetupResponse",
		"SetupService.CollectAddress(CollectAddressRequest) CollectAddressResponse",
		"SetupService.DescribeSetup(DescribeSetupRequest) DescribeSetupResponse",
		"SetupService.HandoffStatus(HandoffStatusRequest) HandoffStatusResponse",
		"SetupService.OfferAddress(OfferAddressRequest) OfferAddressResponse",
		"SetupService.ReportReach(ReportReachRequest) ReportReachResponse",
		"SetupService.RunSetup(RunSetupRequest) RunSetupResponse",
	}, want, "connect.proto's service")
	require.Equal(t, want, got, "the generated service differs from connect.proto: run make proto")
}

// TestConnectionStringIsSensitive: every field that carries the admin
// connection string, the hand-off ticket or the database's address is marked sensitive, so a logging interceptor can find
// it by the option (CONTRACT.md, Connect).
func TestConnectionStringIsSensitive(t *testing.T) {
	t.Parallel()
	fd := connectv1.File_basalt_connect_v1_connect_proto
	found, tickets, addresses := 0, 0, 0
	msgs := fd.Messages()
	for i := range msgs.Len() {
		fields := msgs.Get(i).Fields()
		for j := range fields.Len() {
			f := fields.Get(j)
			if f.Name() == "database_url" {
				found++
				require.True(t, isSensitive(f), "%s is not marked sensitive", f.FullName())
			}
			if f.FullName() == "basalt.connect.v1.CheckSetupResponse.database" || f.FullName() == "basalt.connect.v1.CollectAddressResponse.address" ||
				f.FullName() == "basalt.connect.v1.ReportReachRequest.address" {
				addresses++
				require.True(t, isSensitive(f), "%s is not marked sensitive", f.FullName())
			}
			if f.Name() == "ticket" {
				tickets++
				require.True(t, isSensitive(f), "%s is not marked sensitive", f.FullName())
			}
		}
	}
	require.Equal(t, 2, found, "CheckSetupRequest and RunSetupRequest carry database_url")
	require.Equal(t, 5, tickets, "CheckSetupResponse, RunSetupResponse, HandoffStatusRequest, HandoffStatusResponse and OfferAddressRequest carry the hand-off ticket, which holds the address")
	require.Equal(t, 3, addresses, "the database CheckSetup names, the address CollectAddress returns and the address ReportReach sends are marked")
}

func isSensitive(f protoreflect.FieldDescriptor) bool {
	opts, ok := f.Options().(*descriptorpb.FieldOptions)
	if !ok || opts == nil {
		return false
	}
	v, ok := proto.GetExtension(opts, connectv1.E_Sensitive).(bool)
	return ok && v
}

// protoTypeName writes a field's type as the .proto spells it.
func protoTypeName(f protoreflect.FieldDescriptor) string {
	prefix := ""
	if f.Cardinality() == protoreflect.Repeated {
		prefix = "repeated"
	}
	switch f.Kind() {
	case protoreflect.MessageKind, protoreflect.GroupKind:
		return prefix + string(f.Message().Name())
	case protoreflect.EnumKind:
		return prefix + string(f.Enum().Name())
	default:
		return prefix + f.Kind().String()
	}
}
