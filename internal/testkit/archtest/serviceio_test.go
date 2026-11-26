package archtest

import (
	"go/ast"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// A service does no file, process or socket I/O itself: it reaches the disk,
// other processes and the network through a port that an out/ adapter
// implements. serviceIO finds the calls that break that rule in the non-test
// files of every service package (a domain root and its subpackages other
// than in/ and out/).

// serviceIOImports are the packages a service may not import at all.
var serviceIOImports = []string{
	"os/exec", "syscall", "golang.org/x/sys/unix", "io/ioutil",
	"net/smtp", "net/rpc", "net/rpc/jsonrpc", "log/syslog",
}

// osAllowed are the names of package os a service may use: the process's own
// environment and identity, error values and types, and constants. Every
// other name of os is file, directory or process I/O.
var osAllowed = []string{
	// environment and identity
	"Getenv", "LookupEnv", "Environ", "Setenv", "Unsetenv", "Clearenv", "Expand", "ExpandEnv",
	"Getpid", "Getppid", "Getuid", "Geteuid", "Getgid", "Getegid", "Getgroups", "Getpagesize",
	"Hostname", "Executable", "Getwd", "Args", "UserHomeDir", "UserConfigDir", "UserCacheDir", "TempDir",
	// errors
	"ErrNotExist", "ErrExist", "ErrPermission", "ErrClosed", "ErrInvalid", "ErrDeadlineExceeded",
	"ErrNoDeadline", "ErrProcessDone", "IsExist", "IsNotExist", "IsPermission", "IsTimeout",
	"PathError", "LinkError", "SyscallError", "NewSyscallError",
	// types and pure helpers
	"File", "FileInfo", "FileMode", "DirEntry", "Root", "Signal", "Interrupt", "Kill",
	"Process", "ProcessState", "ProcAttr", "SameFile", "IsPathSeparator",
	"PathSeparator", "PathListSeparator", "DevNull",
}

// osAllowedPrefixes are allowed name prefixes of package os: open flags,
// file modes and seek constants.
var osAllowedPrefixes = []string{"O_", "Mode", "SEEK_"}

// netBanned are the names of package net that dial, listen, resolve or read
// the host's interfaces; netBannedPrefixes catches the families of them.
var (
	netBanned         = []string{"Dialer", "ListenConfig", "Resolver", "DefaultResolver"}
	netBannedPrefixes = []string{"Dial", "Listen", "Lookup", "Resolve", "File", "Interface"}
)

// serviceIOBanned are, per package, the names that do file, process or
// socket I/O. The module's own helpers are listed too: a service writing a
// file through atomicfile, or reading engine.json through config, still
// touches the disk itself.
var serviceIOBanned = map[string][]string{
	// the functions of path/filepath that read the disk
	"path/filepath": {"Walk", "WalkDir", "Glob", "EvalSymlinks"},
	// TLS dialing and listening
	"crypto/tls": {"Dial", "DialWithDialer", "Dialer", "Listen", "NewListener"},
	// atomic file writes
	modulePath + "/internal/lib/atomicfile": {"Write", "WriteFunc"},
	// opening a browser runs a process; Command only names the opener
	modulePath + "/internal/lib/browser": {"Open"},
	// fetching a server's certificates dials it and runs a TLS handshake
	modulePath + "/pkg/trustpin": {"Fetch"},
	// the pid file lock and its reader
	modulePath + "/internal/lib/pidlock":   {"AcquireLock", "Running"},
	modulePath + "/internal/lib/sysdns":    {"Resolver"},
	modulePath + "/internal/lib/ownerfile": {"Open", "OpenNoFollow", "Read", "ReadOrCreate"},
	"os/user":                              {"Lookup", "LookupId", "LookupGroup", "LookupGroupId", "Current"},
	// the config functions that open, stat, lock, read or write a file; the
	// path builders, validators and methods on a loaded Config are pure
	modulePath + "/internal/config": {
		// read the config
		"Load", "LoadNoFollow", "LoadOpen", "LoadOpenRaw", "Discover",
		// write the config
		"UpsertAgent", "UpsertAgentVault", "UpsertAgentVaultAt", "UpsertedVault",
		"ClearSetup", "ClearSetupAt", "UpdateConfig", "WriteFile", "RemoveAgents",
		// read a credential file
		"ReadCredential", "ReadCredentialAt", "ReadCredentialAtLimit",
		"ReadOwnCredential", "ReadOwnCredentialLimit", "SameCredentialFile", "SameFileAt",
		// open, check and lock a file
		"OpenPlainAt", "CheckTrustedConfig", "LockAt", "LockFile", "LockOpenFile", "LockConfigAs",
	},
}

func hasPrefixIn(prefixes []string, s string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// serviceIOName reports whether the use of name from the package at path is
// file, process or socket I/O.
func serviceIOName(path, name string) bool {
	switch path {
	case "os":
		return !in(osAllowed, name) && !hasPrefixIn(osAllowedPrefixes, name)
	case "net":
		return in(netBanned, name) || hasPrefixIn(netBannedPrefixes, name)
	}
	return in(serviceIOBanned[path], name)
}

// serviceIO returns one line per service package, file, declaration and
// banned name: "<package> <file>: <declaration>: <name>", with "(N times)"
// when the declaration uses the name more than once, so a second use where
// one is listed is a new line. A banned import is one line per file:
// "<package> <file>: imports <path>". The lines carry no line numbers, so
// moving code inside a declaration keeps them, and each move out of a
// service removes one.
func serviceIO(root string) ([]string, error) {
	pkgs, err := load(root)
	if err != nil {
		return nil, err
	}
	var out []string
	for rel, pk := range pkgs {
		if layerOf(rel) != lService {
			continue
		}
		for _, f := range pk.files {
			names := localNames(f.ast)
			for _, s := range f.ast.Imports {
				ip := importPath(s)
				switch {
				case in(serviceIOImports, ip):
					out = append(out, rel+" "+f.name+": imports "+ip)
				case s.Name != nil && s.Name.Name == "." && (ip == "os" || ip == "net" || serviceIOBanned[ip] != nil):
					out = append(out, rel+" "+f.name+": dot-imports "+ip)
				}
			}
			var uses []string
			for _, d := range f.ast.Decls {
				ast.Inspect(d, func(n ast.Node) bool {
					sel, ok := n.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					id, ok := sel.X.(*ast.Ident)
					if !ok {
						return true
					}
					if ip, ok := names[id.Name]; ok && serviceIOName(ip, sel.Sel.Name) {
						uses = append(uses, rel+" "+f.name+": "+declName(d, sel)+": "+strings.TrimPrefix(ip, modulePath+"/")+"."+sel.Sel.Name)
					}
					return true
				})
			}
			out = append(out, counted(uses)...)
		}
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}

// serviceIOBaseline lists the service I/O the check still lets through.
const serviceIOBaseline = "serviceio_calls_baseline.txt"

// TestServicesDoNoIO fails a file, process or socket call in a service that
// the baseline does not list, and a baseline line that is no longer true. The
// baseline only shrinks: move the I/O behind a port with an out/ adapter.
// -update drops the lines no longer true and never adds one.
func TestServicesDoNoIO(t *testing.T) {
	root := moduleRoot(t)
	got, err := serviceIO(root)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(root, "internal", "testkit", "archtest", serviceIOBaseline)
	base := readLines(t, file)
	if *update {
		kept := shrinkBaseline(base, got)
		if err := os.WriteFile(file, []byte(strings.Join(kept, "\n")+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if len(kept) < len(got) {
			t.Errorf("%d new I/O lines in services were not added to %s; put them behind a port", len(got)-len(kept), serviceIOBaseline)
		}
		return
	}
	for _, l := range got {
		if !slices.Contains(base, l) {
			t.Errorf("%s\n\tnew I/O in a service; put it behind a port with an out/ adapter (do not add it to %s)", l, serviceIOBaseline)
		}
	}
	for _, l := range base {
		if !slices.Contains(got, l) {
			t.Errorf("%s\n\tno longer true; remove it from %s (or lower its count)", l, serviceIOBaseline)
		}
	}
}

// shrinkBaseline returns the lines of base that are still in got: an update
// removes what was fixed and never adds what is new.
func shrinkBaseline(base, got []string) []string {
	var kept []string
	for _, l := range base {
		if slices.Contains(got, l) {
			kept = append(kept, l)
		}
	}
	return kept
}

func TestShrinkBaselineNeverAdds(t *testing.T) {
	got := shrinkBaseline([]string{"a", "b", "c"}, []string{"b", "c", "new"})
	if want := []string{"b", "c"}; !slices.Equal(got, want) {
		t.Errorf("shrinkBaseline = %q, want %q", got, want)
	}
}

// TestServiceIOCatchesViolations runs the check on a small module with one
// breach of each kind in a service, and the same calls where they are allowed.
func TestServiceIOCatchesViolations(t *testing.T) {
	ioCalls := "package %s\n\nimport (\n\t\"net\"\n\t\"os\"\n\t\"path/filepath\"\n)\n\n" +
		"var _ = os.ReadFile\nvar _ = net.Dialer{}\nvar _ = filepath.WalkDir\n"
	src := func(pkg string) string { return strings.Replace(ioCalls, "%s", pkg, 1) }
	m := modulePath + "/"
	root := fixture(t, map[string]string{
		"go.mod":                         "module " + modulePath + "\n",
		"internal/ledger/io.go":          src("ledger"),
		"internal/ledger/io_test.go":     src("ledger"),
		"internal/ledger/sub/proc.go":    "package sub\n\nimport (\n\t\"os/exec\"\n\t\"syscall\"\n)\n\nvar _ = exec.Command\nvar _ = syscall.Getpid\n",
		"internal/ledger/sub/smtp.go":    "package sub\n\n" + imp("net/smtp"),
		"internal/ledger/sub/rpc.go":     "package sub\n\n" + imp("net/rpc"),
		"internal/ledger/sub/syslog.go":  "package sub\n\n" + imp("log/syslog"),
		"internal/ledger/alias.go":       "package ledger\n\nimport (\n\tdisk \"os\"\n\tsock \"net\"\n)\n\nvar _ = disk.MkdirAll\nvar _ = sock.Listen\nvar _ = sock.DefaultResolver\n",
		"internal/ledger/dot.go":         "package ledger\n\nimport . \"os\"\n\nvar _ = Remove\n",
		"internal/ledger/twice.go":       "package ledger\n\nimport \"os/user\"\n\nfunc Once() { _, _ = user.Lookup(\"a\") }\n\nfunc Twice() {\n\t_, _ = user.Lookup(\"a\")\n\t_, _ = user.Lookup(\"b\")\n}\n",
		"internal/ledger/resolve.go":     "package ledger\n\nimport \"net\"\n\nvar _ = net.ResolveTCPAddr\n",
		"internal/ledger/tls.go":         "package ledger\n\nimport \"crypto/tls\"\n\nvar _ = tls.Dial\nvar _ = tls.NewListener\nvar _ tls.Config\n",
		"internal/ledger/helpers.go":     "package ledger\n\nimport (\n\t\"" + m + "internal/config\"\n\t\"" + m + "internal/lib/atomicfile\"\n\t\"" + m + "internal/lib/pidlock\"\n\t\"" + m + "internal/lib/browser\"\n\t\"" + m + "internal/lib/sysdns\"\n\t\"" + m + "internal/lib/ownerfile\"\n\t\"" + m + "pkg/trustpin\"\n)\n\nvar _ = ownerfile.OpenNoFollow\nvar _ = ownerfile.Check\nvar _ = sysdns.Resolver{}\nvar _ = atomicfile.Write\nvar _ = pidlock.AcquireLock\nvar _ = config.Load\nvar _ = config.SocketPath\nvar _ = browser.Open\nvar _ = browser.Command\nvar _ = trustpin.Fetch\nvar _ = trustpin.Check\nvar _ atomicfile.Options\n",
		"internal/ledger/clean.go":       "package ledger\n\nimport (\n\t\"net\"\n\t\"os\"\n\t\"os/user\"\n\t\"path/filepath\"\n)\n\nvar _ = os.Getenv\nvar _ = os.ErrNotExist\nvar _ = os.O_RDONLY\nvar _ = os.ModeDir\nvar _ *os.File\nvar _ = net.JoinHostPort\nvar _ net.Conn\nvar _ = filepath.Join\nvar _ = user.Current\nvar _ user.User\n",
		"internal/ledger/out/disk/d.go":  src("disk"),
		"internal/ledger/in/cli/c.go":    src("cli"),
		"internal/core/thing/t.go":       src("thing"),
		"internal/platform/keyfile/k.go": src("keyfile"),
		"internal/testkit/archtest/a.go": src("archtest"),
	})
	got, err := serviceIO(root)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"internal/ledger alias.go: _: net.DefaultResolver",
		"internal/ledger alias.go: _: net.Listen",
		"internal/ledger alias.go: _: os.MkdirAll",
		"internal/ledger clean.go: _: os/user.Current",
		"internal/ledger dot.go: dot-imports os",
		"internal/ledger helpers.go: _: internal/config.Load",
		"internal/ledger helpers.go: _: internal/lib/atomicfile.Write",
		"internal/ledger helpers.go: _: internal/lib/browser.Open",
		"internal/ledger helpers.go: _: internal/lib/ownerfile.OpenNoFollow",
		"internal/ledger helpers.go: _: internal/lib/pidlock.AcquireLock",
		"internal/ledger helpers.go: _: internal/lib/sysdns.Resolver",
		"internal/ledger helpers.go: _: pkg/trustpin.Fetch",
		"internal/ledger io.go: _: net.Dialer",
		"internal/ledger io.go: _: os.ReadFile",
		"internal/ledger io.go: _: path/filepath.WalkDir",
		"internal/ledger resolve.go: _: net.ResolveTCPAddr",
		"internal/ledger tls.go: _: crypto/tls.Dial",
		"internal/ledger tls.go: _: crypto/tls.NewListener",
		"internal/ledger twice.go: Once: os/user.Lookup",
		"internal/ledger twice.go: Twice: os/user.Lookup (2 times)",
		"internal/ledger/sub proc.go: imports os/exec",
		"internal/ledger/sub proc.go: imports syscall",
		"internal/ledger/sub rpc.go: imports net/rpc",
		"internal/ledger/sub smtp.go: imports net/smtp",
		"internal/ledger/sub syslog.go: imports log/syslog",
	}
	if !slices.Equal(got, want) {
		t.Errorf("serviceIO:\n got %q\nwant %q", got, want)
	}
	// A second call in a declaration the baseline lists changes its line,
	// so the listed one-call line is stale and the counted line is new.
	if slices.Contains(got, "internal/ledger twice.go: Twice: os/user.Lookup") {
		t.Error("a declaration with two banned calls kept its one-call line; a second call would pass a listed declaration")
	}
}
