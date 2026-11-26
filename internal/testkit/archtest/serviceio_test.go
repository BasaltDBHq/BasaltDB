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
var serviceIOImports = []string{"os/exec", "syscall", "golang.org/x/sys/unix", "io/ioutil"}

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
	netBannedPrefixes = []string{"Dial", "Listen", "Lookup", "File", "Interface"}
)

// filepathBanned are the functions of path/filepath that read the disk.
var filepathBanned = []string{"Walk", "WalkDir", "Glob", "EvalSymlinks"}

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
	case "path/filepath":
		return in(filepathBanned, name)
	}
	return false
}

// serviceIO returns one line per service package, file and banned name:
// "<package> <file>: <name>". The lines carry no line numbers, so moving code
// inside a file keeps them, and each move out of a service removes one.
func serviceIO(root string) ([]string, error) {
	pkgs, err := load(root)
	if err != nil {
		return nil, err
	}
	var out []string
	for rel, pk := range pkgs {
		if layerOf(rel) != lService || isTestHelper(rel) {
			continue
		}
		for _, f := range pk.files {
			names := localNames(f.ast)
			for _, s := range f.ast.Imports {
				ip := importPath(s)
				switch {
				case in(serviceIOImports, ip):
					out = append(out, rel+" "+f.name+": imports "+ip)
				case s.Name != nil && s.Name.Name == "." && (ip == "os" || ip == "net" || ip == "path/filepath"):
					out = append(out, rel+" "+f.name+": dot-imports "+ip)
				}
			}
			ast.Inspect(f.ast, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				id, ok := sel.X.(*ast.Ident)
				if !ok {
					return true
				}
				if ip, ok := names[id.Name]; ok && serviceIOName(ip, sel.Sel.Name) {
					out = append(out, rel+" "+f.name+": "+ip+"."+sel.Sel.Name)
				}
				return true
			})
		}
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}

const serviceIOBaseline = "serviceio_baseline.txt"

// TestServicesDoNoIO fails a file, process or socket call in a service that
// the baseline does not list, and a baseline line that is no longer true. The
// baseline only shrinks: move the I/O behind a port with an out/ adapter.
func TestServicesDoNoIO(t *testing.T) {
	root := moduleRoot(t)
	got, err := serviceIO(root)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(root, "internal", "testkit", "archtest", serviceIOBaseline)
	if *update {
		if err := os.WriteFile(file, []byte(strings.Join(got, "\n")+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	base := readLines(t, file)
	for _, l := range got {
		if !slices.Contains(base, l) {
			t.Errorf("%s\n\tnew I/O in a service; put it behind a port with an out/ adapter (do not add it to %s)", l, serviceIOBaseline)
		}
	}
	for _, l := range base {
		if !slices.Contains(got, l) {
			t.Errorf("%s\n\tno longer true; remove it from %s", l, serviceIOBaseline)
		}
	}
}

// TestServiceIOCatchesViolations runs the check on a small module with one
// breach of each kind in a service, and the same calls where they are allowed.
func TestServiceIOCatchesViolations(t *testing.T) {
	ioCalls := "package %s\n\nimport (\n\t\"net\"\n\t\"os\"\n\t\"path/filepath\"\n)\n\n" +
		"var _ = os.ReadFile\nvar _ = net.Dialer{}\nvar _ = filepath.WalkDir\n"
	src := func(pkg string) string { return strings.Replace(ioCalls, "%s", pkg, 1) }
	root := fixture(t, map[string]string{
		"go.mod":                           "module " + modulePath + "\n",
		"internal/ledger/io.go":            src("ledger"),
		"internal/ledger/io_test.go":       src("ledger"),
		"internal/ledger/sub/proc.go":      "package sub\n\nimport (\n\t\"os/exec\"\n\t\"syscall\"\n)\n\nvar _ = exec.Command\nvar _ = syscall.Getpid\n",
		"internal/ledger/alias.go":         "package ledger\n\nimport (\n\tdisk \"os\"\n\tsock \"net\"\n)\n\nvar _ = disk.MkdirAll\nvar _ = sock.Listen\nvar _ = sock.DefaultResolver\n",
		"internal/ledger/dot.go":           "package ledger\n\nimport . \"os\"\n\nvar _ = Remove\n",
		"internal/ledger/clean.go":         "package ledger\n\nimport (\n\t\"net\"\n\t\"os\"\n\t\"path/filepath\"\n)\n\nvar _ = os.Getenv\nvar _ = os.ErrNotExist\nvar _ = os.O_RDONLY\nvar _ = os.ModeDir\nvar _ *os.File\nvar _ = net.JoinHostPort\nvar _ net.Conn\nvar _ = filepath.Join\n",
		"internal/ledger/out/disk/d.go":    src("disk"),
		"internal/ledger/in/cli/c.go":      src("cli"),
		"internal/core/thing/t.go":         "package thing\n",
		"internal/platform/keyfile/k.go":   src("keyfile"),
		"internal/testkit/archtest/a.go":   src("archtest"),
		"internal/plugin/out/x/xtest/h.go": src("xtest"),
	})
	got, err := serviceIO(root)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"internal/ledger alias.go: net.DefaultResolver",
		"internal/ledger alias.go: net.Listen",
		"internal/ledger alias.go: os.MkdirAll",
		"internal/ledger dot.go: dot-imports os",
		"internal/ledger io.go: net.Dialer",
		"internal/ledger io.go: os.ReadFile",
		"internal/ledger io.go: path/filepath.WalkDir",
		"internal/ledger/sub proc.go: imports os/exec",
		"internal/ledger/sub proc.go: imports syscall",
	}
	if !slices.Equal(got, want) {
		t.Errorf("serviceIO:\n got %q\nwant %q", got, want)
	}
}
