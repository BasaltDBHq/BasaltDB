package app

import (
	"context"
	"io"
	"os"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/pluginmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/servicespec"
	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"
	"github.com/basaltdbhq/basaltdb/internal/engine/out/crash"
	"github.com/basaltdbhq/basaltdb/internal/engine/out/laststop"
	"github.com/basaltdbhq/basaltdb/internal/platform/osservice"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pgdial"
	"github.com/basaltdbhq/basaltdb/internal/plugin"
	"github.com/basaltdbhq/basaltdb/internal/setup/out/trustdir"
	"github.com/basaltdbhq/basaltdb/internal/status/out/updatecheck"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
)

// What the commands in cmd/basalt use from the outbound adapters. cmd does
// not import an adapter (ARCHITECTURE.md); it reaches each through the
// names here, so this file is the one place the commands' construction of
// adapters lives. Each function is declared, never a variable holding one,
// so nothing in the binary can swap a check at run time.

// The engine service on the operating system.
type (
	OSSystem     = osservice.System
	OSExecSystem = osservice.OSSystem
	OSSpec       = servicespec.Spec
	OSFile       = servicespec.File
	OSTrustedDir = osservice.TrustedDir
	OSPluginHost = servicespec.PluginHost
	OSPluginUnit = servicespec.PluginEntry
)

const (
	OSInstallPrompt = servicespec.InstallPrompt
	OSRemovePrompt  = servicespec.RemovePrompt
	OSResetPrompt   = servicespec.ResetPrompt
	OSUnitName      = servicespec.SystemdUnitName
	OSLaunchdLabel  = servicespec.LaunchdLabel
)

var (
	ErrOSDialogCancelled = servicespec.ErrDialogCancelled
	ErrOSNoDialog        = servicespec.ErrNoDialog
)

func OSApply(ctx context.Context, sys OSSystem, steps []osservice.Step, dryRun bool, out io.Writer) error {
	return osservice.Apply(ctx, sys, steps, dryRun, out)
}
func OSDefaultUser(goos string) string { return osservice.DefaultUser(goos) }
func OSDialogCommand(goos, prompt, script string) ([]string, error) {
	return osservice.DialogCommand(goos, prompt, script)
}

func OSDialogError(goos string, code int, stderr string, runErr error) error {
	return osservice.DialogError(goos, code, stderr, runErr)
}
func OSDialogPaths(goos string) ([]string, error) { return osservice.DialogPaths(goos) }
func OSEntryFor(p config.Plugin, v pluginmodel.Verified) (OSPluginUnit, bool) {
	return plugin.EntryFor(p, v)
}

func OSHostFor(cfg config.Config, goos, configPath, engineUser string) OSPluginHost {
	return plugin.HostFor(cfg, goos, configPath, engineUser)
}

func OSInstallPlan(ctx context.Context, sys OSSystem, s OSSpec) ([]osservice.Step, error) {
	return osservice.InstallPlan(ctx, sys, s)
}

func OSInstallScript(goos, binary string) (string, error) {
	return osservice.InstallScript(goos, binary)
}
func OSRemoveScript(goos string) (string, error)          { return osservice.RemoveScript(goos) }
func OSResetScript(goos string) (string, error)           { return osservice.ResetScript(goos) }
func OSSettle(err error, sys OSSystem, goos string) error { return osservice.Settle(err, sys, goos) }
func OSUnitPath(goos string) string                       { return osservice.UnitPath(goos) }

// OSLookupUID is the uid of the OS user name, or -1 when there is no such
// user.
func OSLookupUID(name string) int { return osservice.LookupUID(name) }

// OSOpenTrustedDir opens dir for root, refusing a directory on the way that
// someone other than root or owner could swap (osservice.OpenTrustedDir).
func OSOpenTrustedDir(dir string, owner int, create bool) (*OSTrustedDir, error) {
	return osservice.OpenTrustedDir(dir, owner, create)
}

// OSOpenTrustedFile opens path read-only for root: its directory as
// OSOpenTrustedDir does, the file itself never through a symlink
// (osservice.OpenTrustedFile).
func OSOpenTrustedFile(path string, owner int) (*os.File, error) {
	return osservice.OpenTrustedFile(path, owner)
}

// The last-stop record the supervisor writes and the autostart reads.
type LastStopRecord = servicespec.LastStopFileRecord

func LastStopHashEngineJSON(path string) string { return laststop.HashEngineJSON(path) }
func LastStopStartHoldOffUntil(rec LastStopRecord, configPath string, now time.Time) (time.Time, bool) {
	return laststop.StartHoldOffUntil(rec, configPath, now)
}

// The crash reports.
type (
	CrashRecorder = crash.Recorder
	CrashInput    = servicespec.CrashInput
)

const (
	CrashDirName   = servicespec.CrashDirName
	CrashKindPanic = servicespec.CrashKindPanic
)

func CrashOSScrubber() *crash.Scrubber { return crash.OSScrubber() }

// The update notice.
type (
	UpdateChecker = updatecheck.Checker
	UpdateNotice  = updatecheck.Notice
)

const UpdateDevVersion = updatecheck.DevVersion

func UpdateCacheDir(override string) (string, error) { return updatecheck.CacheDir(override) }
func UpdateDisabled(getenv func(string) string) bool { return updatecheck.Disabled(getenv) }

// DemoAgent is the sample database's agent name.
const DemoAgent = setupcode.DemoAgent

// Querier is what the guard's reads take: a connection or a transaction.
type Querier = guard.Querier

func GuardAgentConnString(adminURL, role, password string) (string, error) {
	return guard.AgentConnString(adminURL, role, password)
}
func GuardLatestVersion() int { return guard.LatestVersion() }

// GuardAgentVersion is the guard version q's database has, 0 when none.
func GuardAgentVersion(ctx context.Context, q Querier) (int, error) {
	return guard.AgentVersion(ctx, q)
}

// GuardSetupRecorded reports whether the setup with id is recorded.
func GuardSetupRecorded(ctx context.Context, q Querier, id uuid.UUID) (bool, error) {
	return guard.SetupRecorded(ctx, q, id)
}

// Database connections.
// WithCertificateHint is err with what can fix it, when it is a
// certificate of dsn's host that did not verify.
func WithCertificateHint(dsn string, err error) error { return pgdial.WithCertificateHint(dsn, err) }

// CurrentTrustProfileSet is the trust profiles a connection opened now uses.
func CurrentTrustProfileSet() *trustprofile.Set { return pgdial.Trust() }

// CertificateNotVerified reports whether err is a server certificate that
// did not verify.
func CertificateNotVerified(err error) bool { return pgdial.CertificateNotVerified(err) }

// Connect opens one connection, usable through a transaction pooler.
func Connect(ctx context.Context, dsn string) (*pgx.Conn, error) {
	return pgdial.Connect(ctx, dsn)
}

// UseTrustDir makes every connection read the trust profiles in the trust.d
// next to the config at path, again for each connection.
func UseTrustDir(path string) {
	pgdial.SetTrust(trustdir.Source(path))
}

// TrustProfileFor is the profile in the trust.d next to the config at
// configPath that names host, or nil.
func TrustProfileFor(configPath, host string) *trustprofile.Profile {
	return trustdir.Set(configPath).For(host)
}
