package app

import (
	"context"
	"os"

	"github.com/jackc/pgx/v5"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/crash"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/laststop"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/osservice"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/demo"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/pgdial"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/trustdir"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/updatecheck"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/vault"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
)

// What the commands in cmd/basalt use from the outbound adapters. cmd does
// not import an adapter (ARCHITECTURE.md); it reaches each through the
// names here, so this file is the one place the commands' construction of
// adapters lives.

// The engine service on the operating system.
type (
	OSSystem     = osservice.System
	OSExecSystem = osservice.OSSystem
	OSSpec       = osservice.Spec
	OSFile       = osservice.File
	OSTrustedDir = osservice.TrustedDir
	OSPluginHost = osservice.PluginHost
	OSPluginUnit = osservice.PluginEntry
)

const (
	OSInstallPrompt = osservice.InstallPrompt
	OSRemovePrompt  = osservice.RemovePrompt
	OSResetPrompt   = osservice.ResetPrompt
	OSUnitName      = osservice.SystemdUnitName
	OSLaunchdLabel  = osservice.LaunchdLabel
)

var (
	ErrOSDialogCancelled = osservice.ErrDialogCancelled
	ErrOSNoDialog        = osservice.ErrNoDialog

	OSApply         = osservice.Apply
	OSDefaultUser   = osservice.DefaultUser
	OSDialogCommand = osservice.DialogCommand
	OSDialogError   = osservice.DialogError
	OSDialogPaths   = osservice.DialogPaths
	OSEntryFor      = osservice.EntryFor
	OSHostFor       = osservice.HostFor
	OSInstallPlan   = osservice.InstallPlan
	OSInstallScript = osservice.InstallScript
	OSRemoveScript  = osservice.RemoveScript
	OSResetScript   = osservice.ResetScript
	OSSettle        = osservice.Settle
	OSUnitPath      = osservice.UnitPath
)

// The owner and trust checks are functions, not variables, so nothing can
// swap them at run time.

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
type LastStopRecord = laststop.LastStopFileRecord

var (
	LastStopHashEngineJSON    = laststop.HashEngineJSON
	LastStopStartHoldOffUntil = laststop.StartHoldOffUntil
)

// The crash reports.
type (
	CrashRecorder = crash.Recorder
	CrashInput    = crash.Input
)

const (
	CrashDirName   = crash.DirName
	CrashKindPanic = crash.KindPanic
)

var CrashOSScrubber = crash.OSScrubber

// The update notice.
type (
	UpdateChecker = updatecheck.Checker
	UpdateNotice  = updatecheck.Notice
)

const UpdateDevVersion = updatecheck.DevVersion

var (
	UpdateCacheDir = updatecheck.CacheDir
	UpdateDisabled = updatecheck.Disabled
)

// The Vault states a local status line reports.
const (
	VaultStateKeyError = string(vault.StateKeyError)
	VaultStateOff      = string(vault.StateOff)
)

// DemoAgent is the sample database's agent name.
const DemoAgent = demo.Agent

// Querier is what the guard's reads take: a connection or a transaction.
type Querier = guard.Querier

var (
	GuardAgentConnString = guard.AgentConnString
	GuardLatestVersion   = guard.LatestVersion
)

// GuardAgentVersion is the guard version q's database has, 0 when none.
func GuardAgentVersion(ctx context.Context, q Querier) (int, error) {
	return guard.AgentVersion(ctx, q)
}

// GuardSetupRecorded reports whether the setup with id is recorded.
func GuardSetupRecorded(ctx context.Context, q Querier, id uuid.UUID) (bool, error) {
	return guard.SetupRecorded(ctx, q, id)
}

// Database connections.
var (
	WithCertificateHint    = pgdial.WithCertificateHint
	CurrentTrustProfileSet = pgdial.Trust
)

// CheckForeignDSN refuses a connection string with parameters that make the
// driver read a file (ErrForeignDSN).
func CheckForeignDSN(dsn string) error { return pgdial.CheckForeignDSN(dsn) }

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
