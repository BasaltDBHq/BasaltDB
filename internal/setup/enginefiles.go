package setup

import (
	"context"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/piistore"
)

// EngineFiles are the engine's own files a local setup reads and writes,
// by path, as the engine's own user: engine.json and the agents'
// credential files. An outbound adapter implements it (setup/out/enginefiles).
// Every call is the config or os call it is named after, unchanged; a
// caller refuses an engine that runs as root before it reads the config.
type EngineFiles interface {
	// Lstat is os.Lstat's error for path: nil when it exists.
	Lstat(path string) error
	LoadConfig(path string) (config.Config, error)
	// ReadCredentialFile reads an agent's connection string
	// (config.ReadCredential), with no check of what the driver would read.
	ReadCredentialFile(path string) (string, error)
	ReadFile(path string) ([]byte, error)
	// WriteFile writes data at path as config.WriteFile does.
	WriteFile(path string, data []byte) error
	Remove(path string) error
	UpsertAgentVault(path string, s config.Settings, a config.Agent) (config.VaultWritten, error)
	RemoveAgents(path string, names []string) (removedFile bool, err error)
}

// ColumnSuggestion is the classifier's suggestion for one column.
type ColumnSuggestion struct {
	Column                                 piistore.Column
	Class, EntityType, PhoneRegion, Reason string
}

// SampleFunc reads one column's sample.
type SampleFunc func(ctx context.Context, col piistore.Column) (piistore.Sample, error)

// Classifier suggests a class for each column from its sample, in the
// columns' order, keeping no value: the PII classifier's run with its
// default options. internal/app fills it.
type Classifier interface {
	SuggestColumns(ctx context.Context, cols []piistore.Column, sample SampleFunc) ([]ColumnSuggestion, error)
}
