package guard

import "github.com/basaltdbhq/basaltdb/internal/core/guardmodel"

// The guard's vocabulary lives in internal/core/guardmodel. These aliases
// and forwards keep the names guard.X working for the packages that still
// use them.

type (
	AgentColumn            = guardmodel.AgentColumn
	AgentSetup             = guardmodel.AgentSetup
	AgentSpec              = guardmodel.AgentSpec
	AppliedRevert          = guardmodel.AppliedRevert
	BatchItem              = guardmodel.BatchItem
	BatchResult            = guardmodel.BatchResult
	CatalogAgent           = guardmodel.CatalogAgent
	CatalogRun             = guardmodel.CatalogRun
	CatalogTable           = guardmodel.CatalogTable
	Classification         = guardmodel.Classification
	ClassificationState    = guardmodel.ClassificationState
	Code                   = guardmodel.Code
	ColumnKey              = guardmodel.ColumnKey
	ColumnLabel            = guardmodel.ColumnLabel
	Label                  = guardmodel.Label
	LabelChange            = guardmodel.LabelChange
	Migration              = guardmodel.Migration
	Names                  = guardmodel.Names
	PIIColumn              = guardmodel.PIIColumn
	PluginApproval         = guardmodel.PluginApproval
	PluginApprovalBound    = guardmodel.PluginApprovalBound
	PluginApprovalDetail   = guardmodel.PluginApprovalDetail
	PluginApprovalRecord   = guardmodel.PluginApprovalRecord
	PluginApprovalResponse = guardmodel.PluginApprovalResponse
	PluginApprovalStatus   = guardmodel.PluginApprovalStatus
	PluginAuth             = guardmodel.PluginAuth
	PluginDetail           = guardmodel.PluginDetail
	PluginEndpoint         = guardmodel.PluginEndpoint
	PluginEventKind        = guardmodel.PluginEventKind
	PluginIsolation        = guardmodel.PluginIsolation
	PluginModel            = guardmodel.PluginModel
	PluginRecord           = guardmodel.PluginRecord
	PluginRecords          = guardmodel.PluginRecords
	PluginSettings         = guardmodel.PluginSettings
	PreparedRevert         = guardmodel.PreparedRevert
	PreviewLine            = guardmodel.PreviewLine
	PreviewPage            = guardmodel.PreviewPage
	ReadableColumn         = guardmodel.ReadableColumn
	RejectedRevert         = guardmodel.RejectedRevert
	RescopeRequest         = guardmodel.RescopeRequest
	RescopedRevert         = guardmodel.RescopedRevert
	RevealedRevert         = guardmodel.RevealedRevert
	RevertCatalog          = guardmodel.RevertCatalog
	RevertScope            = guardmodel.RevertScope
	Setup                  = guardmodel.Setup
	Status                 = guardmodel.Status
	UnclassifiedColumn     = guardmodel.UnclassifiedColumn
)

const (
	AgentConnectionLimit          = guardmodel.AgentConnectionLimit
	CLIPrepareTimeout             = guardmodel.CLIPrepareTimeout
	ClassFreeText                 = guardmodel.ClassFreeText
	ClassIdentifier               = guardmodel.ClassIdentifier
	ClassPublic                   = guardmodel.ClassPublic
	ClassSecret                   = guardmodel.ClassSecret
	ClassUnclassified             = guardmodel.ClassUnclassified
	CodeApprovalExpired           = guardmodel.CodeApprovalExpired
	CodeApprovalInvalid           = guardmodel.CodeApprovalInvalid
	CodeApprovalRequired          = guardmodel.CodeApprovalRequired
	CodeIntentRequired            = guardmodel.CodeIntentRequired
	CodeLedgerInputInvalid        = guardmodel.CodeLedgerInputInvalid
	CodeNotAllowed                = guardmodel.CodeNotAllowed
	CodeNothingToRevert           = guardmodel.CodeNothingToRevert
	CodePreviewCannotCommit       = guardmodel.CodePreviewCannotCommit
	CodeRevertCascade             = guardmodel.CodeRevertCascade
	CodeRevertExpired             = guardmodel.CodeRevertExpired
	CodeRevertInvalid             = guardmodel.CodeRevertInvalid
	CodeRowLimitExceeded          = guardmodel.CodeRowLimitExceeded
	CodeScopeRefused              = guardmodel.CodeScopeRefused
	CodeSetupRefused              = guardmodel.CodeSetupRefused
	CodeStaleRead                 = guardmodel.CodeStaleRead
	DefaultPrefix                 = guardmodel.DefaultPrefix
	DefaultStatementTimeout       = guardmodel.DefaultStatementTimeout
	DetailAlreadyApproved         = guardmodel.DetailAlreadyApproved
	DetailApprovalCancelled       = guardmodel.DetailApprovalCancelled
	DetailApprovalNotFound        = guardmodel.DetailApprovalNotFound
	DetailHoldTooLarge            = guardmodel.DetailHoldTooLarge
	DetailTooManyPending          = guardmodel.DetailTooManyPending
	DetailUnknownAgent            = guardmodel.DetailUnknownAgent
	EntityAddress                 = guardmodel.EntityAddress
	EntityEmail                   = guardmodel.EntityEmail
	EntityOther                   = guardmodel.EntityOther
	EntityPersonName              = guardmodel.EntityPersonName
	EntityPhone                   = guardmodel.EntityPhone
	GuardMissing                  = guardmodel.GuardMissing
	GuardNewer                    = guardmodel.GuardNewer
	GuardOK                       = guardmodel.GuardOK
	GuardOutdated                 = guardmodel.GuardOutdated
	GuardUnknown                  = guardmodel.GuardUnknown
	GuardUpgradeAvailable         = guardmodel.GuardUpgradeAvailable
	MCPPrepareTimeout             = guardmodel.MCPPrepareTimeout
	MaxHeldLineBytesBefore37      = guardmodel.MaxHeldLineBytesBefore37
	MaxHeldLinesBytes             = guardmodel.MaxHeldLinesBytes
	MaxRejectNote                 = guardmodel.MaxRejectNote
	OutcomePending                = guardmodel.OutcomePending
	OutcomeRestored               = guardmodel.OutcomeRestored
	OutcomeSkipped                = guardmodel.OutcomeSkipped
	PluginApprovalPending         = guardmodel.PluginApprovalPending
	PluginApprovalStatusApproved  = guardmodel.PluginApprovalStatusApproved
	PluginApprovalStatusCancelled = guardmodel.PluginApprovalStatusCancelled
	PluginApprovalStatusExpired   = guardmodel.PluginApprovalStatusExpired
	PluginApprovalStatusPending   = guardmodel.PluginApprovalStatusPending
	PluginApproved                = guardmodel.PluginApproved
	PluginChanged                 = guardmodel.PluginChanged
	PluginDisabled                = guardmodel.PluginDisabled
	PluginEnabled                 = guardmodel.PluginEnabled
	PluginEndpointLocal           = guardmodel.PluginEndpointLocal
	PluginEndpointRemote          = guardmodel.PluginEndpointRemote
	PluginFilesNone               = guardmodel.PluginFilesNone
	PluginFilesOSUser             = guardmodel.PluginFilesOSUser
	PluginNetworkDeclared         = guardmodel.PluginNetworkDeclared
	PluginNetworkEnforced         = guardmodel.PluginNetworkEnforced
	PluginNetworkNotEnforced      = guardmodel.PluginNetworkNotEnforced
	PluginSignerKnown             = guardmodel.PluginSignerKnown
	PluginSignerUnknown           = guardmodel.PluginSignerUnknown
	PluginTrustAdded              = guardmodel.PluginTrustAdded
	PluginTrustRemoved            = guardmodel.PluginTrustRemoved
	RejectViaLinkOrAgent          = guardmodel.RejectViaLinkOrAgent
	RejectViaScopeToken           = guardmodel.RejectViaScopeToken
	RescopeViaOwnWork             = guardmodel.RescopeViaOwnWork
	RescopeViaProof               = guardmodel.RescopeViaProof
	RescopeViaScopeToken          = guardmodel.RescopeViaScopeToken
	RevealRefused                 = guardmodel.RevealRefused
	RevealRowsChanged             = guardmodel.RevealRowsChanged
	RevertWidenRefused            = guardmodel.RevertWidenRefused
	ScopeDescriptor               = guardmodel.ScopeDescriptor
	ScopeFilter                   = guardmodel.ScopeFilter
	ScopeFilterCap                = guardmodel.ScopeFilterCap
	ScopeNotOwnChange             = guardmodel.ScopeNotOwnChange
	ScopeNotOwnRun                = guardmodel.ScopeNotOwnRun
	ScopeNotOwnTask               = guardmodel.ScopeNotOwnTask
	ScopeShape                    = guardmodel.ScopeShape
	ScopeStoreReserved            = guardmodel.ScopeStoreReserved
	SetupAgent                    = guardmodel.SetupAgent
	SetupExpired                  = guardmodel.SetupExpired
	SetupExpiryTooFar             = guardmodel.SetupExpiryTooFar
	SetupIDInFuture               = guardmodel.SetupIDInFuture
	SetupInstall                  = guardmodel.SetupInstall
	SetupSuperseded               = guardmodel.SetupSuperseded
	SetupUpgrade                  = guardmodel.SetupUpgrade
	SetupUsed                     = guardmodel.SetupUsed
	UnclassifiedClass             = guardmodel.UnclassifiedClass
	UnclassifiedNew               = guardmodel.UnclassifiedNew
	UnclassifiedTypeChanged       = guardmodel.UnclassifiedTypeChanged
)

var (
	EntityTypes       = guardmodel.EntityTypes
	ErrClassesChanged = guardmodel.ErrClassesChanged
	ErrInvalidAgent   = guardmodel.ErrInvalidAgent
	ErrInvalidName    = guardmodel.ErrInvalidName
	ErrLabelNotListed = guardmodel.ErrLabelNotListed
	ErrPrepareTimeout = guardmodel.ErrPrepareTimeout
	LabelClasses      = guardmodel.LabelClasses
)

// agentInfix is the role name part between the prefix and an agent name.
const agentInfix = guardmodel.AgentInfix

// ValidAgentName forwards to guardmodel.ValidAgentName.
func ValidAgentName(name string) bool { return guardmodel.ValidAgentName(name) }

// ValidLabel forwards to guardmodel.ValidLabel.
func ValidLabel(l Label) bool { return guardmodel.ValidLabel(l) }

// ValidWas forwards to guardmodel.ValidWas.
func ValidWas(l Label) bool { return guardmodel.ValidWas(l) }
