package setupcode

// Refusal names why a setup code is refused (CONTRACT.md, The setup
// checks). The codec's are the first four; the rest are the runner's
// checks against its clock, its binary and the database.
type Refusal string

// Refusals.
const (
	RefusalNotASetupCode     Refusal = "NOT_A_SETUP_CODE"
	RefusalUnsupportedFormat Refusal = "UNSUPPORTED_FORMAT"
	RefusalDamaged           Refusal = "DAMAGED"
	RefusalInvalid           Refusal = "INVALID"

	RefusalExpired         Refusal = "EXPIRED"
	RefusalSetupIDInFuture Refusal = "SETUP_ID_IN_FUTURE"
	RefusalExpiryTooFar    Refusal = "EXPIRY_TOO_FAR"
	RefusalBinaryTooOld    Refusal = "BINARY_TOO_OLD"
	RefusalGuardTooOld     Refusal = "GUARD_TOO_OLD"
	RefusalPrefixMismatch  Refusal = "PREFIX_MISMATCH"
	RefusalUsed            Refusal = "USED"
	RefusalSuperseded      Refusal = "SUPERSEDED"
	RefusalRoleExists      Refusal = "ROLE_EXISTS"
	RefusalRoleMissing     Refusal = "ROLE_MISSING"
)

// Fixed messages (CONTRACT.md, The setup code).
const (
	msgNotASetupCode = "This is not a BasaltDB setup code."
	msgUnsupported   = "This setup code is in a newer format than the connect service reads yet: try again later."
	msgDamaged       = "This setup code is damaged; copy it again."
	msgInvalid       = "This setup code is not valid"
)

// Error is a refused setup code. Message is what the person reads. It
// never holds a secret: a code carries none, and messages name fields, not
// the values the code-maker wrote, except the agent's name and times.
type Error struct {
	Refusal Refusal
	Message string
	// Detail is what is wrong, for INVALID: basalt init --remote names it
	// when its own inputs would make an invalid code.
	Detail string
}

func (e *Error) Error() string { return e.Message }

// refuse builds a codec refusal: the contract's fixed words, or for
// INVALID what is wrong (detail).
func refuse(r Refusal, detail string) *Error {
	switch r {
	case RefusalNotASetupCode:
		return &Error{Refusal: r, Message: msgNotASetupCode}
	case RefusalUnsupportedFormat:
		return &Error{Refusal: r, Message: msgUnsupported}
	case RefusalDamaged:
		return &Error{Refusal: r, Message: msgDamaged}
	default:
		return &Error{Refusal: r, Message: msgInvalid + ": " + detail + ". Ask your agent for a new one.", Detail: detail}
	}
}

func refuseWith(r Refusal, msg string) *Error {
	return &Error{Refusal: r, Message: msg}
}
