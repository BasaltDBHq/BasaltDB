package stepcatalogtest

// ApprovalErrorKeys are the CaseKeys of the error cases the approval package
// runs on its own step builders (see RevertErrorKeys).
func ApprovalErrorKeys() []string {
	return sorted(
		CaseKey("APPROVAL_INVALID", "ALREADY_USED", ""),
		CaseKey("APPROVAL_INVALID", "DIFFERENT_WRITE", ""),
		CaseKey("APPROVAL_INVALID", "NOT_THIS_AGENT", ""),
		CaseKey("APPROVAL_INVALID", "ROWS_CHANGED", ""),
		CaseKey("APPROVAL_REQUIRED", "HELD", ""),
		CaseKey("APPROVAL_REQUIRED", "HELD_NO_PAGES", ""),
		CaseKey("APPROVAL_REQUIRED", "NO_PASSKEY", ""),
		CaseKey("APPROVAL_REQUIRED", "REQUEST_TOO_LARGE", ""),
		CaseKey("APPROVAL_REQUIRED", "WAIT_ENDED", ""),
		CaseKey("STATEMENT_REFUSED", "HOLD_TOO_LARGE", ""),
	)
}

// ApprovalResultKeys are the keys (tool|case) of the result cases the
// approval package runs.
func ApprovalResultKeys() []string {
	return sorted(
		"list_pending|EXPIRED",
		"list_pending|PENDING",
		"list_pending|REQUEST_TOO_LARGE",
	)
}
