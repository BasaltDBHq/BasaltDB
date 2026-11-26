package guardmodel

// MaxHeldLinesBytes is the most a held write's preview lines may hold, in
// bytes of their text summed (CONTRACT.md, Large values). Over it, the
// store refuses the hold (STATEMENT_REFUSED reason HOLD_TOO_LARGE).
const MaxHeldLinesBytes = 64 << 20
