package guardmodel

// MaxHeldLinesBytes is the most a held write's preview lines may hold, in
// bytes of their text summed (CONTRACT.md, Large values). Over it,
// preview_lines and hold_action refuse with BS007 NOT_ALLOWED and detail
// DetailHoldTooLarge.
const MaxHeldLinesBytes = 64 << 20

// DetailHoldTooLarge is the detail of the guard's refusal of preview lines
// over MaxHeldLinesBytes.
const DetailHoldTooLarge = "HOLD_TOO_LARGE"
