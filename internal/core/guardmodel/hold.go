package guardmodel

// MaxHeldLinesBytes is the most a held write's preview lines may hold, in
// bytes of their text summed (basalt_meta version 37; CONTRACT.md, Large
// values). Over it, preview_lines and hold_action refuse with BS007
// NOT_ALLOWED and detail DetailHoldTooLarge.
const MaxHeldLinesBytes = 64 << 20

// MaxHeldLineBytesBefore37 is the most one preview line may hold on a
// guard before version 37; hold_action refuses a longer one with BS008.
const MaxHeldLineBytesBefore37 = 64 << 10

// DetailHoldTooLarge is the detail of the guard's refusal of preview lines
// over MaxHeldLinesBytes.
const DetailHoldTooLarge = "HOLD_TOO_LARGE"
