package pii

import "github.com/basaltdbhq/basaltdb/internal/lib/pgquerier"

// The page transactions pii is given are pgquerier.Neutral: a change to its
// method would otherwise fail every page.
var _ textQuerier = pgquerier.Neutral{}
