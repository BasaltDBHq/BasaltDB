package linkcodectest

import (
	"fmt"

	"github.com/basaltdbhq/basaltdb/internal/core/linkcodec"
)

// Encode returns a fragment (without '#'): format, then the base64url of
// the deflate-raw of v's JSON.
func Encode(format string, v any) (string, error) {
	raw, err := linkcodec.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("encode request: %w", err)
	}
	return linkcodec.Deflate(format, raw)
}
