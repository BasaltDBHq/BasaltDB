package main

import (
	"bytes"
	"io"
)

// fixedRand is a deterministic randomness source, so a test can build the
// same registration request basalt init builds.
func fixedRand() io.Reader { return bytes.NewReader(bytes.Repeat([]byte{0x42}, 1024)) }
