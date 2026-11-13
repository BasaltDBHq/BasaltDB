//go:build !darwin && !linux

package main

import (
	"context"
	"os"
)

func readTerminalLine(context.Context, *os.File, []byte) (string, error) {
	return "", errNoRawRead
}
