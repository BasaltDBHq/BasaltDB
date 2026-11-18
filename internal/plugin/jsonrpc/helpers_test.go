package jsonrpc_test

import (
	"os"
	"strconv"
	"syscall"
)

func itoa(n int) string { return strconv.Itoa(n) }

func syscallZero() os.Signal { return syscall.Signal(0) }
