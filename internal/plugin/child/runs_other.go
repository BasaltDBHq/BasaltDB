//go:build !unix

package child

import (
	"errors"
	"io/fs"
)

const noFollow = 0

func ownedByMe(fs.FileInfo) bool { return false }

func killGroupID(int) error { return errors.New("child: no process groups on this OS") }

func getpgrp() int { return 0 }
