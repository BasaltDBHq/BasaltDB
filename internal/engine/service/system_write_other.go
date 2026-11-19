//go:build !unix

package service

import (
	"errors"
	"os"
)

var errUnsupported = errors.New("the engine service installs on linux and darwin only")

func (OSSystem) WriteFile(string, []byte, os.FileMode, string) error { return errUnsupported }

func (OSSystem) CreateFile(string, os.FileMode, string) error { return errUnsupported }

func (OSSystem) Mkdir(string, os.FileMode, string, string) error { return errUnsupported }

func (OSSystem) RemoveTree(string) error { return errUnsupported }

func (OSSystem) CheckBinary(string) error { return errUnsupported }

func OpenTrustedFile(string, int) (*os.File, error) { return nil, errUnsupported }
