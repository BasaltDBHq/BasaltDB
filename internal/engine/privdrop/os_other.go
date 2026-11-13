//go:build !linux && !darwin

package privdrop

import "errors"

var errUnsupported = errors.New("basalt engine --user runs on Linux and macOS only")

func (OS) Umask(int)                {}
func (OS) Setgroups([]uint32) error { return errUnsupported }
func (OS) Setgid(uint32) error      { return errUnsupported }
func (OS) Setuid(uint32) error      { return errUnsupported }
func (OS) NoNewPrivs() error        { return errUnsupported }
func (OS) Verify(Account) error     { return errUnsupported }
