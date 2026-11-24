package setupcli

import (
	"github.com/basaltdbhq/basaltdb/internal/platform/cli"
	"github.com/basaltdbhq/basaltdb/internal/setup"
)

// InvokingUID is the uid of the person running init.
func InvokingUID(c *cli.IO) (uint32, error) {
	euid := c.Host.Euid()
	if euid != 0 {
		return uint32(euid), nil
	}
	sudo := c.Getenv(setup.EnvSudoUID)
	if sudo == "" {
		return 0, setup.ErrNoPerson
	}
	return setup.ParseUID(sudo)
}
