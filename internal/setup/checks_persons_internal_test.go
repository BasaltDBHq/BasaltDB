package setup

import (
	"errors"
	"os/user"
	"testing"

	"github.com/stretchr/testify/require"
)

// engineUsers knows one OS user, the engine's, with uid 4000.
type engineUsers struct{ noUsers }

func (engineUsers) Lookup(name string) (*user.User, error) {
	if name == "basalt" {
		return &user.User{Uid: "4000", Username: name}, nil
	}
	return nil, errors.New("no such user")
}

// A service install never records the engine's own OS user as the person;
// an engine user that does not exist yet (the install creates it) is no
// refusal.
func TestCheckServicePersonsRefusesTheEngineUser(t *testing.T) {
	t.Parallel()
	require.ErrorContains(t, CheckServicePersons([]uint32{501, 4000}, "basalt", engineUsers{}), "is the engine's own OS user basalt")
	require.NoError(t, CheckServicePersons([]uint32{501}, "basalt", engineUsers{}))
	require.NoError(t, CheckServicePersons([]uint32{4000}, "newuser", engineUsers{}))
}
