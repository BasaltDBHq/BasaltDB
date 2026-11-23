package setup

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// EnvSudoUID is the uid of the user who ran sudo.
const EnvSudoUID = "SUDO_UID"

var ErrNoPerson = errors.New("no person to record (init runs as root without SUDO_UID); " +
	"give --person-uid N, the person's OS user id")

// CheckPersons refuses no uid and root.
func CheckPersons(uids []uint32) error {
	if len(uids) == 0 {
		return ErrNoPerson
	}
	for _, u := range uids {
		if u == 0 {
			return errors.New("--person-uid 0 is root; give the person's OS user id")
		}
	}
	return nil
}

// ParseUID reads an OS user id.
func ParseUID(v string) (uint32, error) {
	uid, err := strconv.ParseUint(strings.TrimSpace(v), 10, 32)
	if err != nil {
		return 0, fmt.Errorf("%q is not an OS user id", v)
	}
	return uint32(uid), nil
}
