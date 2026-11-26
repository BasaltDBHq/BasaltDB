// Package osusers looks the computer's OS users up for the local setup
// page (the setup service's Users port): each method is the os/user call it
// is named after.
package osusers

import (
	"os"
	"os/user"
)

// Users has no state.
type Users struct{}

func (Users) Lookup(name string) (*user.User, error)  { return user.Lookup(name) }
func (Users) LookupID(uid string) (*user.User, error) { return user.LookupId(uid) }
func (Users) GroupIDs(u *user.User) ([]string, error) { return u.GroupIds() }

// Self is this process's uid.
func (Users) Self() int { return os.Getuid() }
