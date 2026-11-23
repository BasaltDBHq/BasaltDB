package setup

import (
	"errors"
	"fmt"
	"regexp"
)

// initStep is the prefix the backend's ApplyScript puts on a statement's
// error.
var initStep = regexp.MustCompile(`^init step (\d+): `)

// sqlstateInsufficientPrivilege is Postgres's insufficient_privilege.
const sqlstateInsufficientPrivilege = "42501"

// FailedStep is step, with the setup script's statement number when err is
// the error of one of its statements.
func FailedStep(step string, err error) string {
	if err == nil {
		return step
	}
	if m := initStep.FindStringSubmatch(err.Error()); m != nil {
		return step + ", statement " + m[1]
	}
	return step
}

// SQLStateOf is the SQLSTATE of the database error in err, empty when err
// carries none. The driver's error says it through its SQLState method.
func SQLStateOf(err error) string {
	var pg interface{ SQLState() string }
	if errors.As(err, &pg) {
		return pg.SQLState()
	}
	return ""
}

// FailedMessage is SETUP_FAILED's fixed sentence for a failure at step
// with sqlstate: it names the Postgres error and the step, never the
// database's or the driver's own words, which stay in the error for the
// log.
func FailedMessage(step, sqlstate string) string {
	switch {
	case sqlstate == sqlstateInsufficientPrivilege:
		return fmt.Sprintf("The admin role lacks a privilege the setup needs (Postgres error %s, %s); nothing changed.", sqlstate, step)
	case sqlstate != "":
		return fmt.Sprintf("Reading the database or running the setup failed (Postgres error %s, %s); nothing changed.", sqlstate, step)
	}
	return "Reading the database or running the setup failed; nothing changed."
}
