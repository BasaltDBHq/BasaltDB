// Package localsetup is the local setup page's link: the job a setup link
// carries, the link itself and the page's routes. The page's jobs are the
// setup service's (internal/setup, LocalService); setuppage serves them.
package localsetup

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

// Job is what a setup link carries (CONTRACT.md, The local setup page, The
// link): the job, the agent, the OS user it runs as and whether it is the
// sample database. It is not a secret.
type Job struct {
	Job    string `json:"job"`
	Agent  string `json:"agent"`
	OSUser string `json:"osUser"`
	// Demo is in the link only when it is true: a CHANGE, REMOVE or UPDATE
	// link never names it, and the page reads a missing one as false.
	Demo bool `json:"demo,omitempty"`
}

// SetupPath is the setup page's path, and linkPrefix its fragment's.
const (
	SetupPath  = "/setup/"
	linkPrefix = "1."
)

// Link is the setup page's link for job at origin:
// <origin>/setup/#1.<b64url(json)>.
func Link(origin string, job Job) (string, error) {
	if origin == "" || strings.HasSuffix(origin, "/") {
		return "", errors.New("localsetup: an origin without a trailing slash is required")
	}
	raw, err := json.Marshal(job)
	if err != nil {
		return "", err
	}
	return origin + SetupPath + "#" + linkPrefix + base64.RawURLEncoding.EncodeToString(raw), nil
}

// SetupCheckPath is the setup page's check route.
const SetupCheckPath = "/api/v1/setup/check"

// SetupRunPath is the setup page's run route.
const SetupRunPath = "/api/v1/setup/run"
