package localsetup

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard"
)

// Job is what a setup link carries (CONTRACT.md, The local setup page, The
// link): the job, the agent, the OS user it runs as and whether it is the
// sample database. It is not a secret.
type Job struct {
	Job    string `json:"job"`
	Agent  string `json:"agent"`
	OSUser string `json:"osUser"`
	Demo   bool   `json:"demo"`
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

// ValidAgentName reports whether name makes an agent role under the default
// prefix.
func ValidAgentName(name string) bool { return guard.ValidAgentName(name) }

// SetupCheckPath is the setup page's check route.
const SetupCheckPath = "/api/v1/setup/check"

// SetupRunPath is the setup page's run route.
const SetupRunPath = "/api/v1/setup/run"

// SetupDoctorPath is the setup page's Update check route.
const SetupDoctorPath = "/api/v1/setup/doctor"
