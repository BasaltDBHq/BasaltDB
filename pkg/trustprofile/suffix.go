package trustprofile

import (
	"fmt"
	"slices"
	"strings"
)

// sharedApexes are domains under which many unrelated parties get hosts
// (cloud providers' shared zones). A profile matching one of them on its
// own would trust its roots for everyone's hosts there.
var sharedApexes = []string{
	"amazonaws.com",
	"amazonaws.com.cn",
	"azure.com",
	"cloudapp.azure.com",
	"cloudapp.net",
	"windows.net",
	"azurewebsites.net",
	"googleapis.com",
	"appspot.com",
	"cloud.goog",
	"run.app",
	"herokuapp.com",
	"ondigitalocean.app",
	"digitaloceanspaces.com",
	"fly.dev",
	"vercel.app",
	"netlify.app",
	"onrender.com",
	"railway.app",
	"up.railway.app",
}

// countrySecondLevels are the second-level labels registries use under a
// two-letter country code (co.uk, com.au, ne.jp).
var countrySecondLevels = []string{"ac", "co", "com", "edu", "gov", "ltd", "ne", "net", "or", "org", "plc"}

// countryCodeLen is the length of a country-code top-level label.
const countryCodeLen = 2

// CheckOperatorMatch refuses an operator's suffix entry that is a public
// suffix on its own: a single label (com), a country's second level
// (co.uk, com.au) or a cloud provider's shared zone (amazonaws.com). A
// profile for one of them would be a global root by another name. An
// exact host (=host) is never refused here.
func CheckOperatorMatch(m string) error {
	if strings.HasPrefix(m, exactPrefix) {
		return nil
	}
	labels := strings.Split(m, ".")
	switch {
	case len(labels) == 1:
		return publicSuffixError(m)
	case len(labels) == 2 && len(labels[1]) == countryCodeLen && slices.Contains(countrySecondLevels, labels[0]):
		return publicSuffixError(m)
	case slices.Contains(sharedApexes, m):
		return publicSuffixError(m)
	}
	return nil
}

func publicSuffixError(m string) error {
	return fmt.Errorf("match entry %q is a public suffix on its own, so its roots would verify everyone's hosts under it; "+
		"name your database's own host (=db.example.com) or a domain only you control", m)
}
