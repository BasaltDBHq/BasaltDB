package trustprofile

import (
	"fmt"
	"slices"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// sharedZones are provider zones the public suffix list treats as ordinary
// registrable domains, yet many unrelated parties get hosts under them. They
// add to the list's answer and never replace it; the list already refuses
// the rest of the cloud zones (cloudapp.net, azurewebsites.net,
// googleapis.com, appspot.com, ...).
var sharedZones = []string{
	"amazonaws.com",
	"amazonaws.com.cn",
	"azure.com",
	"cloudapp.azure.com",
	"windows.net",
	"rds.amazonaws.com",
	"rds.amazonaws.com.cn",
	"database.windows.net",
	"postgres.database.azure.com",
}

// CheckOperatorMatch refuses an operator's suffix entry that is a public
// suffix on its own, by Go's public suffix list (ICANN and private entries):
// a single label (com), a country's second level (co.uk, com.au), or a zone
// a provider hands out to many parties (github.io, cloudfront.net,
// s3.amazonaws.com, elb.amazonaws.com). It also refuses a short list of
// shared cloud and database zones the list does not mark (amazonaws.com,
// rds.amazonaws.com, database.windows.net). A profile for one of them would
// be a global root by another name. A domain below a public suffix
// (db.example.com) and an exact host (=host) are never refused here.
func CheckOperatorMatch(m string) error {
	if strings.HasPrefix(m, exactPrefix) {
		return nil
	}
	// The list also names zones by wildcard (*.elb.amazonaws.com), which
	// makes every host directly below them a public suffix but not the zone
	// itself. Probing one label below finds those zones as well.
	own, _ := publicsuffix.PublicSuffix(m)
	below, _ := publicsuffix.PublicSuffix("x." + m)
	if own == m || below == "x."+m || slices.Contains(sharedZones, m) {
		return publicSuffixError(m)
	}
	return nil
}

func publicSuffixError(m string) error {
	return fmt.Errorf("match entry %q is a public suffix on its own, so its roots would verify everyone's hosts under it; "+
		"name your database's own host (=db.example.com) or a domain only you control", m)
}
