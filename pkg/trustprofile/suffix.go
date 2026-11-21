package trustprofile

import (
	"fmt"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// CheckOperatorMatch refuses an operator's suffix entry that is a public
// suffix on its own, by Go's public suffix list (ICANN and private entries):
// a single label (com), a country's second level (co.uk, com.au), or a
// zone a provider hands out to many parties (github.io, cloudfront.net,
// s3.amazonaws.com, elb.amazonaws.com). A profile for one of them would be a global root by
// another name. A domain below a public suffix (db.example.com) and an
// exact host (=host) are never refused here.
func CheckOperatorMatch(m string) error {
	if strings.HasPrefix(m, exactPrefix) {
		return nil
	}
	// The list also names zones by wildcard (*.elb.amazonaws.com), which
	// makes every host directly below them a public suffix but not the zone
	// itself. Probing one label below finds those zones as well.
	own, _ := publicsuffix.PublicSuffix(m)
	below, _ := publicsuffix.PublicSuffix("x." + m)
	if own == m || below == "x."+m {
		return publicSuffixError(m)
	}
	return nil
}

func publicSuffixError(m string) error {
	return fmt.Errorf("match entry %q is a public suffix on its own, so its roots would verify everyone's hosts under it; "+
		"name your database's own host (=db.example.com) or a domain only you control", m)
}
