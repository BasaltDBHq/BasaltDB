package config

import "regexp"

var loadErrorSecrets = []*regexp.Regexp{
	// scheme://user:password@host: the whole userinfo goes, to the last @ of
	// the word, since a password may hold a character a URL parser stops at.
	regexp.MustCompile(`(?i)([a-z][a-z0-9+.-]*://)[^\s"']*@`),
	regexp.MustCompile(`(?i)(password\s*=\s*)[^\s"'&]+`),
}

// ScrubLoadError is the text of a Load error with a URL's user name and
// password and any password= value replaced, for a place the agent reads
// it. The config errors quote the value they refused (a pagesUrl, a
// vaultUrl), and a value can hold a credential.
func ScrubLoadError(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	s = loadErrorSecrets[0].ReplaceAllString(s, "${1}[redacted]@")
	return loadErrorSecrets[1].ReplaceAllString(s, "${1}[redacted]")
}
