package plugin

import (
	"errors"
	"io/fs"
	"os"
	"slices"
	"strings"
)

// AddedKeys are the ids of the keys the person added to the trust store, in
// order: each <keyId>.pem in plugin-trust/ that the path rule and key
// checks accept, as a verification would. The built-in publisher keys are
// not listed: nobody added them. A store that does not exist holds none.
// The engine records PLUGIN_TRUST_ADDED for each id an agent's ledger does
// not have yet.
func (t TrustStore) AddedKeys() ([]string, error) {
	if _, err := os.Lstat(t.dir); errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err := t.check(); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(t.dir)
	if err != nil {
		return nil, pathRefusal(t.dir, "cannot be read")
	}
	var out []string
	for _, e := range entries {
		id, ok := strings.CutSuffix(e.Name(), trustFileExt)
		if !ok || !keyIDPattern.MatchString(id) {
			continue
		}
		if _, builtIn := t.embedded[id]; builtIn {
			continue
		}
		if _, err := t.key(id); err != nil {
			continue // not a trusted key: a signature naming it fails too
		}
		out = append(out, id)
	}
	slices.Sort(out)
	return out, nil
}
