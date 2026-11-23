package handoff

import (
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"
)

type fakePins struct{ err error }

func (f fakePins) PinNew(string, string, *x509.Certificate, bool) (bool, error) { return false, f.err }

func (f fakePins) Repin(string, string, *x509.Certificate, bool) ([]string, error) { return nil, f.err }

// A profile that covers the host by the time of the YES is a refusal that
// says the certificate authority trusted on the connect page is not pinned.
func TestWritePinWrapsACoveredHost(t *testing.T) {
	t.Parallel()
	f := SetupFiles{ConfigPath: "engine.json", Pins: fakePins{err: setupcode.ErrCovered}}
	err := f.WritePin("db.example.com", Pin{})
	require.ErrorIs(t, err, setupcode.ErrCovered)
	require.ErrorContains(t, err, "so the certificate authority trusted on the connect page is not pinned")

	other := fakePins{err: errNotCovered}
	err = SetupFiles{Pins: other}.WritePin("db.example.com", Pin{})
	require.ErrorIs(t, err, errNotCovered)
	require.NotContains(t, err.Error(), "connect page")
}

var errNotCovered = &coveredTestError{}

type coveredTestError struct{}

func (*coveredTestError) Error() string { return "write failed" }
