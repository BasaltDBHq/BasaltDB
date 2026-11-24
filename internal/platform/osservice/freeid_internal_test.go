package osservice

import (
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// The install picks a macOS system account id with freeID(usedIDs(dscl
// output)): the lowest id from 300 to 499 that dscl does not list.
func TestFreeIDFromDsclOutput(t *testing.T) {
	t.Parallel()
	id, err := freeID(usedIDs(""))
	require.NoError(t, err)
	require.Equal(t, 300, id)
	id, err = freeID(usedIDs("a 300\nb 301\n\nmalformed\nc x\n"))
	require.NoError(t, err)
	require.Equal(t, 302, id)

	var all strings.Builder
	for i := 300; i <= 499; i++ {
		all.WriteString("u " + strconv.Itoa(i) + "\n")
	}
	_, err = freeID(usedIDs(all.String()))
	require.Error(t, err)
}
