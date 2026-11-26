package setuppage

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/setup"
)

// A refusal the engine raises after the database changed (it could not
// write its own config or files) is an internal error, whatever its code;
// the other refusals take their code's status.
func TestSetupStatusOfAnInternalRefusalIs500(t *testing.T) {
	t.Parallel()
	require.Equal(t, http.StatusInternalServerError, setupStatus(&setup.RefusalError{Code: setup.CodeSetupFailed, Internal: true}))
	require.Equal(t, http.StatusConflict, setupStatus(&setup.RefusalError{Code: setup.CodeSetupFailed}))
	require.Equal(t, http.StatusBadRequest, setupStatus(&setup.RefusalError{Code: setup.CodeInvalidArgument}))
}
