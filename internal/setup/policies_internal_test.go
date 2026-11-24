package setup

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
)

// The row-level security answers name each question at most once: a table
// named twice is refused, as the local setup page refuses it; a question
// not named stays hidden.
func TestPoliciesAnswerEachQuestionOnce(t *testing.T) {
	t.Parallel()
	p := &Prepared{Blind: []guardmodel.BlindTable{{Table: "public.vault"}, {Table: "public.payroll"}}}

	got, err := p.policies([]string{"public.payroll"})
	require.NoError(t, err)
	require.Equal(t, []guardmodel.BlindTable{{Table: "public.payroll"}}, got)

	got, err = p.policies(nil)
	require.NoError(t, err)
	require.Empty(t, got, "no answer: every question is answered no")

	var refusal *SetuprunRefusalError
	_, err = p.policies([]string{"public.vault", "public.vault"})
	require.True(t, errors.As(err, &refusal))
	require.Equal(t, SetuprunCodeAnswersInvalid, refusal.Code)
	require.Equal(t, "the answers name table public.vault twice; answer each question once and check the setup again", refusal.Message)

	_, err = p.policies([]string{"public.other"})
	require.True(t, errors.As(err, &refusal))
	require.Equal(t, SetuprunCodeAnswersInvalid, refusal.Code)
}
