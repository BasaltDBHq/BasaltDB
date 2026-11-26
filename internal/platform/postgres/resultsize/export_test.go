package resultsize

import (
	"errors"

	"github.com/basaltdbhq/basaltdb/internal/core/budget"
)

// IsSizeLimit reports whether err is a read stopped by the budget.
func IsSizeLimit(err error) bool { return errors.Is(err, budget.ErrSizeLimit) }
