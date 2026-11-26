package setupstore_test

import (
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/setupstore"
	"github.com/basaltdbhq/basaltdb/internal/setup"
)

// Store is the backend the setup service runs on.
var _ setup.SetuprunBackend = setupstore.Store{}

// Store is also the setup contract's backend (pkg/setup).
var _ setup.ContractBackend = setupstore.Store{}
