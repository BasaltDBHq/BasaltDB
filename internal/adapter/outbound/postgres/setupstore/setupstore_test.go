package setupstore_test

import (
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/setupstore"
	"github.com/basaltdbhq/basaltdb/internal/service/setuprun"
)

// Store is the backend the setup service runs on.
var _ setuprun.Backend = setupstore.Store{}
