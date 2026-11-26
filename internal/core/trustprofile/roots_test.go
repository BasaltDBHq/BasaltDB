package trustprofile

import "github.com/basaltdbhq/basaltdb/internal/lib/certroots"

// BuiltIns are the embedded profiles with the system's roots, as the
// engine loads them.
var BuiltIns = LoadBuiltIns(certroots.Store{})
