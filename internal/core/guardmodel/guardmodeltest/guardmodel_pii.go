package guardmodeltest

import (
	"time"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
)

// Classification is one write of basalt classify.
type Classification struct {
	// Columns are upserted; columns not listed keep their row.
	Columns []guardmodel.PIIColumn
	// At stamps confirmed_at and classified_at.
	At time.Time
}

// ClassificationState is what basalt classify reads before it suggests:
// the readable columns, the stored classes and both fingerprints.
type ClassificationState struct {
	// Readable is pii_readable_columns(), by schema, table and attnum.
	Readable []guardmodel.ReadableColumn
	// Stored are the rows of pii_columns.
	Stored map[guardmodel.ColumnKey]guardmodel.PIIColumn
	// Fingerprint is pii_fingerprint() now.
	Fingerprint []byte
	// Previous is pii_catalog.fingerprint, nil before the first classify.
	Previous []byte
}
