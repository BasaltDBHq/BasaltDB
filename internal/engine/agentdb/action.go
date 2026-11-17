package agentdb

import (
	"github.com/basaltdbhq/basaltdb/internal/action"
	"github.com/basaltdbhq/basaltdb/internal/guard"
)

// The service speaks internal/action; the guard's functions take their own
// types. These map one to the other at the store's edge, field for field.

func guardIntent(in action.Intent) guard.Intent {
	return guard.Intent{RunID: in.RunID, TaskID: in.TaskID, Text: in.Text}
}

func guardRead(r action.Read) guard.Read {
	return guard.Read{
		RunID: r.RunID, Statement: r.Statement, Params: r.Params, Tables: r.Tables,
		Rows: r.Rows, Duration: r.Duration, Versions: guardVersions(r.Versions),
	}
}

func guardVersions(vs []action.RowVersion) []guard.RowVersion {
	if vs == nil {
		return nil
	}
	out := make([]guard.RowVersion, len(vs))
	for i, v := range vs {
		out[i] = guard.RowVersion{TableOID: v.TableOID, Key: v.Key, Version: v.Version}
	}
	return out
}

func guardRefusal(r action.Refusal) guard.Refusal {
	return guard.Refusal{
		Intent: guardIntent(r.Intent), Op: string(r.Op), Statement: r.Statement, Params: r.Params,
		Code: r.Code, Reason: r.Reason, Duration: r.Duration,
	}
}
