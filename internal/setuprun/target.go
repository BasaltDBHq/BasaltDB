package setuprun

import (
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/setupcode"
)

// CheckTarget refuses an admin connection whose database, got, is not the
// code's target (step 3, CO-17): with a Supabase project ref, the same ref
// and database; otherwise the same host, port and database.
func CheckTarget(p setupcode.Payload, got setupcode.Target) error {
	if p.Target == nil || SameDatabase(*p.Target, got) {
		// A connect-only code has no target: the database the connection
		// names is the setup's (never TARGET_MISMATCH).
		return nil
	}
	want := TargetWords(*p.Target)
	msg := fmt.Sprintf("This setup code is for database %s of %s (the agent connects there). Your admin connection string points at database %s of %s. "+
		"Either run this command with the admin connection string of %s, or ask %s for a new code for the database you meant",
		p.Target.Database, want, got.Database, TargetWords(got), want, AgentWord(p))
	return refuse(CodeTargetMismatch, msg+".")
}

// CheckConnTarget is CheckTarget for an open connection's configuration:
// its host, port, database and user, and every fallback on the same host
// and port (pgx adds one per TLS mode it tries). Its message names no
// connection string.
func CheckConnTarget(p setupcode.Payload, cfg *pgx.ConnConfig) error {
	for _, fb := range cfg.Fallbacks {
		if !strings.EqualFold(fb.Host, cfg.Host) || fb.Port != cfg.Port {
			return refuse(CodeTargetMismatch, "the admin connection names several hosts; connect to the database's one host")
		}
	}
	return CheckTarget(p, setupcode.ConnTarget(cfg.Host, int(cfg.Port), cfg.Database, cfg.User))
}

// SameDatabase compares by database identity (CO-17): a Supabase project
// by its ref and database name, so its pooler and direct hosts match;
// anything else by host, port and database.
func SameDatabase(want, got setupcode.Target) bool {
	if want.SupabaseRef != "" {
		return got.SupabaseRef == want.SupabaseRef && got.Database == want.Database
	}
	return strings.EqualFold(got.Host, want.Host) && got.Port == want.Port && got.Database == want.Database
}

// TargetWords names where a target is: a Supabase project, or host:port.
func TargetWords(t setupcode.Target) string {
	if t.SupabaseRef != "" {
		return "Supabase project " + t.SupabaseRef
	}
	return fmt.Sprintf("%s:%d", printableLabel(t.Host), t.Port)
}
