package localsetup

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
)

// The fixes of the Update check (CONTRACT.md, The Update check): LABELS,
// PASSKEY_ADD and PASSKEY_REMOVE here, TRUST in trustfix.go and REPAIR in
// repair.go. Each is a setup job with the admin connection string: each
// check reads in a transaction it rolls back, and each run repeats its
// check and changes the database in one transaction.

// CodeNothingToFix: the fix finds nothing to change.
const CodeNothingToFix = "NOTHING_TO_FIX"

const (
	// maxCredentialIDBytes is WebAuthn's limit on a credential id.
	maxCredentialIDBytes = 1023
	// maxActivePasskeys is the passkey list's limit: a database holds at
	// most this many active passkeys added on the page.
	maxActivePasskeys = 100
	// addedDate is how a passkey's day of registration is written.
	addedDate = "2 Jan 2006"
)

func nothingToFix() *RefusalError { return refuse(CodeNothingToFix, "There is nothing to fix.") }

// fixDatabase checks in tx what every fix checks before it changes
// anything, after the agent and the admin string's target (validateAgentJob):
// a guard of this engine's prefix and the agent's role. It returns the
// database the server names.
func (s *Service) fixDatabase(ctx context.Context, tx pgx.Tx, j agentJob) (string, error) {
	database, err := currentDatabase(ctx, tx)
	if err != nil {
		return "", err
	}
	if _, err := s.installedGuard(ctx, tx, database, "to fix"); err != nil {
		return "", err
	}
	if err := agentRole(ctx, tx, j, database); err != nil {
		return "", err
	}
	return database, nil
}

// checkFix is a fix's check: it reads and changes nothing.
func (s *Service) checkFix(ctx context.Context, j agentJob) (CheckAnswer, error) {
	switch j.req.Job {
	case JobTrust:
		return s.checkTrust(ctx, j)
	case JobRepair:
		return s.checkRepair(ctx, j)
	}
	conn, err := s.connect(ctx, j.req.DatabaseURL)
	if err != nil {
		return CheckAnswer{}, err
	}
	defer conn.Close(context.WithoutCancel(ctx))
	tx, err := conn.Begin(ctx)
	if err != nil {
		return CheckAnswer{}, setupFailed()
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	database, err := s.fixDatabase(ctx, tx, j)
	if err != nil {
		return CheckAnswer{}, timeLimit(ctx, err)
	}
	var out CheckAnswer
	switch j.req.Job {
	case JobLabels:
		out, err = s.checkLabels(ctx, conn, tx, j, database)
	case JobPasskeyAdd:
		out, err = s.checkPasskeyAdd(ctx, tx, j, database)
	default:
		out, err = s.checkPasskeyRemove(ctx, tx, j, database)
	}
	if err != nil {
		return CheckAnswer{}, timeLimit(ctx, err)
	}
	return out, nil
}

// fixAnswer is the frame of a fix's check answer.
func fixAnswer(database string, lines []string, sql string) CheckAnswer {
	return CheckAnswer{Database: database, Lines: lines, SQL: sql, Questions: []Question{}, Notes: []string{}}
}

// runFix is a fix's run: its check again, then its change, in one
// transaction.
func (s *Service) runFix(ctx context.Context, j agentJob) (RunAnswer, error) {
	switch j.req.Job {
	case JobTrust:
		return s.runTrust(ctx, j)
	case JobRepair:
		return s.runRepair(ctx, j)
	}
	var cred *passkey.Credential
	if j.req.Job == JobPasskeyAdd {
		if j.req.Passkey == nil {
			return RunAnswer{}, refuse(CodePasskeyRequired, "Create the passkey on this page first. Nothing changed.")
		}
		// The challenge's expiry and the registration, before anything
		// connects; its binding once the server named the database.
		c, err := s.verifyPasskey(j.req)
		if err != nil {
			return RunAnswer{}, err
		}
		cred = c
	}
	conn, err := s.connect(ctx, j.req.DatabaseURL)
	if err != nil {
		return RunAnswer{}, err
	}
	defer conn.Close(context.WithoutCancel(ctx))
	answer := RunAnswer{Agent: j.req.Agent, Warnings: []string{}, Passkeys: []RegisteredPasskey{}}
	err = pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
		database, err := s.fixDatabase(ctx, tx, j)
		if err != nil {
			return err
		}
		switch j.req.Job {
		case JobLabels:
			return s.runLabels(ctx, tx, j, database, &answer)
		case JobPasskeyAdd:
			return s.runPasskeyAdd(ctx, tx, j, database, *cred, &answer)
		}
		return s.runPasskeyRemove(ctx, tx, j, &answer)
	})
	if err != nil {
		return RunAnswer{}, timeLimit(ctx, AsRefusal(err))
	}
	return answer, nil
}

// ---- LABELS: the columns the agent may read that have no label ----

// checkLabels lists the columns the agent's role may read whose class is
// UNCLASSIFIED, at most 500, with the classifier's suggestion for each,
// sampled with the admin connection under the install's limits.
func (s *Service) checkLabels(ctx context.Context, conn *pgx.Conn, tx pgx.Tx, j agentJob, database string) (CheckAnswer, error) {
	cols, err := guard.AgentUnlabeled(ctx, tx, j.names, j.role)
	if err != nil {
		return CheckAnswer{}, setupFailed()
	}
	// The listing is read; the transaction ends before the columns are
	// sampled on the connection.
	_ = tx.Rollback(context.WithoutCancel(ctx))
	more := len(cols) > maxColumns
	if more {
		cols = cols[:maxColumns]
	}
	sampled := make([]sampled, len(cols))
	infos := make([]ColumnInfo, len(cols))
	for i, c := range cols {
		infos[i] = ColumnInfo{Table: c.TableName(), Column: c.Column, DataType: c.DataType, Class: c.Class, EntityType: c.EntityType, PhoneRegion: c.PhoneRegion}
		sampled[i] = sampledColumn(infos[i], c.TableOID, c.Attnum)
	}
	s.suggest(ctx, conn, sampled, infos)
	out := fixAnswer(database, []string{
		fmt.Sprintf("This labels the columns of the database %s that have no label yet. Labels apply to every agent on this database.", database),
	}, fmt.Sprintf("-- column labels: the ones you set, written to basalt_meta.pii_columns (%d columns listed)\n", len(infos)))
	out.Columns, out.ColumnsMore = infos, more
	return out, nil
}

// runLabels writes the person's labels as the install writes them, for the
// columns the agent's role may read that have no class.
func (s *Service) runLabels(ctx context.Context, tx pgx.Tx, j agentJob, database string, answer *RunAnswer) error {
	if err := checkFixClasses(j.req.ColumnClasses); err != nil {
		return err
	}
	changes := make([]guard.LabelChange, len(j.req.ColumnClasses))
	for i, c := range j.req.ColumnClasses {
		changes[i] = guard.LabelChange{Table: c.Table, Column: c.Column, Label: c.label(), Was: c.Was.guard()}
	}
	n, err := guard.WriteAgentLabels(ctx, tx, j.names, j.role, changes, j.req.RestPublic, s.opts.Now())
	switch {
	case errors.Is(err, guard.ErrLabelNotListed):
		return refuse(CodeAnswersInvalid, "The column labels are not valid: a column the check does not list. Nothing changed.")
	case errors.Is(err, guard.ErrClassesChanged):
		return refuse(CodeClassesChanged, "A column's label changed since the page showed it (someone classified it, or the column is gone), so nothing changed. Read the labels again.")
	case err != nil:
		return setupFailed()
	}
	answer.Lines = []string{fmt.Sprintf("%d columns labeled in the database %s", n, database)}
	return nil
}

// checkFixClasses applies the install's shape rules to a LABELS run's
// labels: at most 500, each column once, a class the page sets, and a was
// of UNCLASSIFIED, the only class a column the check lists has.
func checkFixClasses(classes []ColumnClass) error {
	bad := func(why string) error {
		return refuse(CodeAnswersInvalid, "The column labels are not valid: "+why+". Nothing changed.")
	}
	if len(classes) > maxColumnClasses {
		return bad("more than 500 columns")
	}
	seen := map[[2]string]bool{}
	for _, c := range classes {
		key := [2]string{c.Table, c.Column}
		switch {
		case seen[key]:
			return bad("a column given twice")
		case !plainTable.MatchString(c.Table) || !plainColumn(c.Column) || !guard.ValidLabel(c.label()):
			return bad("a class, entity type or phone region the page does not set")
		case c.Was.guard() != (guard.Label{Class: guard.ClassUnclassified}):
			return bad("a column the check does not list")
		}
		seen[key] = true
	}
	return nil
}

// ---- PASSKEY_ADD: a passkey on this device ----

func (s *Service) checkPasskeyAdd(ctx context.Context, tx pgx.Tx, j agentJob, database string) (CheckAnswer, error) {
	if err := s.passkeyRoom(ctx, tx); err != nil {
		return CheckAnswer{}, err
	}
	ch, err := s.challenge(j.req, bound{database: database, host: j.host})
	if err != nil {
		return CheckAnswer{}, setupFailed()
	}
	out := fixAnswer(database, []string{
		fmt.Sprintf("This adds a passkey on this device for the database %s. It can approve your agents' held writes and sign undos.", database),
	}, "SELECT basalt_meta.register_passkey(…); -- the passkey you create now, for http://localhost:8787\n")
	out.PasskeyNeeded, out.Challenge = true, &ch
	return out, nil
}

// passkeyRoom refuses a database that holds as many active passkeys as
// the list shows.
func (s *Service) passkeyRoom(ctx context.Context, tx pgx.Tx) error {
	keys, err := guard.ActivePasskeys(ctx, tx)
	if err != nil {
		return setupFailed()
	}
	if len(keys) >= maxActivePasskeys {
		return refuse(CodeAnswersInvalid, "The database holds 100 passkeys, as many as the list shows. Remove one you no longer use first; nothing changed.")
	}
	return nil
}

func (s *Service) runPasskeyAdd(ctx context.Context, tx pgx.Tx, j agentJob, database string, cred passkey.Credential, answer *RunAnswer) error {
	// The challenge was made for this job, agent, database and host.
	if err := s.checkBinding(j.req, bound{database: database, host: j.host}); err != nil {
		return err
	}
	if err := s.passkeyRoom(ctx, tx); err != nil {
		return err
	}
	if err := guard.RegisterPasskey(ctx, tx, cred, j.req.Passkey.Label); err != nil {
		return setupFailed()
	}
	code, _ := cred.CheckCode()
	answer.Lines = []string{fmt.Sprintf("passkey added in the database %s", database)}
	answer.Passkeys = []RegisteredPasskey{{CredentialID: cred.ID, Label: j.req.Passkey.Label, CheckCode: code}}
	return nil
}

// ---- PASSKEY_REMOVE: a lost device ----

// notActive is the refusal of a credential id that is no active passkey.
func notActive() *RefusalError {
	return refuse(CodeAnswersInvalid, "This passkey is not active any more. Nothing changed.")
}

// removedPasskey is the active passkey the request names, with the
// passkeys of this page's origin that stay.
func (s *Service) removedPasskey(ctx context.Context, tx pgx.Tx, j agentJob) (guard.RegisteredPasskey, int, error) {
	id, err := base64.RawURLEncoding.DecodeString(j.req.CredentialID)
	if err != nil || len(id) == 0 || len(id) > maxCredentialIDBytes {
		return guard.RegisteredPasskey{}, 0, notActive()
	}
	keys, err := guard.ActivePasskeys(ctx, tx)
	if err != nil {
		return guard.RegisteredPasskey{}, 0, setupFailed()
	}
	var found *guard.RegisteredPasskey
	others := 0
	for i, k := range keys {
		switch {
		case bytes.Equal(k.ID, id):
			found = &keys[i]
		case k.Origin == s.opts.Origin:
			others++
		}
	}
	if found == nil {
		return guard.RegisteredPasskey{}, 0, notActive()
	}
	return *found, others, nil
}

func (s *Service) checkPasskeyRemove(ctx context.Context, tx pgx.Tx, j agentJob, database string) (CheckAnswer, error) {
	k, others, err := s.removedPasskey(ctx, tx, j)
	if err != nil {
		return CheckAnswer{}, err
	}
	lines := []string{fmt.Sprintf("This removes the passkey %s, added %s. It can no longer approve writes or sign undos.", passkeyLabel(k.Label), k.CreatedAt.UTC().Format(addedDate))}
	if others == 0 {
		lines = append(lines, "It is the last passkey for this computer: until you add one, your agents' held writes and undos wait.")
	}
	return fixAnswer(database, lines, fmt.Sprintf("SELECT basalt_meta.revoke_passkey('\\x%s'::bytea, true);\n", hex.EncodeToString(k.ID))), nil
}

// runPasskeyRemove revokes the passkey, always forced: the admin string is
// what allows it, so the last passkey can go.
func (s *Service) runPasskeyRemove(ctx context.Context, tx pgx.Tx, j agentJob, answer *RunAnswer) error {
	k, others, err := s.removedPasskey(ctx, tx, j)
	if err != nil {
		return err
	}
	if _, err := guard.RevokePasskey(ctx, tx, k.ID, true); err != nil {
		var pg *pgconn.PgError
		if errors.As(err, &pg) && pg.Code == sqlstateLedgerInputInvalid {
			return notActive()
		}
		return setupFailed()
	}
	answer.Lines = []string{fmt.Sprintf("passkey %s removed", passkeyLabel(k.Label))}
	answer.Remaining = &others
	return nil
}

// sqlstateLedgerInputInvalid is the guard's refusal of an input it does
// not accept (basalt_meta._invalid).
const sqlstateLedgerInputInvalid = "BS008"

// passkeyLabel is a passkey's label as a line names it.
func passkeyLabel(label string) string {
	if label == "" {
		return "without a label"
	}
	return label
}

// sampledColumn is a listed column with its catalog reference, for the
// classifier's sample.
func sampledColumn(info ColumnInfo, oid uint32, attnum int16) sampled {
	s := sampled{info: info}
	s.ref.TableOID, s.ref.Attnum = oid, attnum
	return s
}
