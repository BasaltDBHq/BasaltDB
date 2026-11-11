package main

import (
	"bytes"
	"errors"
	"fmt"
	"runtime"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/basaltdbhq/basaltdb/internal/approval"
	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/ledger"
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
)

// runApprove: basalt approve. A relay, never an approver: it carries the
// code the approval page gave the person to Postgres, which checks the
// passkey signature (owner decision #6). With --show it prints the
// approval link of one of the agent's held writes; with --open it opens
// that link in the browser.
func runApprove(c *cliIO, args []string) int {
	fs := c.flags("approve")
	show := fs.String("show", "", "print the approval link of this held write (approval id) instead")
	reissue := fs.Bool("reissue", false, "with --show or --open: issue a new short link (the held write's earlier short link stops working)")
	open := fs.String("open", "", "open the approval link of this held write (approval id) in your browser instead")
	pagesURL := fs.String("pages-url", "", "pages base URL for --show and --open (default: the engine config's pagesUrl, else "+links.DefaultLocal+")")
	agent := fs.String("agent", "", "use this agent's credential from the engine config")
	configPath := fs.String("config", config.DefaultPath(runtime.GOOS), "engine config file")
	credFile := fs.String("credential-file", "", "read the agent's connection string from this file")
	if err := fs.Parse(args); err != nil {
		return c.fail(fmt.Errorf("%w: %w", errUsage, err))
	}
	if *show != "" && *open != "" {
		return c.fail(fmt.Errorf("%w: give --show or --open, not both", errUsage))
	}
	held := *show + *open
	if *reissue && held == "" {
		return c.fail(fmt.Errorf("%w: --reissue goes with --show or --open", errUsage))
	}
	code, err := approveCode(c, fs.Args(), held)
	if err != nil {
		return c.fail(err)
	}
	dsn, err := agentURL(c, *agent, *credFile, *configPath)
	if err != nil {
		return c.fail(err)
	}
	conn, err := connect(c.ctx, dsn)
	if err != nil {
		return c.fail(err)
	}
	defer conn.Close(c.ctx)
	if held != "" {
		pages := linkPages{
			base: configuredBase(*pagesURL, *agent, *configPath),
		}
		if *reissue {
			// A short link is issued only on request: issuing revokes the
			// one the agent handed over (CONTRACT.md, Link secrets).
			pages.local = localPages(c, *pagesURL, *agent, *configPath)
		}
		return showApproval(c, conn, held, pages, *open != "")
	}
	return submitApproval(c, conn, code)
}

// approveCode is the response code: the one argument, or a line from stdin
// when there is none. --show and --open (held) take no code.
func approveCode(c *cliIO, args []string, held string) (string, error) {
	switch {
	case held != "" && len(args) > 0:
		return "", fmt.Errorf("%w: --show and --open take no code", errUsage)
	case held != "":
		return "", nil
	case len(args) > 1:
		return "", fmt.Errorf("%w: give one approval code", errUsage)
	case len(args) == 1:
		return args[0], nil
	}
	fmt.Fprint(c.stderr, "Paste the code the approval page showed: ")
	return c.line()
}

// showApproval prints the approval link of a held write on stdout, or with
// open opens it in the browser (printing it only when no browser opens):
// the short link when the engine serves the pages, else the long one.
func showApproval(c *cliIO, conn *pgx.Conn, idText string, pages linkPages, open bool) int {
	id, err := uuid.Parse(idText)
	if err != nil {
		return c.fail(fmt.Errorf("%w: --show and --open need an approval id", errUsage))
	}
	a, err := ledger.FindApproval(c.ctx, conn, id)
	if errors.Is(err, ledger.ErrApprovalNotFound) {
		return c.fail(fmt.Errorf("approval %s is not a held write of this agent", id))
	}
	if err != nil {
		return c.fail(err)
	}
	if a.Status != ledger.ApprovalPending {
		fmt.Fprintf(c.stderr, "basalt: approval %s is %s\n", id, a.Status)
	}
	keys, err := ledger.Passkeys(c.ctx, conn)
	if err != nil {
		return c.fail(err)
	}
	ids := make([]passkey.Bytes, 0, len(keys))
	for _, k := range keys {
		ids = append(ids, k.ID)
	}
	summary, err := approval.SummarizeText(a.Lines)
	if err != nil {
		return c.fail(err)
	}
	link, err := approval.Request{ApprovalID: a.ID, Binding: a.BindingText, Lines: a.Lines, CredentialIDs: ids}.URL(pages.base)
	if err != nil {
		return c.fail(err)
	}
	link = pages.short(c, "approvals", a.ID, a.BindingText, link)
	fmt.Fprintf(c.stderr, "basalt: %s\n", summary.Headline())
	expires := a.ExpiresAt.UTC().Format(timeLayout)
	if open {
		fmt.Fprintf(c.stderr, "basalt: %d rows, held by run %s, expires %s\n", a.Rows, a.RunID, expires)
		openLink(c, link, c.stdout)
		fmt.Fprintln(c.stderr, pages.nextStep("basalt: check the rows and sign with your passkey", "basalt approve '<code>'"))
		return exitOK
	}
	fmt.Fprintf(c.stderr, "basalt: %d rows, held by run %s, expires %s; open this link on a device with your passkey:\n",
		a.Rows, a.RunID, expires)
	fmt.Fprintln(c.stdout, link)
	return exitOK
}

func submitApproval(c *cliIO, conn *pgx.Conn, code string) int {
	resp, err := approval.ParseResponse(code)
	if err != nil {
		return c.fail(fmt.Errorf("%w: %w", errUsage, err))
	}
	if err := checkLocally(c, conn, resp); err != nil {
		return c.fail(err)
	}
	if _, err := guard.SubmitApproval(c.ctx, conn, resp.ApprovalID, resp.Assertion()); err != nil {
		return c.fail(fmt.Errorf("the database refused the approval: %s", pgDetail(err)))
	}
	fmt.Fprintf(c.stderr, "basalt: approval %s signed; the agent applies it by repeating the write with approvalId %s\n",
		resp.ApprovalID, resp.ApprovalID)
	return exitOK
}

// checkLocally verifies the code with the Go mirror of the Postgres check
// when this agent can see the approval, for a clear message before
// submitting. Postgres checks again either way.
func checkLocally(c *cliIO, conn *pgx.Conn, resp approval.Response) error {
	a, err := ledger.FindApproval(c.ctx, conn, resp.ApprovalID)
	if errors.Is(err, ledger.ErrApprovalNotFound) {
		return nil // another agent's approval: only Postgres can check it
	}
	return verifyCode(c, conn, err, resp.CredentialID, "submitted", func(k passkey.Credential) error {
		_, err := approval.Verify(a.BindingText, k, resp)
		return err
	})
}

// verifyCode runs verify with the registered passkey that signed a relayed
// code (the Go mirror of the Postgres check, for a clear message before
// relaying), or fails when the database does not know that passkey. found
// is the error of looking up what the code signs.
func verifyCode(c *cliIO, conn *pgx.Conn, found error, credentialID []byte, notDone string, verify func(passkey.Credential) error) error {
	if found != nil {
		return found
	}
	keys, err := ledger.Passkeys(c.ctx, conn)
	if err != nil {
		return err
	}
	for _, k := range keys {
		if !bytes.Equal(k.ID, credentialID) {
			continue
		}
		if err := verify(k); err != nil {
			return fmt.Errorf("the code does not verify, nothing was %s: %w", notDone, err)
		}
		return nil
	}
	return errors.New("the code was signed by a passkey this database does not know; run basalt init to register yours")
}

// pgDetail is a Postgres error with its detail, which says what the guard
// refused and why (it names nothing secret).
func pgDetail(err error) string {
	var pe *pgconn.PgError
	if !errors.As(err, &pe) {
		return err.Error()
	}
	if pe.Detail == "" {
		return pe.Message
	}
	return pe.Message + ": " + pe.Detail
}
