package main

import (
	"bytes"
	"errors"
	"fmt"
	"runtime"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/basaltdbhq/basaltdb/internal/approval"
	"github.com/basaltdbhq/basaltdb/internal/engine/config"
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
	reissue := fs.Bool("reissue", false, "with --show or --open: issue a new short link; this is now the default when the engine serves the pages locally (the held write's earlier short link stops working)")
	open := fs.String("open", "", "open the approval link of this held write (approval id) in your browser instead")
	var pagesURL string
	pagesURLFlag(fs, &pagesURL, "pages base URL for --show and --open (default: the engine config's pagesUrl, else "+links.DefaultLocal+")")
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
	if c.needsAgent(*agent, *credFile) {
		if *agent, err = approvalAgent(c, *configPath, held, code); err != nil {
			return c.fail(err)
		}
	}
	l, err := openLedger(c, *agent, *credFile, *configPath)
	if err != nil {
		return c.fail(err)
	}
	defer l.close()
	if held != "" {
		// Where the engine serves the pages, a short link is issued, which
		// revokes the one the agent handed over (CONTRACT.md, Link secrets),
		// and the page relays the signature; --reissue is the same thing.
		pages := linkPages{
			base:  l.pagesBase(pagesURL),
			local: l.localPages(c, pagesURL),
		}
		return showApproval(c, l, held, pages, *open != "")
	}
	return submitApproval(c, l, code)
}

// approvalAgent picks the agent of a code, or of the held write --show
// or --open names, when none was named (pickAgent).
func approvalAgent(c *cliIO, configPath, held, code string) (string, error) {
	var id uuid.UUID
	if held != "" {
		parsed, err := uuid.Parse(held)
		if err != nil {
			return "", fmt.Errorf("%w: --show and --open need an approval id", errUsage)
		}
		id = parsed
	} else {
		resp, err := approval.ParseResponse(code)
		if err != nil {
			return "", fmt.Errorf("%w: %w", errUsage, err)
		}
		id = resp.ApprovalID
	}
	return pickAgent(c, configPath, "approval "+id.String(), ownsApproval(c, configPath, id))
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
	return c.pasted(c.ctx)
}

// showApproval prints the approval link of a held write on stdout, or with
// open opens it in the browser (printing it only when no browser opens):
// the short link when the engine serves the pages, else the long one.
func showApproval(c *cliIO, l *agentLedger, idText string, pages linkPages, open bool) int {
	id, err := uuid.Parse(idText)
	if err != nil {
		return c.fail(fmt.Errorf("%w: --show and --open need an approval id", errUsage))
	}
	a, err := l.FindApproval(c.ctx, id)
	if errors.Is(err, ledger.ErrApprovalNotFound) {
		return c.fail(fmt.Errorf("approval %s is not a held write of this agent", id))
	}
	if err != nil {
		return c.fail(err)
	}
	if a.Status != ledger.ApprovalPending {
		fmt.Fprintln(c.stderr, approvalStatusLine(id, a.Status))
	}
	keys, err := l.credentials(c.ctx)
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
	ref := linkRef{setting: "pagesUrl", item: "approval " + id.String(), again: "basalt approve --show " + id.String()}
	long := link
	link = pages.short(c, "approvals", a.ID, a.BindingText, long)
	if link == long {
		// No short link was issued, so the page cannot relay: paste it.
		pages.local = ""
	}
	fmt.Fprintf(c.stderr, "basalt: %s\n", visibleText(summary.Headline()))
	expires := a.ExpiresAt.UTC().Format(timeLayout)
	if open {
		fmt.Fprintf(c.stderr, "basalt: %d rows, held by run %s, expires %s\n", a.Rows, a.RunID, expires)
		if err := openLink(c, link, c.stdout, ref); err != nil {
			return c.fail(err)
		}
		if pages.local != "" {
			fmt.Fprintln(c.stderr, replacesLink)
			return awaitApproval(c, l, id)
		}
		fmt.Fprintln(c.stderr, pages.nextStep("basalt: check the rows and sign with your passkey", "basalt approve '<code>'"))
		return exitOK
	}
	fmt.Fprintf(c.stderr, "basalt: %d rows, held by run %s, expires %s; open this link on a device with your passkey:\n",
		a.Rows, a.RunID, expires)
	if err := printLink(c, c.stdout, link, ref); err != nil {
		return c.fail(err)
	}
	if pages.local != "" {
		fmt.Fprintln(c.stderr, replacesLink)
		return awaitApproval(c, l, id)
	}
	return exitOK
}

// replacesLink tells the person the short link took the agent's link's place.
const replacesLink = "basalt: this link replaces the one the agent showed you; the agent still applies the write by its approval id"

// approvalStatusLine says a held write is no longer pending, with the
// status from the database escaped (visibleText).
func approvalStatusLine(id uuid.UUID, status string) string {
	return fmt.Sprintf("basalt: approval %s is %s", id, visibleText(status))
}

func submitApproval(c *cliIO, l *agentLedger, code string) int {
	resp, err := approval.ParseResponse(code)
	if err != nil {
		return c.fail(fmt.Errorf("%w: %w", errUsage, err))
	}
	if err := checkLocally(c, l, resp); err != nil {
		return c.fail(err)
	}
	if _, err := l.SubmitApproval(c.ctx, resp.ApprovalID, resp.Assertion()); err != nil {
		return c.fail(fmt.Errorf("the database refused the approval: %s", pgDetail(err)))
	}
	return approvalSigned(c, resp.ApprovalID)
}

// approvalSigned says a held write is signed and what the agent does next.
func approvalSigned(c *cliIO, id uuid.UUID) int {
	fmt.Fprintf(c.stderr, "basalt: approval %s signed; the agent applies it by repeating the write with approvalId %s\n", id, id)
	return exitOK
}

// checkLocally verifies the code with the Go mirror of the Postgres check
// when this agent can see the approval, for a clear message before
// submitting. Postgres checks again either way.
func checkLocally(c *cliIO, l *agentLedger, resp approval.Response) error {
	a, err := l.FindApproval(c.ctx, resp.ApprovalID)
	if errors.Is(err, ledger.ErrApprovalNotFound) {
		return nil // another agent's approval: only Postgres can check it
	}
	return verifyCode(c, l, err, resp.CredentialID, "submitted", func(k passkey.Credential) error {
		_, err := approval.Verify(a.BindingText, k, resp)
		return err
	})
}

// verifyCode runs verify with the registered passkey that signed a relayed
// code (the Go mirror of the Postgres check, for a clear message before
// relaying), or fails when the database does not know that passkey. found
// is the error of looking up what the code signs.
func verifyCode(c *cliIO, l *agentLedger, found error, credentialID []byte, notDone string, verify func(passkey.Credential) error) error {
	if found != nil {
		return found
	}
	keys, err := l.credentials(c.ctx)
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
