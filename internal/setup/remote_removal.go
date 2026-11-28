package setup

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
)

// basalt init --remove on an agent-operated engine (CONTRACT.md, CLI,
// --remove; Connect, The removal hand-off): the person asked the bot to
// remove BasaltDB and has no terminal. Init makes a removal link: an AGENT
// code with no change (no verifier, no tables) for the database the agent's
// credential names, carrying the engine's key, recorded in engine.json as
// the agent's pending removal. The person opens the link, pastes the
// admin connection string and presses Remove; the engine then removes
// itself from this machine. Nothing logs in here: the link only names the
// database, and the connect page checks that the pasted string is that
// one.

// ErrNothingToRemove is basalt init --remove where the agent has no
// credential on this machine: BasaltDB is not set up for it here.
var ErrNothingToRemove = errors.New("BasaltDB is not set up for this agent on this computer, so there is nothing to remove")

// RemovalPrefix starts the connect link's fragment of a removal link:
// https://portal.basaltvault.app/connect#remove=<code>.
const RemovalPrefix = "remove="

// RemovalLink is the connect page's removal link for code, or "" when it
// does not fit budget.
func RemovalLink(code string, budget int) string {
	url := links.Portal + links.ConnectPath + "#" + RemovalPrefix + code
	if budget <= 0 || len(url) > budget {
		return ""
	}
	return url
}

// InitRemoteRemoval runs basalt init --remove on an agent-operated engine
// and returns what it prints: the removal link and the code's fingerprint.
// An unexpired pending removal is handed out again (Reused).
func InitRemoteRemoval(ctx context.Context, env RemoteEnv, h RemoteHost, f RemoteFlags) (RemoteInitResult, error) {
	r := &remoteInit{ctx: ctx, env: env, host: h, f: f}
	if err := r.paths(); err != nil {
		return RemoteInitResult{}, err
	}
	unlock, err := r.files.Lock(r.credFile + config.LockSuffix)
	if err != nil {
		r.files.Close()
		return RemoteInitResult{}, err
	}
	defer func() {
		unlock()
		r.files.Close()
		if r.configDir != nil {
			r.configDir.Close()
		}
	}()
	return r.runRemoval()
}

func (r *remoteInit) runRemoval() (RemoteInitResult, error) {
	if !r.existed || r.entry == nil {
		return RemoteInitResult{}, ErrNothingToRemove
	}
	if err := ConnectOnlyAllowed(r.settings, r.prev, r.existed); err != nil {
		return RemoteInitResult{}, err
	}
	cred, err := ReadCredentialIfAny(r.files, r.credFile)
	if err != nil {
		return RemoteInitResult{}, err
	}
	if cred == nil {
		return RemoteInitResult{}, ErrNothingToRemove
	}
	r.base, r.target = cred.URL, cred.Target
	if prefix := CredentialPrefix(r.base, r.f.Agent, r.target.SupabaseRef); prefix != "" && prefix != r.f.Prefix {
		if err := r.setPrefix(prefix); err != nil {
			return RemoteInitResult{}, err
		}
	}
	now := r.env.Now()
	if rm := r.entry.Removal; rm != nil {
		if exp, err := rm.Expires(); err == nil && now.Before(exp) {
			if err := r.writeRemoval(*rm); err != nil {
				return RemoteInitResult{}, err
			}
			return r.removalResult(*rm, true), nil
		}
	}
	latest := r.host.GuardLatestVersion()
	run := RemoteRun{Agent: r.f.Agent, Prefix: r.f.Prefix, Timeout: r.f.Timeout, Target: r.target, Latest: latest}
	p, err := run.Payload(Plan{Kind: setupcode.KindAgent, From: latest}, now, r.env.Rand(), r.engineKey, r.pinnedSHA)
	if err != nil {
		return RemoteInitResult{}, err
	}
	if p.Engine == nil {
		return RemoteInitResult{}, errors.New("a removal link needs the engine's key, and basalt cannot read or make it as this user: run basalt init --remove as the engine's OS user")
	}
	code, err := encodeSetup(p)
	if err != nil {
		return RemoteInitResult{}, err
	}
	rm := config.Removal{SetupID: p.SetupID, ExpiresAt: p.ExpiresAt, Code: code, Fingerprint: p.Fingerprint()}
	if err := r.writeRemoval(rm); err != nil {
		return RemoteInitResult{}, err
	}
	return r.removalResult(rm, false), nil
}

// writeRemoval records rm as the agent's pending removal in engine.json,
// keeping its pending setup.
func (r *remoteInit) writeRemoval(rm config.Removal) error {
	a := config.Agent{Name: r.f.Agent, OSUser: r.osUser, Store: config.PostgresStore(r.credFile), Setup: r.entry.Setup, Removal: &rm}
	var err error
	if r.configDir != nil {
		_, err = r.configDir.Upsert(filepath.Base(r.f.ConfigPath), r.settings, a)
	} else {
		_, err = r.host.UpsertAgentVault(r.f.ConfigPath, r.settings, a)
	}
	if err != nil {
		return err
	}
	r.connectBudget = r.linkBudget
	if r.connectBudget <= 0 {
		r.connectBudget = links.DefaultBudget
	}
	return nil
}

// removalResult is what init prints for rm: the removal link, or the
// code to paste on the connect page's Remove tab when the link is over
// the budget.
func (r *remoteInit) removalResult(rm config.Removal, reused bool) RemoteInitResult {
	res := RemoteInitResult{
		Agent: r.f.Agent, SetupID: rm.SetupID, Kind: string(setupcode.KindAgent), Code: rm.Code, Fingerprint: rm.Fingerprint,
		Reused: reused, ExpiresAt: rm.ExpiresAt, Removal: true, OSUser: r.osUser,
	}
	lead := "Remove BasaltDB from the database " + r.target.Database + " on " + r.target.Host + " and from " + r.f.Agent + "'s computer."
	if url := RemovalLink(rm.Code, r.connectBudget); url != "" {
		res.ConnectURL = url
		res.PersonMessage, _ = RemovalMessage(lead, url)
		return res
	}
	res.PasteAtPortal = true
	res.PersonMessage = fmt.Sprintf("%s The removal link is too long for this chat (its code expires at %s), so the page can remove BasaltDB from the database only: open %s, choose Remove BasaltDB, and paste the admin connection string there, never into this chat.",
		lead, expiresText(rm.ExpiresAt), links.Portal+links.ConnectPath)
	return res
}

// LabelRemove is the removal link's label in links.
const LabelRemove = "Remove BasaltDB"

// RemovalMessage is the personMessage that hands the person the removal
// link: one page, one box, one press, and the admin string stays there.
func RemovalMessage(lead, url string) (string, []toolresult.Link) {
	return guidance.NewMessage().
		Text(lead+" Open this link, paste your database's admin connection string there and press Remove. The link uses BasaltVault, a hosted service:").
		Link(LabelRemove, url).
		Text("The page shows when BasaltDB is gone from the database and from this computer. Never paste your database password into this chat.").
		Build()
}

// expiresText is an RFC 3339 time as the person reads it.
func expiresText(at string) string {
	t, err := time.Parse(time.RFC3339, at)
	if err != nil {
		return at
	}
	return t.UTC().Format(guidance.PersonTime)
}
