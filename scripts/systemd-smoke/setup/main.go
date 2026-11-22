// Command setup does the person's part of the local setup page for the
// systemd smoke test: it reads the link basalt init printed and the admin
// connection string on stdin, posts the check, creates a passkey for the
// challenge with a software authenticator, and posts the run. It prints the
// agent the engine set up.
package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/localsetup"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
	"github.com/basaltdbhq/basaltdb/internal/passkey/passkeytest"
)

const callTimeout = 70 * time.Second

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "setup:", err)
		os.Exit(1)
	}
}

func run(args []string, stdin io.Reader, stdout io.Writer) error {
	if len(args) != 1 {
		return errors.New("usage: setup <link> (the admin connection string on stdin)")
	}
	link, err := url.Parse(args[0])
	if err != nil {
		return err
	}
	origin := link.Scheme + "://" + link.Host
	job, err := parseJob(link.Fragment)
	if err != nil {
		return err
	}
	admin, err := bufio.NewReader(stdin).ReadString('\n')
	if err != nil && admin == "" {
		return errors.New("no admin connection string on stdin")
	}
	req := localsetup.Request{Job: job.Job, Agent: job.Agent, OSUser: job.OSUser, Demo: job.Demo, DatabaseURL: strings.TrimSpace(admin)}

	var checked localsetup.CheckAnswer
	if err := post(origin, localsetup.SetupCheckPath, req, &checked); err != nil {
		return fmt.Errorf("check: %w", err)
	}
	if checked.PasskeyNeeded {
		reg, err := register(origin, checked.Challenge)
		if err != nil {
			return err
		}
		req.Challenge, req.Passkey = &checked.Challenge, &localsetup.Passkey{RegistrationResponse: reg, Label: "smoke"}
	}
	var done localsetup.RunAnswer
	if err := post(origin, localsetup.SetupRunPath, req, &done); err != nil {
		return fmt.Errorf("run: %w", err)
	}
	_, err = fmt.Fprintln(stdout, done.Agent)
	return err
}

func parseJob(fragment string) (localsetup.Job, error) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(fragment, "1."))
	if err != nil {
		return localsetup.Job{}, fmt.Errorf("the link's fragment: %w", err)
	}
	var j localsetup.Job
	if err := json.Unmarshal(raw, &j); err != nil {
		return localsetup.Job{}, err
	}
	return j, nil
}

func register(origin string, c localsetup.Challenge) (passkey.RegistrationResponse, error) {
	rp, err := passkey.Local(origin)
	if err != nil {
		return passkey.RegistrationResponse{}, err
	}
	auth, err := passkeytest.New(rp)
	if err != nil {
		return passkey.RegistrationResponse{}, err
	}
	rr, err := passkey.RegistrationRequestFor(c.Challenge, c.UserID, c.UserName, c.DisplayName)
	if err != nil {
		return passkey.RegistrationResponse{}, err
	}
	return auth.Register(rr, nil)
}

// post sends body as the page does, with the page's Origin, and decodes
// the answer into out; a refusal is its code and message.
func post(origin, path string, body, out any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, origin+path, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Origin", origin)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: callTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	answer, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%d %s", resp.StatusCode, answer)
	}
	return json.Unmarshal(answer, out)
}
