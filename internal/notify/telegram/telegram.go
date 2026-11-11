// Package telegram sends BasaltDB notifications through a Telegram bot: the
// approval link for a held write (M2) and, later, the dead-man alert (D14).
// Telegram only delivers the notification; the approval itself needs the
// person's passkey and is checked in Postgres.
//
// The bot token is a secret. It is read from a file only the engine's user
// can read, never logged, never put in an error, and printed as [redacted].
package telegram

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"strings"
	"time"
)

// DefaultAPIBase is the Bot API endpoint.
const DefaultAPIBase = "https://api.telegram.org"

const (
	// tokenFilePermMask: the token file must give group and others nothing,
	// like the agent credential file.
	tokenFilePermMask = 0o077
	// maxTokenFileBytes bounds the token file read.
	maxTokenFileBytes = 1 << 10
	// maxResponseBytes bounds a Bot API response body.
	maxResponseBytes = 1 << 20
)

// tokenPattern is the Bot API token shape: <bot id>:<secret>.
var tokenPattern = regexp.MustCompile(`^[0-9]+:[A-Za-z0-9_-]+$`)

const redacted = "[redacted]"

// Token is a bot token. Every way of printing it prints [redacted].
type Token struct {
	value string
}

// String implements fmt.Stringer.
func (Token) String() string { return redacted }

// GoString implements fmt.GoStringer, for %#v.
func (Token) GoString() string { return redacted }

// MarshalJSON keeps the token out of JSON logs and config dumps.
func (Token) MarshalJSON() ([]byte, error) { return json.Marshal(redacted) }

// ParseToken checks a token's shape. The error never contains the input.
func ParseToken(s string) (Token, error) {
	s = strings.TrimSpace(s)
	if !tokenPattern.MatchString(s) {
		return Token{}, errors.New("telegram bot token is not in the <bot id>:<secret> form")
	}
	return Token{value: s}, nil
}

// LoadToken reads a bot token from path, which must be readable by its owner
// only. Errors name the file, never its content.
func LoadToken(path string) (Token, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return Token{}, fmt.Errorf("telegram bot token file: %w", err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm()&tokenFilePermMask != 0 {
		return Token{}, fmt.Errorf("telegram bot token file %s is mode %o; it must be readable by the engine's user only (0600)", path, fi.Mode().Perm())
	}
	f, err := os.Open(path)
	if err != nil {
		return Token{}, fmt.Errorf("telegram bot token file: %w", err)
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxTokenFileBytes))
	if err != nil {
		return Token{}, fmt.Errorf("read telegram bot token file %s: %w", path, err)
	}
	tok, err := ParseToken(string(raw))
	if err != nil {
		return Token{}, fmt.Errorf("%s: %w", path, err)
	}
	return tok, nil
}

// Button is an inline keyboard button that opens a URL.
type Button struct {
	Text string
	URL  string
}

// Message is one chat message, plain text (no parse mode, so nothing in it
// needs escaping), with an optional button.
type Message struct {
	Text   string
	Button *Button
}

// APIError is a Bot API refusal ("ok": false).
type APIError struct {
	Status      int
	Code        int
	Description string
	// RetryAfter is set when Telegram rate-limits the bot (HTTP 429).
	RetryAfter time.Duration
}

func (e *APIError) Error() string {
	msg := fmt.Sprintf("telegram sendMessage: %d %s", e.Code, e.Description)
	if e.RetryAfter > 0 {
		msg += fmt.Sprintf(" (retry after %s)", e.RetryAfter)
	}
	return msg
}

// Client calls the Bot API's sendMessage for one chat.
type Client struct {
	http   *http.Client
	base   string
	token  Token
	chatID string
}

// NewClient returns a client for chatID. base is DefaultAPIBase outside
// tests. It panics on a nil HTTP client or an empty chat id: both are
// required.
func NewClient(httpClient *http.Client, base string, token Token, chatID string) *Client {
	if httpClient == nil {
		panic("telegram.NewClient: nil http.Client")
	}
	if strings.TrimSpace(chatID) == "" {
		panic("telegram.NewClient: empty chat id")
	}
	return &Client{http: httpClient, base: strings.TrimRight(base, "/"), token: token, chatID: chatID}
}

type inlineButton struct {
	Text string `json:"text"`
	URL  string `json:"url"`
}

type replyMarkup struct {
	InlineKeyboard [][]inlineButton `json:"inline_keyboard"`
}

type linkPreviewOptions struct {
	IsDisabled bool `json:"is_disabled"`
}

// sendMessageRequest is the Bot API's body; its snake_case keys are
// Telegram's, not ours.
type sendMessageRequest struct {
	ChatID             string             `json:"chat_id"`
	Text               string             `json:"text"`
	LinkPreviewOptions linkPreviewOptions `json:"link_preview_options"`
	ReplyMarkup        *replyMarkup       `json:"reply_markup,omitempty"`
}

type apiResponse struct {
	OK          bool   `json:"ok"`
	ErrorCode   int    `json:"error_code"`
	Description string `json:"description"`
	Parameters  struct {
		RetryAfter int `json:"retry_after"`
	} `json:"parameters"`
}

// SendMessage sends m to the client's chat.
func (c *Client) SendMessage(ctx context.Context, m Message) error {
	body := sendMessageRequest{ChatID: c.chatID, Text: m.Text, LinkPreviewOptions: linkPreviewOptions{IsDisabled: true}}
	if m.Button != nil {
		body.ReplyMarkup = &replyMarkup{InlineKeyboard: [][]inlineButton{{{Text: m.Button.Text, URL: m.Button.URL}}}}
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("telegram sendMessage: encode: %w", err)
	}
	// The token is part of the URL path (Bot API design), so no error built
	// from this request may carry the URL.
	endpoint := c.base + "/bot" + c.token.value + "/sendMessage"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil {
		return errors.New("telegram sendMessage: cannot build the request")
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("telegram sendMessage: %w", stripURL(err))
	}
	defer resp.Body.Close()
	var out apiResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&out); err != nil {
		return fmt.Errorf("telegram sendMessage: HTTP %d with an unreadable body", resp.StatusCode)
	}
	if out.OK {
		return nil
	}
	return &APIError{
		Status:      resp.StatusCode,
		Code:        out.ErrorCode,
		Description: out.Description,
		RetryAfter:  time.Duration(out.Parameters.RetryAfter) * time.Second,
	}
}

// stripURL drops the request URL (which holds the token) from a transport
// error and keeps its cause.
func stripURL(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return fmt.Errorf("%s: %w", ue.Op, ue.Err)
	}
	return err
}
