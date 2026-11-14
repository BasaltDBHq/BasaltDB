// Package pagetest is a portal page written in Go for hermetic tests: it
// opens a link session through a Vault (CONTRACT.md, Vault channel, The
// page's socket), runs the handshake as the initiator and speaks the pages
// API in frames, as the portal's WebCrypto page does.
package pagetest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/coder/websocket"

	"github.com/basaltdbhq/basaltdb/internal/channel"
	"github.com/basaltdbhq/basaltdb/internal/links"
)

// readLimit is above every session message, so the page sees what the
// engine sends and checks the size itself.
const readLimit = 1 << 20

// Page is one page socket and, once the handshake is done, its session.
type Page struct {
	ws      *websocket.Conn
	session *channel.Session
	// Welcome is what message 2 told the page about the engine.
	Welcome channel.Welcome
	nextID  int
	// transport is the prologue's: RELAY through a Vault, DIRECT to the
	// engine's own listener.
	transport channel.Transport
}

// Dial opens the page socket for token at a Vault's ws:// base URL, from the
// portal's origin, without sending anything.
func Dial(ctx context.Context, vaultURL string, token channel.LinkToken) (*Page, error) {
	h := http.Header{}
	h.Set("Origin", links.Portal)
	ws, resp, err := websocket.Dial(ctx, vaultURL+"/v1/links/"+token.Wire(), &websocket.DialOptions{HTTPHeader: h})
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if err != nil {
		return nil, err
	}
	ws.SetReadLimit(readLimit)
	return &Page{ws: ws, transport: channel.TransportRelay}, nil
}

// DialDirect opens a page socket to an engine's direct session route
// (ws://host/v1/session) from the portal's origin, without sending
// anything. Its handshake uses transport DIRECT.
func DialDirect(ctx context.Context, sessionURL string, header http.Header) (*Page, error) {
	h := http.Header{}
	h.Set("Origin", links.Portal)
	for k, v := range header {
		h[k] = v
	}
	ws, resp, err := websocket.Dial(ctx, sessionURL, &websocket.DialOptions{HTTPHeader: h, Host: h.Get("Host")})
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if err != nil {
		return nil, err
	}
	ws.SetReadLimit(readLimit)
	return &Page{ws: ws, transport: channel.TransportDirect}, nil
}

// Open dials and runs the handshake for a link's keys.
func Open(ctx context.Context, vaultURL string, keys channel.LinkKeys) (*Page, error) {
	p, err := Dial(ctx, vaultURL, keys.Token)
	if err != nil {
		return nil, err
	}
	if err := p.Handshake(ctx, keys); err != nil {
		p.Close()
		return nil, err
	}
	return p, nil
}

// Handshake sends message 1 for keys and reads message 2.
func (p *Page) Handshake(ctx context.Context, keys channel.LinkKeys) error {
	ini, msg1, err := channel.WriteHello(p.transport, keys)
	if err != nil {
		return err
	}
	if err := p.SendRaw(ctx, msg1); err != nil {
		return err
	}
	msg2, err := p.ReadRaw(ctx)
	if err != nil {
		return err
	}
	s, w, err := ini.ReadWelcome(msg2)
	if err != nil {
		return err
	}
	p.session, p.Welcome = s, w
	return nil
}

// SendRaw sends one binary message as it is.
func (p *Page) SendRaw(ctx context.Context, msg []byte) error {
	return p.ws.Write(ctx, websocket.MessageBinary, msg)
}

// ReadRaw reads one binary message.
func (p *Page) ReadRaw(ctx context.Context) ([]byte, error) {
	typ, data, err := p.ws.Read(ctx)
	if err != nil {
		return nil, err
	}
	if typ != websocket.MessageBinary {
		return nil, errors.New("pagetest: a text message from the Vault")
	}
	return data, nil
}

// Send seals content as the page's next frame and sends it.
func (p *Page) Send(ctx context.Context, content []byte) error {
	frame, err := p.session.Seal(content)
	if err != nil {
		return err
	}
	return p.SendRaw(ctx, frame)
}

// SendJSON sends v as one frame's content.
func (p *Page) SendJSON(ctx context.Context, v any) error {
	content, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return p.Send(ctx, content)
}

// Seal makes the page's next frame without sending it.
func (p *Page) Seal(content []byte) ([]byte, error) { return p.session.Seal(content) }

// Receive reads and opens the engine's next frame.
func (p *Page) Receive(ctx context.Context) ([]byte, error) {
	frame, err := p.ReadRaw(ctx)
	if err != nil {
		return nil, err
	}
	return p.session.Open(frame)
}

// Request is a REQUEST frame's content.
type Request struct {
	Type    string            `json:"type"`
	ID      int               `json:"id"`
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
	More    bool              `json:"more"`
}

// Continue is a CONTINUE frame's content.
type Continue struct {
	Type string `json:"type"`
	ID   int    `json:"id"`
	Body string `json:"body"`
	More bool   `json:"more"`
}

// frameOut is a frame from the engine: a RESPONSE or a CONTINUE.
type frameOut struct {
	Type    string            `json:"type"`
	ID      int               `json:"id"`
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
	More    bool              `json:"more"`
}

// Reply is a whole response.
type Reply struct {
	Status      int
	ContentType string
	Body        string
	// Frames is how many frames it took.
	Frames int
}

// Headers are a request's headers from the portal with secret.
func Headers(secret string) map[string]string {
	return map[string]string{links.SecretHeader: secret, "origin": links.Portal}
}

// PostHeaders are Headers with content-type application/json.
func PostHeaders(secret string) map[string]string {
	h := Headers(secret)
	h["content-type"] = "application/json"
	return h
}

// NextID is the id the page's next request takes.
func (p *Page) NextID() int { return p.nextID + 1 }

// Do sends one request, its body in pieces of at most chunk bytes (the
// whole body in the REQUEST when chunk is 0), and reads the whole response.
func (p *Page) Do(ctx context.Context, method, path string, headers map[string]string, body string, chunk int) (Reply, error) {
	p.nextID++
	id := p.nextID
	first, rest := body, ""
	if chunk > 0 && len(body) > chunk {
		first, rest = body[:chunk], body[chunk:]
	}
	if err := p.SendJSON(ctx, Request{Type: "REQUEST", ID: id, Method: method, Path: path, Headers: headers, Body: first, More: rest != ""}); err != nil {
		return Reply{}, err
	}
	for rest != "" {
		piece := rest[:min(chunk, len(rest))]
		rest = rest[len(piece):]
		if err := p.SendJSON(ctx, Continue{Type: "CONTINUE", ID: id, Body: piece, More: rest != ""}); err != nil {
			return Reply{}, err
		}
	}
	return p.Reply(ctx, id)
}

// Reply reads the response to request id: a RESPONSE, then CONTINUEs until
// the one with more false.
func (p *Page) Reply(ctx context.Context, id int) (Reply, error) {
	var out Reply
	for {
		content, err := p.Receive(ctx)
		if err != nil {
			return out, err
		}
		var f frameOut
		if err := json.Unmarshal(content, &f); err != nil {
			return out, err
		}
		want := "CONTINUE"
		if out.Frames == 0 {
			want = "RESPONSE"
			out.Status, out.ContentType = f.Status, f.Headers["content-type"]
		}
		if f.Type != want || f.ID != id {
			return out, fmt.Errorf("pagetest: got %s %d, want %s %d", f.Type, f.ID, want, id)
		}
		out.Frames++
		out.Body += f.Body
		if !f.More {
			return out, nil
		}
	}
}

// Closed reads until the socket ends and returns its close code.
func (p *Page) Closed(ctx context.Context) websocket.StatusCode {
	for {
		if _, _, err := p.ws.Read(ctx); err != nil {
			return websocket.CloseStatus(err)
		}
	}
}

// Close ends the page normally.
func (p *Page) Close() {
	_ = p.ws.Close(websocket.StatusNormalClosure, "")
}
