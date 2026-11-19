package main

import (
	"bytes"
	"encoding/json"
	"os"
	"sync"

	tn "github.com/basaltdbhq/basaltdb/internal/plugin/testnotifier"
)

// recordMode keeps the record readable by its owner only.
const recordMode = 0o600

// recorder appends one JSON line per hook call. Each line is one write to a
// file opened for appending, so a test reading it sees whole lines.
type recorder struct {
	path string
	mu   sync.Mutex
}

func (r *recorder) write(rec tn.Record) {
	if r.path == "" {
		return
	}
	// No HTML escaping: the recorded events are the bytes that arrived.
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if enc.Encode(rec) != nil {
		return
	}
	b := bytes.TrimSuffix(buf.Bytes(), []byte{'\n'})
	r.mu.Lock()
	defer r.mu.Unlock()
	f, err := os.OpenFile(r.path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, recordMode)
	if err != nil {
		return
	}
	_, _ = f.Write(append(b, '\n'))
	_ = f.Close()
}
