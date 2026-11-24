package agent

import (
	"bytes"
	"encoding/json"
	"errors"
)

// jsonObject writes one JSON object member by member, in the order they are
// added: describe's answer has members the store names (feature groups,
// flags, display), and its fingerprint hashes them in a fixed order. Each
// value is encoded as encoding/json encodes it, so the bytes are the same as
// a struct with those members in that order.
type jsonObject struct {
	buf bytes.Buffer
	err error
}

var errDisplayNotObject = errors.New("describe: a store display is not a JSON object")

func (o *jsonObject) sep() {
	if o.buf.Len() == 0 {
		o.buf.WriteByte('{')
		return
	}
	o.buf.WriteByte(',')
}

// add writes key and v.
func (o *jsonObject) add(key string, v any) {
	if o.err != nil {
		return
	}
	k, err := json.Marshal(key)
	if err != nil {
		o.err = err
		return
	}
	raw, err := json.Marshal(v)
	if err != nil {
		o.err = err
		return
	}
	o.sep()
	o.buf.Write(k)
	o.buf.WriteByte(':')
	o.buf.Write(raw)
}

// splice writes the members of v, which encodes to a JSON object or null
// (nothing is written).
func (o *jsonObject) splice(v any) {
	if o.err != nil {
		return
	}
	raw, err := json.Marshal(v)
	if err != nil {
		o.err = err
		return
	}
	if string(raw) == "null" {
		return
	}
	if len(raw) < len("{}") || raw[0] != '{' {
		o.err = errDisplayNotObject
		return
	}
	inner := raw[1 : len(raw)-1]
	if len(inner) == 0 {
		return
	}
	o.sep()
	o.buf.Write(inner)
}

// close ends the object and returns it, or the first error.
func (o *jsonObject) close() ([]byte, error) {
	if o.err != nil {
		return nil, o.err
	}
	if o.buf.Len() == 0 {
		return []byte("{}"), nil
	}
	o.buf.WriteByte('}')
	return o.buf.Bytes(), nil
}
