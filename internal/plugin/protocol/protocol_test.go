package protocol

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

const testdata = "../../../api/plugin/testdata"

func load(t *testing.T, name string, v any) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(testdata, name))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
}

func TestContractExamplesDecode(t *testing.T) {
	var req InitializeRequest
	load(t, "valid-initialize-request.json", &req)
	if len(req.Protocols) == 0 || len(req.Hooks) == 0 || req.Limits.MaxInFlight != MaxInFlight || req.Limits.MaxMessageBytes != MaxMessageBytes {
		t.Fatalf("request = %+v", req)
	}
	var resp InitializeResponse
	load(t, "valid-initialize-response.json", &resp)
	if resp.Protocol != Version1 || resp.Name == "" || len(resp.Hooks) == 0 {
		t.Fatalf("response = %+v", resp)
	}
	var h HealthResponse
	load(t, "valid-health-response.json", &h)
	if h.Status != HealthReady {
		t.Fatalf("health = %+v", h)
	}
}

func TestEmptyConfigEncodesAsObject(t *testing.T) {
	b, err := json.Marshal(InitializeRequest{})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if string(m["config"]) != "{}" {
		t.Fatalf("config = %s", m["config"])
	}
}
