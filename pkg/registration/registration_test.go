package registration

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRegisterSendsVersionInRequest(t *testing.T) {
	expectedVersion := "2.4.1"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/agents" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}

		var req RegisterRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("failed to decode register request: %v", err)
		}

		if req.Version != expectedVersion {
			t.Fatalf("expected version %s, got %s", expectedVersion, req.Version)
		}

		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(RegisterResponse{
			AgentID: "agent-1",
			Token:   "token-1",
			Status:  "ok",
		})
	}))
	defer server.Close()

	resp, err := Register(server.URL, "agent-1", "db-host", expectedVersion, true)
	if err != nil {
		t.Fatalf("register failed: %v", err)
	}

	if resp.Token != "token-1" {
		t.Fatalf("expected token token-1, got %s", resp.Token)
	}
	if resp.AgentID != "agent-1" {
		t.Fatalf("expected agent_id agent-1, got %s", resp.AgentID)
	}
}

func TestRegisterRejectsPlainHTTPPrefix(t *testing.T) {
	_, err := Register("http://example.com", "agent-1", "db-host", "1.0.0", false)
	if err == nil {
		t.Fatalf("expected plain HTTP registration URL to be rejected")
	}
}

func TestRegisterHandlesShortHTTPStringWithoutPanic(t *testing.T) {
	_, err := Register("http", "agent-1", "db-host", "1.0.0", false)
	if err == nil {
		t.Fatalf("expected invalid registration URL to fail")
	}
}
