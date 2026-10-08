package namespacelifecycle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func participantHTTPState(t *testing.T) State {
	t.Helper()
	s := State{Version: "namespace-lifecycle.v2", Namespace: Namespace{ID: strings.Repeat("1", 24), Name: "/target"}, Ancestors: []Namespace{{ID: strings.Repeat("2", 24), Name: "/"}}, Revision: 8, Phase: "forming", Pins: []Pin{}, Drains: []DrainProof{}, Creation: &Creation{Origin: "create", OperationID: "owner-operation", Digest: strings.Repeat("a", 64), CreatedAt: "2026-01-01T00:00:00Z", Participants: []string{"hanni"}, Phase: "applied", Acquisitions: []string{"held"}, Enrollments: []CreationEnrollment{{Participant: "hanni", Phase: "attempted", RegistryID: strings.Repeat("1", 24)}}}}
	var err error
	s.Creation.ApplicationDigest, err = CreationMarkerDigest(s)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func participantHTTPProof(t *testing.T, state State) []byte {
	t.Helper()
	// Independent literal wire golden: order and compact ordinary Go JSON are
	// contract, not map order, source digest or a granted boolean.
	wire := fmt.Sprintf(`{"schemaVersion":"participant-enrollment.v1","registryID":"111111111111111111111111","enrollment":{"operationID":"owner-operation","digest":"%s","scope":{"namespace":{"id":"111111111111111111111111","name":"/target"},"ancestors":[{"id":"222222222222222222222222","name":"/"}]}}}`, state.Creation.ApplicationDigest)
	digest := sha256.Sum256([]byte(wire))
	data, err := json.Marshal(struct {
		Proof EnrollmentProof `json:"proof"`
	}{EnrollmentProof{"hanni", state.Namespace.ID, "owner-operation", state.Namespace.ID, hex.EncodeToString(digest[:])}})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestHTTPParticipantsWireObserveAndEnroll(t *testing.T) {
	state := participantHTTPState(t)
	proof := participantHTTPProof(t, state)
	var actions []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/findingpublicationnamespaces" || r.URL.RawQuery != "" || r.Header.Get("X-Namespace") != "/target" || r.Header.Get("Authorization") != "Bearer owned-token" {
			t.Error("request binding")
		}
		data, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		var command map[string]string
		if err := json.Unmarshal(data, &command); err != nil {
			t.Error(err)
		}
		if len(command) != 5 || command["namespaceID"] != state.Namespace.ID || command["registryID"] != state.Namespace.ID || command["participant"] != "hanni" || command["operationID"] != "owner-operation" {
			t.Errorf("command: %s", data)
		}
		actions = append(actions, command["action"])
		_, _ = w.Write(proof)
	}))
	defer server.Close()
	tokens := 0
	p, err := NewHTTPParticipants(server.URL, server.Client(), func(ctx context.Context) (string, error) {
		tokens++
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 10*time.Second {
			t.Error("missing whole-attempt deadline")
		}
		return "owned-token", nil
	}, "hanni")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Enroll(context.Background(), state, "hanni"); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Observe(context.Background(), state, "hanni"); err != nil {
		t.Fatal(err)
	}
	if strings.Join(actions, ",") != "Enroll,Inspect" || tokens != 2 {
		t.Fatalf("actions=%v tokens=%d", actions, tokens)
	}
}

func TestHTTPParticipantsRejectProofAndNeverRetryOrCreateOnMiss(t *testing.T) {
	for _, name := range []string{"missing", "redirect", "boolean", "wrong-digest", "wrong-source", "duplicate", "case", "trailing", "null", "oversize"} {
		t.Run(name, func(t *testing.T) {
			state := participantHTTPState(t)
			data := string(participantHTTPProof(t, state))
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				body, _ := io.ReadAll(r.Body)
				if !strings.Contains(string(body), `"action":"Inspect"`) {
					t.Error("Observe attempted creation")
				}
				switch name {
				case "missing":
					w.WriteHeader(404)
					return
				case "redirect":
					w.Header().Set("Location", "/redirected")
					w.WriteHeader(307)
					return
				case "boolean":
					data = `{"granted":true}`
				case "wrong-digest":
					data = strings.ReplaceAll(data, `"digest":"`, `"digest":"a`)
				case "wrong-source":
					data = strings.ReplaceAll(data, "owner-operation", "other-operation")
				case "duplicate":
					data = strings.Replace(data, `"participant":`, `"participant":"hanni","participant":`, 1)
				case "case":
					data = strings.ReplaceAll(data, "namespaceID", "NamespaceID")
				case "trailing":
					data += `{}`
				case "null":
					data = `{"proof":null}`
				case "oversize":
					data += strings.Repeat(" ", participantHTTPMaxBytes)
				}
				_, _ = io.WriteString(w, data)
			}))
			defer server.Close()
			p, err := NewHTTPParticipants(server.URL, server.Client(), func(context.Context) (string, error) { return "owned-token", nil }, "hanni")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := p.Observe(context.Background(), state, "hanni"); err == nil {
				t.Fatal("accepted invalid response")
			}
			if calls != 1 {
				t.Fatalf("retried or redirected: %d", calls)
			}
		})
	}
}

func TestHTTPParticipantsFreezeAndValidateBeforeCallback(t *testing.T) {
	state := participantHTTPState(t)
	proof := participantHTTPProof(t, state)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(data), `"operationID":"owner-operation"`) {
			t.Error("source binding drifted")
		}
		_, _ = w.Write(proof)
	}))
	defer server.Close()
	calls := 0
	p, err := NewHTTPParticipants(server.URL, server.Client(), func(context.Context) (string, error) {
		calls++
		state.Creation.OperationID = "mutated"
		return "owned-token", nil
	}, "hanni")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Enroll(context.Background(), state, "hanni"); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Observe(context.Background(), state, "hanni"); err == nil || calls != 1 {
		t.Fatal("invalid source dispatched", err)
	}
	state = participantHTTPState(t)
	state.Ancestors = nil
	if _, err := p.Enroll(context.Background(), state, "hanni"); err == nil || calls != 1 {
		t.Fatal("incomplete ancestry dispatched", err)
	}
	for _, target := range []string{"https://example.test/path", "https://u:p@example.test", "https://example.test?next=x", "https://example.test#x", "http://example.test"} {
		if _, err := NewHTTPParticipants(target, server.Client(), func(context.Context) (string, error) { return "", nil }, "hanni"); err == nil {
			t.Fatalf("accepted unsafe target %s", target)
		}
	}
}
