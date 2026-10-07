//go:build integration

package processors

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.acuvity.ai/a3s/internal/mongofixture"
	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/a3s/pkgs/authorizer"
	"go.acuvity.ai/a3s/pkgs/namespacelifecycle"
	"go.acuvity.ai/a3s/pkgs/permissions"
	"go.acuvity.ai/bahamut"
	"go.acuvity.ai/elemental"
	"go.acuvity.ai/manipulate"
)

func TestNamespaceParticipationOwnedMongoHTTP(t *testing.T) {
	ctx := context.Background()
	m := mongofixture.New(t)
	store, err := namespacelifecycle.NewStore(m)
	if err != nil {
		t.Fatal(err)
	}
	fixture := participationState(t)
	binding := *fixture.Creation
	binding.Origin, binding.Phase, binding.ApplicationDigest = "", "", ""
	binding.Acquisitions, binding.Enrollments = nil, nil
	state, err := store.ReserveCreation(ctx, fixture.Namespace, fixture.Ancestors, binding)
	if err != nil {
		t.Fatal(err)
	}
	step := func(next namespacelifecycle.State, won bool, err error) {
		t.Helper()
		if err != nil || !won {
			t.Fatalf("prepare owner: won=%v err=%v", won, err)
		}
		state = next
	}
	step(store.ClaimCreation(ctx, state))
	step(store.AttemptCreationAcquisition(ctx, state, 0))
	step(store.ConfirmCreationAcquisition(ctx, state, 0))
	step(store.AttemptNativeCreation(ctx, state))
	digest, err := namespacelifecycle.CreationMarkerDigest(state)
	if err != nil {
		t.Fatal(err)
	}
	step(store.ConfirmCreationApplied(ctx, state, digest))
	step(store.AttemptCreationEnrollment(ctx, state, "hanni"))

	// Real native namespace lookup and policy retrieval, not a claims-only grant.
	ns := api.NewNamespace()
	ns.ID, ns.Name, ns.Namespace = state.Namespace.ID, "/target", "/"
	if err := m.Create(manipulate.NewContext(ctx, manipulate.ContextOptionNamespace("/")), ns); err != nil {
		t.Fatal(err)
	}
	f := participationAuth(t)
	f.policy.Namespace = "/target"
	f.policy.FlattenedSubject = []string{"role=enroller"}
	f.policy.TrustedIssuers = []string{"test-issuer"}
	if err := m.Create(manipulate.NewContext(ctx, manipulate.ContextOptionNamespace("/target")), f.policy); err != nil {
		t.Fatal(err)
	}
	retriever := permissions.NewRetriever(m)
	f.auth.retriever = retriever
	processor, err := NewNamespaceParticipationProcessor(store, f.auth)
	if err != nil {
		t.Fatal(err)
	}
	nativeAuthorizer := authorizer.New(ctx, retriever, nil)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, h *http.Request) {
		h.Body = http.MaxBytesReader(w, h.Body, namespaceParticipationMaxBytes)
		r, err := elemental.NewRequestFromHTTPRequest(h, api.Manager())
		if err != nil {
			http.Error(w, "invalid", http.StatusUnprocessableEntity)
			return
		}
		b := bahamut.NewContext(h.Context(), r)
		if action, err := f.auth.authenticator.AuthenticateRequest(b); err != nil || action == bahamut.AuthActionKO {
			http.Error(w, "denied", http.StatusForbidden)
			return
		}
		if action, err := nativeAuthorizer.IsAuthorized(b); err != nil || action != bahamut.AuthActionOK {
			http.Error(w, "denied", http.StatusForbidden)
			return
		}
		input := api.NewNamespaceParticipation()
		if err := json.Unmarshal(r.Data, input); err != nil {
			http.Error(w, "invalid", http.StatusUnprocessableEntity)
			return
		}
		b.SetInputData(input)
		if err := processor.ProcessCreate(b); err != nil {
			http.Error(w, "held", http.StatusConflict)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(b.OutputData()); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	bearer := f.bearer(t, nil)
	call := func(action, credential string) (namespaceParticipationResult, int) {
		t.Helper()
		command := participationContext(t, credential, action).Request().Data
		r, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+"/namespaceparticipations", bytes.NewReader(command))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Namespace", "/target")
		if credential != "" {
			r.Header.Set("Authorization", "Bearer "+credential)
		}
		response, err := server.Client().Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close() //nolint:errcheck
		data, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		var out namespaceParticipationResult
		if response.StatusCode == 200 {
			if err := json.Unmarshal(data, &out); err != nil {
				t.Fatal(err)
			}
		}
		return out, response.StatusCode
	}
	if _, status := call("ClaimEnrollment", ""); status == 200 {
		t.Fatal("missing token granted")
	}
	retained, err := store.Get(ctx, state.Namespace.ID)
	if err != nil || retained.Revision != state.Revision {
		t.Fatal("denial changed owner", err)
	}
	if out, status := call("Inspect", bearer); status != 200 || out.Granted || out.Snapshot.Phase != "attempted" {
		t.Fatalf("inspect: %d %+v", status, out)
	}
	if out, status := call("ClaimEnrollment", bearer); status != 200 || !out.Granted || out.Snapshot.Phase != "claimed" {
		t.Fatalf("claim: %d %+v", status, out)
	}
	if out, status := call("ClaimEnrollment", bearer); status != 200 || out.Granted || out.Snapshot.Phase != "claimed" {
		t.Fatalf("replay: %d %+v", status, out)
	}
	retained, err = store.Get(ctx, state.Namespace.ID)
	if err != nil || retained.Revision != state.Revision+1 {
		t.Fatal("replay mutated owner", err)
	}
}
