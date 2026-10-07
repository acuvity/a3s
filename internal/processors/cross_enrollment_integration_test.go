//go:build integration

package processors

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/a3s/pkgs/namespacelifecycle"
	"go.acuvity.ai/bahamut"
	"go.acuvity.ai/manipulate"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// Only the notification sink is local; it grants no native authority.
type crossNotifications struct{ bahamut.PubSubClient }

func (crossNotifications) Publish(*bahamut.Publication, ...bahamut.PubSubOptPublish) error {
	return nil
}

// Task 3.73.12: enrollment only. Deliberately no NamespaceDeletion, writer,
// lease, external-service grant, rollout, or release qualification assertions.
func TestCrossEnrollmentOwnedHTTP(t *testing.T) {
	binary := os.Getenv("CROSS_ENROLLMENT_HELPER")
	if binary == "" {
		t.Skip("run the explicit cross-enrollment runner")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 70*time.Second)
	defer cancel()
	dir := t.TempDir()
	crossMust(t, os.Chmod(dir, 0700))
	f := newCrossFixture(t, ctx, dir)
	h := f.startHelper(binary)
	participantToken := f.bearer("owner", "")
	participants, err := namespacelifecycle.NewHTTPParticipants(h.URL, &http.Client{Timeout: 10 * time.Second}, func(context.Context) (string, error) { return participantToken, nil }, "hanni")
	crossMust(t, err)
	f.owner, err = NewOwnerNamespacesProcessor(f.m, crossNotifications{}, NamespaceOwnerOptions{Store: f.store, Native: f.native, Participants: participants, RequiredParticipants: []string{"hanni"}, Authorize: f.ownerAuthority})
	crossMust(t, err)
	creatorToken, claimToken := f.bearer("creator", ""), f.bearer("hanni", "")
	create := func(name, bearer string) ([]byte, int) {
		return f.post(f.server.URL, "/namespaces", "/", bearer, map[string]string{"name": name})
	}
	command := func(state namespacelifecycle.State, action string) namespaceParticipationCommand {
		return namespaceParticipationCommand{Action: action, NamespaceID: state.Namespace.ID, OperationID: state.Creation.OperationID, Participant: "hanni", RegistryID: state.Namespace.ID}
	}
	checkCounts := func(namespace string, claims, inserts, registryCount, registryInserts int64) crossStatus {
		t.Helper()
		status := f.control(h, http.MethodGet, "/_cross/status", namespace, "")
		if f.claims.calls.Load() != claims || f.claims.grants.Load() != claims || f.inserts() != inserts || status.Count != registryCount || status.Inserts != registryInserts {
			t.Fatalf("mutations: claims=%d grants=%d native inserts=%d registry count=%d inserts=%d; want %d/%d/%d/%d", f.claims.calls.Load(), f.claims.grants.Load(), f.inserts(), status.Count, status.Inserts, claims, inserts, registryCount, registryInserts)
		}
		return status
	}
	rootBefore, err := f.store.GetByName(ctx, "/")
	crossMust(t, err)
	for _, variant := range []string{"missing", "namespace", "resource", "issuer", "audience", "source"} {
		bearer := ""
		if variant != "missing" {
			bearer = f.bearer("creator", variant)
		}
		if _, status := create("cross", bearer); status < 400 {
			t.Fatalf("namespace Create accepted %s", variant)
		}
		if _, err := f.store.GetByName(ctx, "/cross"); !errors.Is(err, namespacelifecycle.ErrNotFound) {
			t.Fatal("denial reserved namespace", err)
		}
		checkCounts("/cross", 0, 1, 0, 0)
	}
	rootAfter, err := f.store.GetByName(ctx, "/")
	crossMust(t, err)
	if !reflect.DeepEqual(rootBefore, rootAfter) {
		t.Fatal("Create denial changed root owner")
	}
	body, status := create("cross", creatorToken)
	if status != http.StatusCreated && status != http.StatusOK {
		retained, readErr := f.store.GetByName(ctx, "/cross")
		t.Logf("retained owner phase=%s creation=%+v error=%v", retained.Phase, retained.Creation, readErr)
		t.Logf("helper status=%+v; claims=%d grants=%d source inserts=%d policy reads=%d revocation reads=%d", f.control(h, http.MethodGet, "/_cross/status", "/cross", ""), f.claims.calls.Load(), f.claims.grants.Load(), f.inserts(), f.policyReads.Load(), f.revocationReads.Load())
		t.Fatalf("owned Create status=%d body=%s", status, body)
	}
	state, err := f.store.GetByName(ctx, "/cross")
	crossMust(t, err)
	if state.Phase != "open" || state.Creation == nil || state.Creation.Phase != "ready" || len(state.Creation.Enrollments) != 1 || state.Creation.Enrollments[0].Phase != "confirmed" || state.Creation.Enrollments[0].RegistryID != state.Namespace.ID {
		t.Fatalf("Creator not ready: %+v", state)
	}
	marker, err := namespacelifecycle.CreationMarkerDigest(state)
	crossMust(t, err)
	stored := api.NewNamespace()
	stored.ID = state.Namespace.ID
	crossMust(t, f.m.Retrieve(manipulate.NewContext(ctx, manipulate.ContextOptionNamespace("/")), stored))
	var output api.Namespace
	crossMust(t, json.Unmarshal(body, &output))
	if output.ID != state.Namespace.ID || stored.ID != state.Namespace.ID || stored.Name != "/cross" || stored.Namespace != "/" || stored.CreationMarker != marker || strings.Contains(string(body), marker) || bytes.Contains(bytes.ToLower(body), []byte("creationmarker")) {
		t.Fatal("native ID/private marker mismatch or marker leaked")
	}
	retained := checkCounts("/cross", 1, 2, 1, 1)
	if retained.Registry == nil || retained.Registry.ID != state.Namespace.ID || retained.Registry.NamespaceName != "/cross" || retained.Registry.Revision != 1 || retained.Registry.Issued != 0 || retained.Registry.TerminalThrough != 0 || retained.Registry.Enrollment.OperationID != state.Creation.OperationID || retained.Registry.Enrollment.Digest != marker || retained.Registry.Enrollment.Scope.Namespace != state.Namespace || !reflect.DeepEqual(retained.Registry.Enrollment.Scope.Ancestors, state.Ancestors) {
		t.Fatalf("registry binding mismatch: %+v", retained.Registry)
	}
	if f.policyReads.Load() == 0 || f.revocationReads.Load() == 0 {
		t.Fatal("Hanni did not cross native policy/revocation HTTP boundary")
	}
	proof, err := participants.Observe(ctx, state, "hanni")
	crossMust(t, err)
	if proof.NamespaceID != state.Namespace.ID || proof.RegistryID != state.Namespace.ID || proof.Digest != state.Creation.Enrollments[0].Digest {
		t.Fatal("source/participant proof mismatch")
	}
	t.Logf("actual chain ready: sourceID=registryID=%s; acknowledged claims=1 native child inserts=1 registry inserts=1", state.Namespace.ID)
	// Every negative token is signed by the fixture key. Issuer/audience,
	// source claims, resource, and namespace restrictions are checked natively.
	for _, variant := range []string{"missing", "namespace", "resource", "issuer", "audience", "source"} {
		for _, endpoint := range []struct{ base, path, role, action string }{{f.server.URL, "/namespaceparticipations", "hanni", "ClaimEnrollment"}, {h.URL, "/findingpublicationnamespaces", "owner", "Enroll"}} {
			bearer := ""
			if variant != "missing" {
				bearer = f.bearer(endpoint.role, variant)
			}
			if _, status := f.post(endpoint.base, endpoint.path, "/cross", bearer, command(state, endpoint.action)); status < 400 {
				t.Fatalf("%s accepted %s", endpoint.path, variant)
			}
		}
		checkCounts("/cross", 1, 2, 1, 1)
		current, err := f.store.Get(ctx, state.Namespace.ID)
		crossMust(t, err)
		if !reflect.DeepEqual(current, state) {
			t.Fatal("denied request mutated owner")
		}
	}
	// Both public Create replay and actual clients remain read-only after ready.
	for range 2 {
		body, status := create("cross", creatorToken)
		if status != 200 && status != 201 {
			t.Fatalf("repeat Create status=%d body=%s", status, body)
		}
		var replay api.Namespace
		crossMust(t, json.Unmarshal(body, &replay))
		if replay.ID != state.Namespace.ID {
			t.Fatal("repeat Create changed source ID")
		}
		got, err := participants.Enroll(ctx, state, "hanni")
		crossMust(t, err)
		if got != proof {
			t.Fatal("repeat Enroll changed proof")
		}
		got, err = participants.Observe(ctx, state, "hanni")
		crossMust(t, err)
		if got != proof {
			t.Fatal("repeat Inspect changed proof")
		}
		body, status = f.post(f.server.URL, "/namespaceparticipations", "/cross", claimToken, command(state, "ClaimEnrollment"))
		var replayClaim namespaceParticipationResult
		crossMust(t, json.Unmarshal(body, &replayClaim))
		if status != 200 || replayClaim.Granted || replayClaim.Snapshot.Phase != "confirmed" {
			t.Fatal("claim replay granted")
		}
	}
	checkCounts("/cross", 1, 2, 1, 1)
	current, err := f.store.Get(ctx, state.Namespace.ID)
	crossMust(t, err)
	if !reflect.DeepEqual(current, state) {
		t.Fatal("replay changed owner")
	}
	// Unknown source incarnation must not create or claim a registry.
	unknown := command(state, "Enroll")
	unknown.NamespaceID = bson.NewObjectID().Hex()
	unknown.RegistryID = unknown.NamespaceID
	if _, status := f.post(h.URL, "/findingpublicationnamespaces", "/cross", participantToken, unknown); status < 400 {
		t.Fatal("unknown source enrolled")
	}
	checkCounts("/cross", 1, 2, 1, 1)
	// Missing previously-confirmed registry: install only a test-database fault.
	f.control(h, http.MethodPost, "/_cross/remove-registry", "/cross", state.Namespace.ID)
	if _, err := participants.Observe(ctx, state, "hanni"); err == nil {
		t.Fatal("missing registry inspected successfully")
	}
	if _, err := participants.Enroll(ctx, state, "hanni"); err == nil {
		t.Fatal("missing registry recreated")
	}
	if _, status := create("cross", creatorToken); status < 400 {
		t.Fatal("missing registry produced ready Create")
	}
	checkCounts("/cross", 1, 2, 0, 1)
	current, err = f.store.Get(ctx, state.Namespace.ID)
	crossMust(t, err)
	if !reflect.DeepEqual(current, state) {
		t.Fatal("missing evidence mutated retained owner")
	}
	// Lost response AFTER a real acknowledged source claim. Hanni must not
	// infer a grant from the subsequent claimed snapshot or insert on replay.
	f.dropClaim.Store(true)
	if _, status := create("lost", creatorToken); status < 400 {
		t.Fatal("lost claim acknowledgment produced success")
	}
	lost, err := f.store.GetByName(ctx, "/lost")
	crossMust(t, err)
	if lost.Creation.Phase != "applied" || lost.Creation.Enrollments[0].Phase != "claimed" {
		t.Fatalf("expected held acknowledged claim: %+v", lost.Creation)
	}
	missing := checkCounts("/lost", 2, 3, 0, 1)
	if missing.Registry != nil {
		t.Fatal("unknown acknowledgment initialized registry")
	}
	f.dropClaim.Store(false)
	if _, err := participants.Enroll(ctx, lost, "hanni"); err == nil {
		t.Fatal("claimed snapshot recreated missing registry")
	}
	if _, err := participants.Observe(ctx, lost, "hanni"); err == nil {
		t.Fatal("unknown outcome inspected successfully")
	}
	if _, status := create("lost", creatorToken); status < 400 {
		t.Fatal("unknown outcome repeat Create succeeded")
	}
	checkCounts("/lost", 2, 3, 0, 1)
	lostAfter, err := f.store.Get(ctx, lost.Namespace.ID)
	crossMust(t, err)
	if !reflect.DeepEqual(lost, lostAfter) {
		t.Fatal("unknown outcome replay mutated source")
	}
	t.Logf("PASS enrollment-only: 18 signed/no-token denials; replay stable; missing/unknown held; native permission reads=%d revocation reads=%d", f.policyReads.Load(), f.revocationReads.Load())
}
