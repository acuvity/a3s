//go:build integration

package processors

import (
	"context"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/a3s/pkgs/namespacelifecycle"
	"go.acuvity.ai/manipulate"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// Task 3.73.14: owned publication-only fixture, not production writer coverage.
// Separate processes/databases preserve the enrollment-only tracer's counts and
// missing/unknown-enrollment cases. No FindingJob, Lua, cleaner, or live stack.
func TestCrossEnrollmentAndDrainHTTP(t *testing.T) {
	binary := os.Getenv("CROSS_ENROLLMENT_HELPER")
	if binary == "" {
		t.Skip("run the explicit cross-enrollment runner")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()
	dir := t.TempDir()
	crossMust(t, os.Chmod(dir, 0700))
	f := newCrossFixture(t, ctx, dir)
	h := f.startHelper(binary)
	ownerToken := f.bearer("owner", "")
	tokens := func(context.Context) (string, error) { return ownerToken, nil }
	client := &http.Client{Timeout: 5 * time.Second}
	participants, err := namespacelifecycle.NewHTTPParticipants(h.URL, client, tokens, "hanni")
	crossMust(t, err)
	deletion, err := namespacelifecycle.NewHTTPDeletionParticipants(h.URL, client, tokens, "hanni")
	crossMust(t, err)
	sink := &crossUpdateSink{t: t}
	f.owner, err = NewOwnerNamespacesProcessor(f.m, sink, NamespaceOwnerOptions{Store: f.store, Native: f.native, Participants: participants, RequiredParticipants: []string{"hanni"}, DeletionParticipants: deletion, Authorize: f.ownerAuthority})
	crossMust(t, err)
	creator := f.bearer("creator", "")
	body, status := f.post(f.server.URL, "/namespaces", "/", creator, map[string]string{"name": "drain"})
	if status != 200 && status != 201 {
		t.Fatalf("Create status=%d body=%s", status, body)
	}
	state, err := f.store.GetByName(ctx, "/drain")
	crossMust(t, err)
	if state.Phase != "open" || state.Creation.Phase != "ready" {
		t.Fatalf("not ready: %+v", state)
	}
	registry := f.control(h, http.MethodGet, "/_cross/status", "/drain", "")
	if registry.Registry == nil || registry.Registry.ID != state.Namespace.ID || registry.Inserts != 1 || f.inserts() != 2 || f.claims.grants.Load() != 1 {
		t.Fatalf("enrollment not exact: %+v", registry)
	}
	sink.arm()
	sink.loseNext() // Lost delivery must be repairable by an authenticated terminal replay.
	remove := func(bearer string) ([]byte, int) {
		return f.request(http.MethodDelete, f.server.URL, "/namespaces/"+state.Namespace.ID, "/", bearer, nil)
	}
	root, err := f.store.GetByName(ctx, "/")
	crossMust(t, err)
	// Negative native DELETE auth is exercised before starting the short-lived
	// dispatch barrier. All fixture roles except creator lack namespaces:delete.
	for _, variant := range []string{"missing", "namespace", "resource", "issuer", "audience", "source", "owner", "hanni", "policy"} {
		bearer := ""
		switch variant {
		case "missing":
		case "owner", "hanni", "policy":
			bearer = f.bearer(variant, "")
		default:
			bearer = f.bearer("creator", variant)
		}
		if _, code := remove(bearer); code != 403 {
			t.Fatalf("DELETE %s status=%d, want native auth denial", variant, code)
		}
		current, err := f.store.Get(ctx, state.Namespace.ID)
		crossMust(t, err)
		parent, err := f.store.GetByName(ctx, "/")
		crossMust(t, err)
		if !reflect.DeepEqual(current, state) || !reflect.DeepEqual(parent, root) || f.nativeDeletes() != 0 {
			t.Fatal("denied DELETE mutated owner")
		}
	}
	// This nonce-only test control directly composes publication auth callbacks.
	// It is deliberately NOT claimed as FindingPublicationHTTP auth coverage.
	f.control(h, http.MethodPost, "/_cross/publication/start", "/drain", "")
	barrierAt := time.Now()
	before := f.publication(h)
	body, status = remove(creator)
	closing, readErr := f.store.Get(ctx, state.Namespace.ID)
	held := f.publication(h)
	present := api.NewNamespace()
	present.ID = state.Namespace.ID
	nativeErr := f.m.Retrieve(manipulate.NewContext(ctx, manipulate.ContextOptionNamespace("/")), present)
	deletesWhileHeld := f.nativeDeletes()
	// Release BEFORE assertions/negative-auth loops: never burn the 10s live
	// dispatch deadline on diagnostics or accidentally strand the accepted owner.
	f.control(h, http.MethodPost, "/_cross/publication/release", "/drain", "")
	elapsed := time.Since(barrierAt)
	crossMust(t, readErr)
	crossMust(t, nativeErr)
	if status != 409 || !strings.Contains(string(body), "held") || closing.Phase != "closing" || closing.Intent == nil || len(closing.Drains) != 0 || deletesWhileHeld != 0 || present.Name != "/drain" {
		t.Fatalf("first DELETE must hold: status=%d body=%s state=%+v deletes=%d", status, body, closing, deletesWhileHeld)
	}
	if elapsed >= 8*time.Second {
		t.Fatalf("fixture barrier too slow: %s", elapsed)
	}
	fence := crossFence{closing.Intent.ID, state.Namespace.ID, "/drain"}
	if before.Control.Active == nil || before.Control.Active.ReceiptID != before.ReceiptID || before.DispatchPhase != "admitted" || before.WriteChecks != 3 || before.FindingCount != 0 || !reflect.DeepEqual(before.Control.Active, held.Control.Active) || held.ControlCount != 1 || held.ReceiptCount != 1 || held.ReceiptID != before.ReceiptID || held.DispatchPhase != "admitted" || held.Registry.DeletionFence == nil || *held.Registry.DeletionFence != fence || held.Control.DeletionFence == nil || *held.Control.DeletionFence != fence || held.FindingCount != 0 || held.Registry.Issued != 2 || held.Registry.TerminalThrough != 2 || string(held.Registry.Slot) != "null" {
		t.Fatalf("accepted work/fences not retained: before=%+v held=%+v", before, held)
	}
	t.Logf("first real DELETE Held; accepted receipt/control retained, registry/control sealed; barrier released in %s", elapsed)
	confirmed := f.publication(h)
	if confirmed.Control.ID != held.Control.ID || confirmed.Control.Active != nil || confirmed.Control.CASRevision != held.Control.CASRevision+1 || confirmed.ReceiptID != before.ReceiptID || confirmed.Receipt.CommandDigest != before.Receipt.CommandDigest || confirmed.Receipt.Status != "Confirmed" || confirmed.DispatchPhase != "confirmed" || confirmed.Receipt.CanonicalID == "" || confirmed.FindingCount != 1 || confirmed.WriteChecks != 4 {
		t.Fatalf("real canonical confirmation/exact release missing: %+v", confirmed)
	}
	f.control(h, http.MethodPost, "/_cross/publication/reject-admission", "/drain", "")
	// All three deletion actions retain their actual operation-specific auth.
	for _, variant := range []string{"missing", "namespace", "resource", "issuer", "audience", "source"} {
		for _, endpoint := range []struct{ base, path, role, action string }{{h.URL, "/findingpublicationnamespaces", "owner", "PrepareDelete"}, {h.URL, "/findingpublicationnamespaces", "owner", "InspectDelete"}, {f.server.URL, "/namespaceparticipations", "hanni", "InspectDeletion"}} {
			bearer := ""
			if variant != "missing" {
				bearer = f.bearer(endpoint.role, variant)
			}
			command := map[string]string{"action": endpoint.action, "namespaceID": state.Namespace.ID, "operationID": state.Creation.OperationID, "participant": "hanni", "registryID": state.Namespace.ID, "deletionIntentID": closing.Intent.ID}
			if _, code := f.post(endpoint.base, endpoint.path, "/drain", bearer, command); code < 400 {
				t.Fatalf("%s accepted %s", endpoint.action, variant)
			}
		}
	}
	unchanged, err := f.store.Get(ctx, state.Namespace.ID)
	crossMust(t, err)
	if !reflect.DeepEqual(closing, unchanged) || !reflect.DeepEqual(confirmed, f.publication(h)) || f.nativeDeletes() != 0 {
		t.Fatal("denied deletion actions mutated retained state")
	}
	// Read-only real coordinator proof; Observe must not replace Prepare.
	proof, err := deletion.Observe(ctx, closing, "hanni")
	crossMust(t, err)
	if proof.IntentID != closing.Intent.ID || proof.NamespaceID != state.Namespace.ID || proof.Participant != "hanni" || len(proof.Digest) != 64 || !reflect.DeepEqual(confirmed, f.publication(h)) {
		t.Fatalf("read-only peer proof invalid: %+v", proof)
	}
	body, status = remove(creator)
	// The first applied DELETE preserves native CRUD's optional representation;
	// a later already-deleted replay returns NoContent. Neither status is proof
	// without the exact owner/native assertions below.
	if status != http.StatusOK && status != http.StatusNoContent {
		t.Fatalf("second DELETE status=%d body=%s", status, body)
	}
	deleted, err := f.store.Get(ctx, state.Namespace.ID)
	crossMust(t, err)
	resultDigest, err := namespacelifecycle.OwnedDeletionResultDigest(deleted)
	crossMust(t, err)
	if deleted.Phase != "deleted" || deleted.Deletion.ResultDigest != resultDigest || len(deleted.Drains) != 1 || deleted.Drains[0] != proof || !reflect.DeepEqual(deleted.Deletion.Acquisitions, []string{"released"}) {
		t.Fatalf("source tombstone incomplete: %+v", deleted)
	}
	rootAfter, err := f.store.GetByName(ctx, "/")
	crossMust(t, err)
	if len(rootAfter.Pins) != 0 || rootAfter.Phase != "open" {
		t.Fatalf("root pins not settled: %+v", rootAfter)
	}
	id, err := bson.ObjectIDFromHex(state.Namespace.ID)
	crossMust(t, err)
	n, err := f.db.Collection(api.NamespaceIdentity.Name).CountDocuments(ctx, bson.M{"_id": id})
	crossMust(t, err)
	if n != 0 || f.nativeDeletes() != 1 || sink.count() != 0 {
		t.Fatalf("delete count=%d remaining=%d notifications=%d", f.nativeDeletes(), n, sink.count())
	}
	// Inspect the real owned-database delete command, not a wrapper counter.
	var deletionProfile bson.Raw
	crossMust(t, f.db.Collection("system.profile").FindOne(ctx, bson.M{"op": "remove", "ns": f.db.Name() + "." + api.NamespaceIdentity.Name}).Decode(&deletionProfile))
	q, validQuery := deletionProfile.Lookup("command", "q").DocumentOK()
	marker, err := namespacelifecycle.CreationMarkerDigest(state)
	crossMust(t, err)
	deleteID, validID := q.Lookup("_id").ObjectIDOK()
	if !validQuery || !validID || deleteID != id || q.Lookup("namespace").StringValue() != "/" || q.Lookup("name").StringValue() != "/drain" || q.Lookup("creationmarker").StringValue() != marker || q.Lookup("createtime").DateTime() != present.CreateTime.UnixMilli() || q.Lookup("$expr").Type != bson.TypeEmbeddedDocument {
		t.Fatalf("native delete was not exact: %s", deletionProfile)
	}
	f.assertNoLegacyDeletion()
	terminal := f.publication(h)
	if terminal.FindingCount != 1 || terminal.Receipt.Status != "Confirmed" || terminal.ReceiptID != before.ReceiptID || terminal.Registry.DeletionFence == nil {
		t.Fatalf("drain destroyed retained evidence: %+v", terminal)
	}
	for replay := range 2 {
		body, status = remove(creator)
		if status != http.StatusNoContent {
			t.Fatalf("repeat DELETE status=%d body=%s", status, body)
		}
		current, err := f.store.Get(ctx, state.Namespace.ID)
		crossMust(t, err)
		parent, err := f.store.GetByName(ctx, "/")
		crossMust(t, err)
		if !reflect.DeepEqual(deleted, current) || !reflect.DeepEqual(rootAfter, parent) || !reflect.DeepEqual(terminal, f.publication(h)) || f.nativeDeletes() != 1 || sink.count() != replay+1 {
			t.Fatal("repeat DELETE changed settled effects or did not repair safe invalidation")
		}
	}
	f.assertNoLegacyDeletion()
	t.Log("PASS owned publication-only drain: authenticated owner/participant HTTP; one canonical finding, one exact native delete, stable tombstone/replays; publication auth is a trusted callback fixture, not production coverage")
}
