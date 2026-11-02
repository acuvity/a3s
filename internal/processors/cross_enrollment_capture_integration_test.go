//go:build integration

package processors

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
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
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// Wire mirror only: authority and current/original comparison remain in the
// actual A3S inspector and native findings.NamespaceCaptureClient respectively.
type crossOriginalNamespace struct {
	Scope            namespacelifecycle.EnrollmentScope
	OwnerOperationID string
	OwnerDigest      string
}

type crossCaptureRequest struct {
	Action, Namespace string
	Original          crossOriginalNamespace
	SourceToken       *string
}

type crossCaptureResult struct {
	Original crossOriginalNamespace
	Verified bool
}

func (f *crossFixture) capture(h crossHelper, input crossCaptureRequest) (crossCaptureResult, int) {
	f.t.Helper()
	data, err := json.Marshal(input)
	crossMust(f.t, err)
	r, err := http.NewRequestWithContext(f.ctx, http.MethodPost, h.URL+"/_cross/capture", bytes.NewReader(data))
	crossMust(f.t, err)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Cross-Nonce", h.Nonce)
	response, err := (&http.Client{Timeout: 15 * time.Second}).Do(r)
	crossMust(f.t, err)
	defer response.Body.Close() //nolint:errcheck
	var out crossCaptureResult
	crossMust(f.t, json.NewDecoder(io.LimitReader(response.Body, 32768)).Decode(&out))
	return out, response.StatusCode
}

// Task 3.73.18.13.13: concrete shared capture/verify over the existing signed,
// two-process HTTP/Mongo harness. No Apex/Colektor producer or writer claim.
func TestCrossEnrollmentCaptureHTTP(t *testing.T) {
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
	body, code := f.post(f.server.URL, "/namespaces", "/", f.bearer("creator", ""), map[string]string{"name": "cross"})
	if code != http.StatusCreated && code != http.StatusOK {
		t.Fatalf("owner Create: status=%d body=%s", code, body)
	}
	state, err := f.store.GetByName(ctx, "/cross")
	crossMust(t, err)
	snapshot, err := namespacelifecycle.SnapshotEnrollment(state, "hanni", state.Namespace.ID)
	crossMust(t, err)
	marker, err := namespacelifecycle.CreationMarkerDigest(state)
	crossMust(t, err)
	expected := crossOriginalNamespace{snapshot.Scope, state.Creation.OperationID, marker}
	registry := f.control(h, http.MethodGet, "/_cross/status", "/cross", "")
	if state.Phase != "open" || snapshot.SchemaVersion != "namespace-enrollment.v1" || snapshot.SourcePhase != "ready" || snapshot.Phase != "confirmed" || snapshot.Digest != marker || registry.Registry == nil || registry.Registry.ID != state.Namespace.ID || registry.Registry.Enrollment.OperationID != expected.OwnerOperationID || registry.Registry.Enrollment.Digest != expected.OwnerDigest || !reflect.DeepEqual(registry.Registry.Enrollment.Scope, expected.Scope) || registry.Count != 1 || registry.Inserts != 1 || f.inserts() != 2 || f.claims.calls.Load() != 1 || f.claims.grants.Load() != 1 {
		t.Fatal("capture prerequisite is not the original real owner/enrollment binding")
	}
	if f.policyReads.Load() == 0 || f.revocationReads.Load() == 0 {
		t.Fatal("enrollment did not cross native permissions/revocation HTTP")
	}

	// Full owned source rows plus real mongod write counters detect even a
	// write-and-restore. Server counters avoid capped system.profile rollover.
	unchanged := func() func() {
		t.Helper()
		read := func() any {
			t.Helper()
			rows := make([][]bson.Raw, 0, 2)
			for _, identity := range []string{api.NamespaceLifecycleIdentity.Name, api.NamespaceIdentity.Name} {
				cursor, err := f.db.Collection(identity).Find(ctx, bson.M{}, options.Find().SetSort(bson.D{{Key: "_id", Value: 1}}))
				crossMust(t, err)
				var records []bson.Raw
				crossMust(t, cursor.All(ctx, &records))
				rows = append(rows, records)
			}
			var server struct {
				Ops struct{ Insert, Update, Delete int64 } `bson:"opcounters"`
			}
			crossMust(t, f.db.Client().Database("admin").RunCommand(ctx, bson.D{{Key: "serverStatus", Value: 1}}).Decode(&server))
			return struct {
				Rows           [][]bson.Raw
				Writes         [3]int64
				Claims, Grants int64
				Registry       crossStatus
			}{rows, [3]int64{server.Ops.Insert, server.Ops.Update, server.Ops.Delete}, f.claims.calls.Load(), f.claims.grants.Load(), f.control(h, http.MethodGet, "/_cross/status", "/cross", "")}
		}
		before := read()
		return func() {
			t.Helper()
			if !reflect.DeepEqual(before, read()) {
				t.Fatal("capture/verify changed lifecycle, native, claim/grant, or registry evidence/counters")
			}
		}
	}
	call := func(input crossCaptureRequest, want int, binding crossOriginalNamespace, verified bool) crossCaptureResult {
		t.Helper()
		check := unchanged()
		out, status := f.capture(h, input)
		if status != want || out.Verified != verified || !reflect.DeepEqual(out.Original, binding) {
			t.Fatalf("%s namespace=%q status=%d result=%+v; want status=%d binding=%+v verified=%v", input.Action, input.Namespace, status, out, want, binding, verified)
		}
		check()
		return out
	}
	zero := crossOriginalNamespace{}
	capture := crossCaptureRequest{Action: "capture", Namespace: "/cross"}
	captured := call(capture, http.StatusOK, expected, false)
	verify := crossCaptureRequest{Action: "verify", Original: captured.Original}
	call(verify, http.StatusOK, zero, true)
	// The source response itself is the existing ready/confirmed, non-granting
	// wire contract. No client-supplied incarnation or owner assertion is sent.
	check := unchanged()
	body, code = f.post(f.server.URL, "/namespaceparticipations", "/cross", f.bearer("hanni", ""), map[string]string{"action": "CaptureScope", "participant": "hanni"})
	var wire namespaceParticipationResult
	crossMust(t, json.Unmarshal(body, &wire))
	if code != http.StatusOK || wire.Granted || !reflect.DeepEqual(wire.Snapshot, snapshot) {
		t.Fatalf("source capture snapshot mismatch: %d %+v", code, wire)
	}
	check()

	before := f.participationRequests.Load()
	if _, code := f.post(h.URL, "/_cross/capture", "/cross", "", capture); code != http.StatusForbidden {
		t.Fatal("test-only capture route accepted missing nonce")
	}
	call(crossCaptureRequest{Action: "verify"}, http.StatusConflict, zero, false)
	if f.participationRequests.Load() != before {
		t.Fatal("missing nonce/original binding reached source lookup")
	}
	for _, mutate := range []func(*crossOriginalNamespace){
		func(n *crossOriginalNamespace) { n.Scope.Namespace.ID = bson.NewObjectID().Hex() },
		func(n *crossOriginalNamespace) { n.Scope.Namespace.Name = "/lost" },
		func(n *crossOriginalNamespace) { n.Scope.Ancestors[0].ID = bson.NewObjectID().Hex() },
		func(n *crossOriginalNamespace) { n.OwnerOperationID = "create:other" },
		func(n *crossOriginalNamespace) { n.OwnerDigest = strings.Repeat("f", 64) },
	} {
		changed := expected
		changed.Scope.Ancestors = append([]namespacelifecycle.Namespace(nil), expected.Scope.Ancestors...)
		mutate(&changed)
		before := f.participationRequests.Load()
		call(crossCaptureRequest{Action: "verify", Original: changed}, http.StatusConflict, zero, false)
		if f.participationRequests.Load() != before+1 {
			t.Fatal("valid mismatched original was not compared against current source")
		}
	}
	for _, variant := range []string{"missing", "signature", "namespace", "resource", "issuer", "audience", "source"} {
		bearer := f.bearer("hanni", variant)
		switch variant {
		case "missing":
			bearer = ""
		case "signature":
			bearer += "broken"
		}
		for _, input := range []crossCaptureRequest{capture, verify} {
			input.SourceToken = &bearer
			call(input, http.StatusConflict, zero, false)
		}
	}
	// Revoke the existing helper source identity in this owned database. This
	// must invalidate both new Capture and retained Verify without replacing it.
	revocation := api.NewRevocation()
	revocation.Namespace, revocation.Subject = "/", [][]string{crossIdentity("hanni")}
	revocation.FlattenedSubject = crossIdentity("hanni")
	crossMust(t, f.m.Create(manipulate.NewContext(ctx, manipulate.ContextOptionNamespace("/")), revocation))
	call(capture, http.StatusConflict, zero, false)
	call(verify, http.StatusConflict, zero, false)
	crossMust(t, f.m.Delete(manipulate.NewContext(ctx, manipulate.ContextOptionNamespace("/")), revocation))
	call(verify, http.StatusOK, zero, true)
	call(crossCaptureRequest{Action: "capture", Namespace: "/lost"}, http.StatusConflict, zero, false)

	// Faults affect only this fresh fixture; each baseline is taken AFTER the
	// fault and checked before restoration. No source or registry repair occurs.
	for _, fault := range []string{"owner-absent", "native-absent", "native-replaced", "closing"} {
		func() {
			collection := f.db.Collection(api.NamespaceIdentity.Name)
			if fault == "owner-absent" || fault == "closing" {
				collection = f.db.Collection(api.NamespaceLifecycleIdentity.Name)
			}
			oid, err := bson.ObjectIDFromHex(state.Namespace.ID)
			crossMust(t, err)
			filter := bson.M{"_id": oid}
			var saved bson.Raw
			crossMust(t, collection.FindOne(ctx, filter).Decode(&saved))
			defer func() {
				_, err := collection.ReplaceOne(ctx, filter, saved, options.Replace().SetUpsert(true))
				crossMust(t, err)
			}()
			if fault == "closing" {
				closing, err := f.store.Get(ctx, state.Namespace.ID)
				crossMust(t, err)
				intent, err := namespacelifecycle.OwnedDeletionIntent(closing, "delete:"+state.Namespace.ID)
				crossMust(t, err)
				closing.Phase, closing.Intent = "closing", &intent
				closing.Deletion = &namespacelifecycle.OwnedDeletion{Acquisitions: make([]string, len(closing.Ancestors))}
				for i := range closing.Deletion.Acquisitions {
					closing.Deletion.Acquisitions[i] = "held"
				}
				data, err := json.Marshal(closing)
				crossMust(t, err)
				_, err = collection.UpdateOne(ctx, filter, bson.M{"$set": bson.M{"data": string(data)}})
				crossMust(t, err)
				current, err := f.store.Get(ctx, state.Namespace.ID)
				crossMust(t, err)
				if current.Phase != "closing" {
					t.Fatal("closing fault not installed")
				}
			} else {
				_, err := collection.DeleteOne(ctx, filter)
				crossMust(t, err)
				if fault == "native-replaced" {
					var replacement bson.D
					crossMust(t, bson.Unmarshal(saved, &replacement))
					other := bson.NewObjectID()
					for i := range replacement {
						if replacement[i].Key == "_id" {
							replacement[i].Value = other
						}
					}
					_, err := collection.InsertOne(ctx, replacement)
					crossMust(t, err)
					defer func() {
						_, err := collection.DeleteOne(ctx, bson.M{"_id": other})
						crossMust(t, err)
					}()
				}
			}
			call(capture, http.StatusConflict, zero, false)
			call(verify, http.StatusConflict, zero, false)
			t.Logf("capture/retained verify held without mutation or replacement: %s", fault)
		}()
		call(verify, http.StatusOK, zero, true)
	}
	call(capture, http.StatusOK, expected, false)
	t.Logf("PASS concrete shared Capture/Verify: exact original owner/registry binding; signed-token/resource/revocation denials; missing binding before lookup; absent/closing/native-replaced held; no claim/grant or storage mutations; policy HTTP reads=%d revocation HTTP reads=%d", f.policyReads.Load(), f.revocationReads.Load())
}
