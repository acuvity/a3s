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
	"testing"
	"time"

	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/a3s/pkgs/namespacelifecycle"
	"go.acuvity.ai/manipulate"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// Wire mirror, not a source/authentication substitute. Native API/model types
// stay in the independently built Go 1.27.1 Hanni process.
type crossGatewayResult struct {
	Conf    json.RawMessage
	Record  json.RawMessage
	Lineage struct {
		Namespace crossOriginalNamespace
		Sources   []struct {
			Kind, ID, Name, SHA256 string
			Namespace              namespacelifecycle.Namespace
		}
	}
	Verified       bool
	InputsVerified bool
}

func (f *crossFixture) gateway(h crossHelper, action string, conf, record json.RawMessage, bearer *string) (crossGatewayResult, int) {
	f.t.Helper()
	data, err := json.Marshal(struct {
		Action      string
		Conf        json.RawMessage
		Record      json.RawMessage
		SourceToken *string
	}{action, conf, record, bearer})
	crossMust(f.t, err)
	r, err := http.NewRequestWithContext(f.ctx, http.MethodPost, h.URL+"/_cross/gateway", bytes.NewReader(data))
	crossMust(f.t, err)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Cross-Nonce", h.Nonce)
	response, err := (&http.Client{Timeout: 55 * time.Second}).Do(r)
	crossMust(f.t, err)
	defer response.Body.Close() //nolint:errcheck
	var result crossGatewayResult
	crossMust(f.t, json.NewDecoder(io.LimitReader(response.Body, 32768)).Decode(&result))
	return result, response.StatusCode
}

// Task3.73.18.13.22: real native Mongo model reads plus the concrete capture
// client crossing actual signed A3S CaptureScope/Verify, not granted=true or an
// owner callback. Component evidence only: no producer/snapshot/Finding write.
func TestCrossGatewayLineageHTTP(t *testing.T) {
	binary := os.Getenv("CROSS_ENROLLMENT_HELPER")
	if binary == "" {
		t.Skip("run cross-enrollment/run.py with CROSS_ENROLLMENT_TEST_PATTERN=^TestCrossGatewayLineageHTTP$")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Second)
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
		t.Fatalf("owner Create status=%d body=%s", code, body)
	}
	state, err := f.store.GetByName(ctx, "/cross")
	crossMust(t, err)
	snapshot, err := namespacelifecycle.SnapshotEnrollment(state, "hanni", state.Namespace.ID)
	crossMust(t, err)
	marker, err := namespacelifecycle.CreationMarkerDigest(state)
	crossMust(t, err)
	expected := crossOriginalNamespace{snapshot.Scope, state.Creation.OperationID, marker}
	registry := f.control(h, http.MethodGet, "/_cross/status", "/cross", "")
	if state.Phase != "open" || snapshot.SourcePhase != "ready" || snapshot.Phase != "confirmed" || registry.Registry == nil || registry.Registry.ID != state.Namespace.ID || !reflect.DeepEqual(registry.Registry.Enrollment.Scope, expected.Scope) || registry.Registry.Enrollment.OperationID != expected.OwnerOperationID || registry.Registry.Enrollment.Digest != expected.OwnerDigest || registry.Count != 1 || registry.Inserts != 1 || f.claims.calls.Load() != 1 || f.claims.grants.Load() != 1 {
		t.Fatal("not a real owner-created/enrolled namespace")
	}

	// Capture never claims admission or modifies any existing source/policy row.
	// Counts cover attempted write-and-restore, not just final row equality.
	unchanged := func() func() {
		t.Helper()
		read := func() any {
			t.Helper()
			names, err := f.db.ListCollectionNames(ctx, bson.M{})
			crossMust(t, err)
			rows := map[string][]bson.Raw{}
			for _, name := range names {
				if name == "system.profile" {
					continue
				}
				cursor, err := f.db.Collection(name).Find(ctx, bson.M{}, options.Find().SetSort(bson.D{{Key: "_id", Value: 1}}))
				crossMust(t, err)
				var records []bson.Raw
				crossMust(t, cursor.All(ctx, &records))
				rows[name] = records
			}
			var server struct {
				Ops struct{ Insert, Update, Delete int64 } `bson:"opcounters"`
			}
			crossMust(t, f.db.Client().Database("admin").RunCommand(ctx, bson.D{{Key: "serverStatus", Value: 1}}).Decode(&server))
			retained := f.control(h, http.MethodGet, "/_cross/status", "/cross", "")
			// This diagnostic counts entries in a CAPPED profiler, not writes.
			// Native guards check actual rows + server write counters per call;
			// allow old profile entries to roll out during the extended exercise.
			retained.Inserts = 0
			return struct {
				Rows           map[string][]bson.Raw
				Writes         [3]int64
				Claims, Grants int64
				Registry       crossStatus
			}{rows, [3]int64{server.Ops.Insert, server.Ops.Update, server.Ops.Delete}, f.claims.calls.Load(), f.claims.grants.Load(), retained}
		}
		before := read()
		return func() {
			t.Helper()
			if !reflect.DeepEqual(before, read()) {
				t.Fatal("gateway capture/verify changed A3S rows/write/claim counters or Hanni enrollment")
			}
		}
	}
	check := unchanged()
	before := f.participationRequests.Load()
	if _, code := f.post(h.URL, "/_cross/gateway", "/cross", "", map[string]string{"Action": "exercise"}); code != http.StatusForbidden {
		t.Fatal("gateway route accepted missing nonce")
	}
	if f.participationRequests.Load() != before {
		t.Fatal("denied fixture route reached source")
	}
	// Inspect the actual signed source response: ready/confirmed, non-granting.
	body, code = f.post(f.server.URL, "/namespaceparticipations", "/cross", f.bearer("hanni", ""), map[string]string{"action": "CaptureScope", "participant": "hanni"})
	var wire namespaceParticipationResult
	crossMust(t, json.Unmarshal(body, &wire))
	if code != http.StatusOK || wire.Granted || !reflect.DeepEqual(wire.Snapshot, snapshot) {
		t.Fatal("capture endpoint returned a grant or substituted owner")
	}
	captured, status := f.gateway(h, "exercise", nil, nil, nil)
	if status != http.StatusOK || !captured.Verified || !captured.InputsVerified || len(captured.Record) == 0 || !reflect.DeepEqual(captured.Lineage.Namespace, expected) || len(captured.Lineage.Sources) != 5 {
		t.Fatalf("native source exercise/binding failed: status=%d result=%+v", status, captured.Lineage)
	}
	for i, source := range captured.Lineage.Sources {
		owner := expected.Scope.Namespace
		if i == 2 || i == 4 {
			owner = expected.Scope.Ancestors[0]
		}
		if source.Namespace != owner || source.ID == "" || len(source.SHA256) != 64 {
			t.Fatal("lost exact owning source identity", i)
		}
	}
	if captured.Lineage.Sources[1].Name != "z-connector" || captured.Lineage.Sources[3].Name != "a-connector" {
		t.Fatal("source order was replaced by rendered route order")
	}
	check()
	verify := func(bearer *string, want int) {
		t.Helper()
		check := unchanged()
		out, status := f.gateway(h, "verify", captured.Conf, captured.Record, bearer)
		if status != want || out.Verified != (want == http.StatusOK) || out.InputsVerified != (want == http.StatusOK) || !bytes.Equal(out.Record, captured.Record) || !bytes.Equal(out.Conf, captured.Conf) {
			t.Fatalf("retained verify status=%d verified=%v; want=%d, original config must remain byte-identical", status, out.Verified, want)
		}
		if want == http.StatusOK {
			if !reflect.DeepEqual(out.Lineage, captured.Lineage) {
				t.Fatal("Verify substituted a new binding/source")
			}
		} else if !reflect.DeepEqual(out.Lineage, (crossGatewayResult{}).Lineage) {
			t.Fatal("Held returned replacement lineage")
		}
		check()
	}
	verify(nil, http.StatusOK)
	for _, variant := range []string{"missing", "signature", "namespace", "resource", "issuer", "audience", "source"} {
		bearer := f.bearer("hanni", variant)
		if variant == "missing" {
			bearer = ""
		}
		if variant == "signature" {
			bearer += "broken"
		}
		verify(&bearer, http.StatusConflict)
		t.Logf("gateway retained Verify Held across signed source denial: %s", variant)
	}
	revocation := api.NewRevocation()
	revocation.Namespace, revocation.Subject, revocation.FlattenedSubject = "/", [][]string{crossIdentity("hanni")}, crossIdentity("hanni")
	crossMust(t, f.m.Create(manipulate.NewContext(ctx, manipulate.ContextOptionNamespace("/")), revocation))
	verify(nil, http.StatusConflict)
	crossMust(t, f.m.Delete(manipulate.NewContext(ctx, manipulate.ContextOptionNamespace("/")), revocation))
	verify(nil, http.StatusOK)

	// Same native namespace name, different incarnation, in this owned DB only.
	// Retained verification must Hold, not Capture a replacement owner for it.
	func() {
		collection := f.db.Collection(api.NamespaceIdentity.Name)
		oid, err := bson.ObjectIDFromHex(state.Namespace.ID)
		crossMust(t, err)
		filter := bson.M{"_id": oid}
		var saved bson.Raw
		crossMust(t, collection.FindOne(ctx, filter).Decode(&saved))
		var replacement bson.M
		crossMust(t, bson.Unmarshal(saved, &replacement))
		other := bson.NewObjectID()
		replacement["_id"] = other
		_, err = collection.DeleteOne(ctx, filter)
		crossMust(t, err)
		_, err = collection.InsertOne(ctx, replacement)
		crossMust(t, err)
		defer func() {
			_, err := collection.DeleteOne(ctx, bson.M{"_id": other})
			crossMust(t, err)
			_, err = collection.InsertOne(ctx, saved)
			crossMust(t, err)
		}()
		verify(nil, http.StatusConflict)
		t.Log("gateway retained Verify Held after actual native owner incarnation replacement")
	}()
	verify(nil, http.StatusOK)
	if f.participationRequests.Load() <= before+2 || f.policyReads.Load() == 0 || f.revocationReads.Load() == 0 {
		t.Fatal("did not cross actual signed capture/permission/revocation boundaries")
	}
	t.Log("PASS captured native inputs through real helper: signed current-owner checks, retained observation bytes, baseline/source drift and wrong-ID Holds, nested detachment; no owner/native read-time writes or admission claims")
	t.Logf("PASS owned cross-gateway lineage: signed CaptureScope/Verify requests=%d, exact original owner/ordered native IDs, drift/secret/unbound Held, no capture claim or write; Mongo source reads are not native API HTTP source-read authorization; component-only, no production coverage", f.participationRequests.Load()-before)
}
