//go:build integration

package processors

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.acuvity.ai/a3s/internal/mongofixture"
	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/a3s/pkgs/authorizer"
	"go.acuvity.ai/a3s/pkgs/indexes"
	"go.acuvity.ai/a3s/pkgs/namespacelifecycle"
	"go.acuvity.ai/a3s/pkgs/permissions"
	"go.acuvity.ai/a3s/pkgs/token"
	"go.acuvity.ai/bahamut"
	"go.acuvity.ai/elemental"
	"go.acuvity.ai/manipulate"
	"go.acuvity.ai/manipulate/manipmongo"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// Test-only participant: the source fixture still consumes the actual Mongo
// enrollment claim. This is not production participant or writer coverage.
type captureEnrollment struct{ store *namespacelifecycle.Store }

func (p captureEnrollment) Enroll(ctx context.Context, s namespacelifecycle.State, participant string) (namespacelifecycle.EnrollmentProof, error) {
	if _, won, err := p.store.ClaimCreationEnrollment(ctx, s, participant, s.Namespace.ID); err != nil || !won {
		return namespacelifecycle.EnrollmentProof{}, namespacelifecycle.ErrPending
	}
	return p.Observe(ctx, s, participant)
}
func (p captureEnrollment) Observe(_ context.Context, s namespacelifecycle.State, participant string) (namespacelifecycle.EnrollmentProof, error) {
	return namespacelifecycle.EnrollmentProof{Participant: participant, NamespaceID: s.Namespace.ID, RegistryID: s.Namespace.ID, OperationID: s.Creation.OperationID, Digest: strings.Repeat("b", 64)}, nil
}

// Delay only the return of a real Mongo permission read. No policy decision or
// storage result is faked. The selected guard follows an actual owner/native read.
type captureReadDelay struct {
	permissions.Retriever
	mu        sync.Mutex
	remaining int
	expires   time.Time
	fired     bool
}

func (r *captureReadDelay) Permissions(ctx context.Context, claims []string, ns string, opts ...permissions.RetrieverOption) (permissions.PermissionMap, error) {
	out, err := r.Retriever.Permissions(ctx, claims, ns, opts...)
	r.mu.Lock()
	var expires time.Time
	if r.remaining > 0 {
		r.remaining--
		if r.remaining == 0 {
			expires, r.fired = r.expires, true
		}
	}
	r.mu.Unlock()
	if !expires.IsZero() {
		select {
		case <-time.After(time.Until(expires) + 20*time.Millisecond):
		case <-ctx.Done():
		}
	}
	return out, err
}

func TestNamespaceParticipationCaptureOwnedMongoHTTP(t *testing.T) {
	ctx := context.Background()
	m := mongofixture.New(t)
	if err := manipmongo.CreateIndex(m, api.NamespaceIdentity, indexes.GetIndexes("a3s", api.Manager())[api.NamespaceIdentity]...); err != nil {
		t.Fatal(err)
	}
	store, err := namespacelifecycle.NewStore(m)
	if err != nil {
		t.Fatal(err)
	}
	native, err := namespacelifecycle.NewNativeNamespaceStore(m)
	if err != nil {
		t.Fatal(err)
	}
	db, err := manipmongo.GetDatabase(m)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC().Truncate(time.Millisecond)
	root := namespacelifecycle.Namespace{ID: bson.NewObjectID().Hex(), Name: "/"}
	marker := "bootstrap:" + root.ID
	prepared, err := namespacelifecycle.PrepareNativeNamespace(api.NewNamespace(), namespacelifecycle.NativeNamespaceIdentity{Namespace: root, Parent: "root", CreatedAt: at, Marker: marker})
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := native.InsertOnce(ctx, prepared)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.BootstrapRoot(ctx, root, marker, evidence.Digest, at); err != nil {
		t.Fatal(err)
	}
	create := func(name string, ancestors []namespacelifecycle.Namespace) namespacelifecycle.State {
		t.Helper()
		ref := namespacelifecycle.Namespace{ID: bson.NewObjectID().Hex(), Name: name}
		binding, source, err := namespacelifecycle.PrepareOwnerNamespace(native, api.NewNamespace(), ref, ancestors, "create:"+ref.ID, at, []string{"hanni"})
		if err != nil {
			t.Fatal(err)
		}
		creator, err := namespacelifecycle.NewCreator(store, source, captureEnrollment{store})
		if err != nil {
			t.Fatal(err)
		}
		s, err := creator.Create(ctx, ref, ancestors, binding)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	parent := create("/parent", []namespacelifecycle.Namespace{root})
	target := create("/parent/target", []namespacelifecycle.Namespace{root, parent.Namespace})
	expected, err := namespacelifecycle.SnapshotEnrollment(target, "hanni", target.Namespace.ID)
	if err != nil {
		t.Fatal(err)
	}
	f := participationAuth(t)
	f.policy.Namespace, f.policy.TargetNamespaces = target.Namespace.Name, []string{target.Namespace.Name}
	f.policy.FlattenedSubject, f.policy.TrustedIssuers = []string{"role=enroller"}, []string{"test-issuer"}
	if err := m.Create(manipulate.NewContext(ctx, manipulate.ContextOptionNamespace(target.Namespace.Name)), f.policy); err != nil {
		t.Fatal(err)
	}
	retriever := permissions.NewRetriever(m)
	delayed := &captureReadDelay{Retriever: retriever}
	f.auth.retriever = delayed
	processor, err := NewNamespaceCaptureProcessor(store, native, f.auth)
	if err != nil {
		t.Fatal(err)
	}
	nativeAuth := authorizer.New(ctx, retriever, nil)
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
		if action, err := nativeAuth.IsAuthorized(b); err != nil || action != bahamut.AuthActionOK {
			http.Error(w, "denied", http.StatusForbidden)
			return
		}
		input := api.NewNamespaceParticipation()
		if err := json.Unmarshal(r.Data, input); err != nil {
			http.Error(w, "invalid", http.StatusUnprocessableEntity)
			return
		}
		if err := input.Validate(); err != nil {
			http.Error(w, "invalid-model", http.StatusUnprocessableEntity)
			return
		}
		b.SetInputData(input)
		if err := processor.ProcessCreate(b); err != nil {
			http.Error(w, "held", http.StatusConflict)
			return
		}
		if err := json.NewEncoder(w).Encode(b.OutputData()); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	rows := func() [][]bson.Raw {
		t.Helper()
		out := make([][]bson.Raw, 0, 2)
		for _, identity := range []elemental.Identity{api.NamespaceLifecycleIdentity, api.NamespaceIdentity} {
			cursor, err := db.Collection(identity.Name).Find(ctx, bson.M{}, options.Find().SetSort(bson.D{{Key: "_id", Value: 1}}))
			if err != nil {
				t.Fatal(err)
			}
			var records []bson.Raw
			if err := cursor.All(ctx, &records); err != nil {
				t.Fatal(err)
			}
			out = append(out, records)
		}
		return out
	}
	call := func(namespace, body, bearer string) (namespaceParticipationResult, int) {
		t.Helper()
		before := rows()
		r, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+"/namespaceparticipations", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Namespace", namespace)
		r.Header.Set("Authorization", "Bearer "+bearer)
		response, err := server.Client().Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close() //nolint:errcheck
		data, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(before, rows()) {
			t.Fatal("capture mutated lifecycle/native rows")
		}
		var out namespaceParticipationResult
		if response.StatusCode == 200 && json.Unmarshal(data, &out) != nil {
			t.Fatal("invalid output", string(data))
		}
		return out, response.StatusCode
	}
	const command = `{"action":"CaptureScope","participant":"hanni"}`
	bearer := f.bearer(t, nil)
	t.Run("ready-exact-source", func(t *testing.T) {
		out, status := call(target.Namespace.Name, command, bearer)
		if status != 200 || out.Granted || !reflect.DeepEqual(out.Snapshot, expected) {
			t.Fatalf("capture: status=%d got=%+v want=%+v", status, out, expected)
		}
		out.Snapshot.Scope.Ancestors[0].ID = strings.Repeat("f", 24)
		again, status := call(target.Namespace.Name, command, bearer)
		if status != 200 || !reflect.DeepEqual(again.Snapshot, expected) {
			t.Fatal("snapshot was not detached")
		}
	})
	for _, tc := range []struct{ name, namespace, body, token string }{
		{"wrong-name", "/absent", command, bearer},
		{"client-id", target.Namespace.Name, `{"action":"CaptureScope","participant":"hanni","namespaceID":"` + target.Namespace.ID + `"}`, bearer},
		{"missing-token", target.Namespace.Name, command, ""},
		{"bad-signature", target.Namespace.Name, command, bearer + "broken"},
		{"duplicate", target.Namespace.Name, `{"action":"CaptureScope","action":"CaptureScope","participant":"hanni"}`, bearer},
		{"case-folded", target.Namespace.Name, `{"Action":"CaptureScope","participant":"hanni"}`, bearer},
		{"flag", target.Namespace.Name, `{"action":"CaptureScope","participant":"hanni","granted":false}`, bearer},
		{"empty-id", target.Namespace.Name, `{"action":"CaptureScope","participant":"hanni","namespaceID":""}`, bearer},
		{"client-operation", target.Namespace.Name, `{"action":"CaptureScope","participant":"hanni","operationID":""}`, bearer},
		{"client-registry", target.Namespace.Name, `{"action":"CaptureScope","participant":"hanni","registryID":""}`, bearer},
		{"client-intent", target.Namespace.Name, `{"action":"CaptureScope","participant":"hanni","deletionIntentID":""}`, bearer},
		{"unknown", target.Namespace.Name, `{"action":"CaptureScope","participant":"hanni","extra":""}`, bearer},
		{"null", target.Namespace.Name, `{"action":"CaptureScope","participant":null}`, bearer},
		{"wrong-participant", target.Namespace.Name, `{"action":"CaptureScope","participant":"other"}`, bearer},
		{"missing-participant", target.Namespace.Name, `{"action":"CaptureScope"}`, bearer},
		{"nested", target.Namespace.Name, `{"action":"CaptureScope","participant":{"name":"hanni"}}`, bearer},
		{"trailing", target.Namespace.Name, command + ` {}`, bearer},
		{"oversized", target.Namespace.Name, command + strings.Repeat(" ", namespaceParticipationMaxBytes), bearer},
		{"restricted-namespace", target.Namespace.Name, command, f.bearer(t, func(idt *token.IdentityToken) { idt.Restrictions = &permissions.Restrictions{Namespace: "/elsewhere"} })},
		{"restricted-resource", target.Namespace.Name, command, f.bearer(t, func(idt *token.IdentityToken) {
			idt.Restrictions = &permissions.Restrictions{Permissions: []string{"namespaces:create"}}
		})},
		{"restricted-network", target.Namespace.Name, command, f.bearer(t, func(idt *token.IdentityToken) {
			idt.Restrictions = &permissions.Restrictions{Networks: []string{"10.0.0.0/8"}}
		})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, status := call(tc.namespace, tc.body, tc.token); status == 200 {
				t.Fatal("invalid capture accepted")
			}
		})
	}
	// Bind, initial guard, then post-owner-read guard; three more guards reach
	// the first native tuple verification. Expiry during the uncached authority
	// read must hold the result even though source reads already succeeded.
	for _, tc := range []struct {
		name  string
		guard int
	}{{"after-owner-read", 3}, {"after-native-read", 6}} {
		t.Run("expires-during-permission-read/"+tc.name, func(t *testing.T) {
			expires := time.Now().Add(2 * time.Second).Truncate(time.Second)
			idt := token.NewIdentityToken(token.Source{Type: "test"})
			idt.Identity = []string{"role=enroller"}
			short, err := idt.JWT(f.key, f.kid, "test-issuer", jwt.ClaimStrings{"test-audience"}, expires, nil)
			if err != nil {
				t.Fatal(err)
			}
			delayed.mu.Lock()
			delayed.remaining, delayed.expires, delayed.fired = tc.guard, expires, false
			delayed.mu.Unlock()
			_, status := call(target.Namespace.Name, command, short)
			delayed.mu.Lock()
			fired := delayed.fired
			delayed.remaining = 0
			delayed.mu.Unlock()
			if status != http.StatusConflict || !fired {
				t.Fatalf("expiry did not hold capture: status=%d delayed=%v", status, fired)
			}
		})
	}
	// Fault injection is confined to this test's owned rows. Each request must
	// leave even the corrupt input rows byte-for-byte unchanged.
	for _, ref := range []namespacelifecycle.Namespace{target.Namespace, parent.Namespace, root} {
		for _, field := range []string{"name", "namespace", "creationmarker", "createtime", "zone", "zhash", "ID", "missing", "owner-missing", "legacy", "closing"} {
			t.Run(ref.Name+"/"+field, func(t *testing.T) {
				collection := db.Collection(api.NamespaceIdentity.Name)
				if field == "legacy" || field == "closing" || field == "owner-missing" {
					collection = db.Collection(api.NamespaceLifecycleIdentity.Name)
				}
				oid, _ := bson.ObjectIDFromHex(ref.ID)
				filter := bson.M{"_id": oid}
				var saved bson.Raw
				if err := collection.FindOne(ctx, filter).Decode(&saved); err != nil {
					t.Fatal(err)
				}
				restore := func() {
					t.Helper()
					if _, err := collection.ReplaceOne(ctx, filter, saved, options.Replace().SetUpsert(true)); err != nil {
						t.Fatal(err)
					}
				}
				defer restore()
				switch field {
				case "ID", "missing", "owner-missing":
					if _, err := collection.DeleteOne(ctx, filter); err != nil {
						t.Fatal(err)
					}
					if field == "ID" {
						var changed bson.D
						if err := bson.Unmarshal(saved, &changed); err != nil {
							t.Fatal(err)
						}
						other := bson.NewObjectID()
						for i := range changed {
							if changed[i].Key == "_id" {
								changed[i].Value = other
							}
						}
						if _, err := collection.InsertOne(ctx, changed); err != nil {
							t.Fatal(err)
						}
						defer func() {
							if _, err := collection.DeleteOne(ctx, bson.M{"_id": other}); err != nil {
								t.Error(err)
							}
						}()
					}
				case "legacy":
					s, err := store.Get(ctx, ref.ID)
					if err != nil {
						t.Fatal(err)
					}
					s.Version, s.Creation = "namespace-lifecycle.v1", nil
					data, err := json.Marshal(s)
					if err != nil {
						t.Fatal(err)
					}
					if _, err := collection.UpdateOne(ctx, filter, bson.M{"$set": bson.M{"data": string(data)}}); err != nil {
						t.Fatal(err)
					}
				case "closing":
					s, err := store.Get(ctx, ref.ID)
					if err != nil {
						t.Fatal(err)
					}
					if ref.Name != "/" {
						intent, err := namespacelifecycle.OwnedDeletionIntent(s, "delete:"+ref.ID)
						if err != nil {
							t.Fatal(err)
						}
						s.Intent = &intent
						s.Deletion = &namespacelifecycle.OwnedDeletion{Acquisitions: make([]string, len(s.Ancestors))}
						for i := range s.Deletion.Acquisitions {
							s.Deletion.Acquisitions[i] = "held"
						}
					}
					// Root cannot legitimately close; corrupt root state must hold too.
					s.Phase = "closing"
					data, err := json.Marshal(s)
					if err != nil {
						t.Fatal(err)
					}
					if _, err := collection.UpdateOne(ctx, filter, bson.M{"$set": bson.M{"data": string(data)}}); err != nil {
						t.Fatal(err)
					}
					if ref.Name != "/" {
						if retained, err := store.Get(ctx, ref.ID); err != nil || retained.Phase != "closing" {
							t.Fatalf("invalid closing fixture: %v", err)
						}
					}
				case "createtime":
					if _, err := collection.UpdateOne(ctx, filter, bson.M{"$set": bson.M{field: at.Add(time.Millisecond)}}); err != nil {
						t.Fatal(err)
					}
				default:
					if _, err := collection.UpdateOne(ctx, filter, bson.M{"$set": bson.M{field: "wrong"}}); err != nil {
						t.Fatal(err)
					}
				}
				if _, status := call(target.Namespace.Name, command, bearer); status == 200 {
					t.Fatal("invalid source captured")
				}
			})
		}
	}
}
