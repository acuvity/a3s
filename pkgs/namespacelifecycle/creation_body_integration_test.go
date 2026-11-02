//go:build integration

package namespacelifecycle

import (
	"context"
	"errors"
	"testing"
	"time"

	legacybson "github.com/globalsign/mgo/bson"
	"go.acuvity.ai/a3s/internal/mongofixture"
	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/a3s/pkgs/indexes"
	"go.acuvity.ai/manipulate/manipmongo"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// This callback executes synchronously inside json.Marshal. No goroutine,
// concurrent access, caller write after prepare, or unsupported data race.
type mutatingCreationOpaque struct{ target *api.Namespace }

func (x mutatingCreationOpaque) MarshalJSON() ([]byte, error) {
	x.target.Description = "body-not-in-request-digest"
	return []byte(`{"value":"same"}`), nil
}
func (mutatingCreationOpaque) GetBSON() (any, error) {
	return map[string]any{"value": "same"}, nil
}

// Even without a side effect, two supported serializers can disagree.
type splitCreationOpaque struct{}

func (splitCreationOpaque) MarshalJSON() ([]byte, error) { return []byte(`{"value":"json"}`), nil }
func (splitCreationOpaque) GetBSON() (any, error)        { return map[string]any{"value": "bson"}, nil }

func TestPreparedCreationBindsNormalizedBody(t *testing.T) {
	for _, tc := range []string{"synchronous-mutation", "different-serializers"} {
		t.Run(tc, func(t *testing.T) {
			input := api.NewNamespace()
			input.Description = "original"
			control := api.NewNamespace()
			control.Description = "original"
			if tc == "synchronous-mutation" {
				input.Opaque = map[string]any{"x": mutatingCreationOpaque{input}}
				control.Opaque = map[string]any{"x": map[string]any{"value": "same"}}
			} else {
				input.Opaque = map[string]any{"x": splitCreationOpaque{}}
				control.Opaque = map[string]any{"x": map[string]any{"value": "json"}}
			}
			ref := Namespace{ID: "000000000000000000000002", Name: "/review"}
			root := Namespace{ID: "000000000000000000000001", Name: "/"}
			at := time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC)
			binding, source, err := PrepareOwnerNamespace(&NativeNamespaceStore{}, input, ref, []Namespace{root}, "review", at, []string{"hanni"})
			if err != nil {
				t.Fatal(err)
			}
			before, _, err := PrepareOwnerNamespace(&NativeNamespaceStore{}, control, ref, []Namespace{root}, "review", at, []string{"hanni"})
			if err != nil {
				t.Fatal(err)
			}
			if binding.Digest != before.Digest {
				t.Fatal("reproduction did not preserve original logical digest")
			}
			owned := api.NewNamespace()
			if err := legacybson.Unmarshal(source.prepared.raw, owned); err != nil {
				t.Fatal(err)
			}
			after, _, err := PrepareOwnerNamespace(&NativeNamespaceStore{}, owned, ref, []Namespace{root}, "review", at, []string{"hanni"})
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("original digest=%s actual owned-body digest=%s owned description=%q opaque=%#v", binding.Digest, after.Digest, owned.Description, owned.Opaque)
			if binding.Digest != after.Digest {
				t.Errorf("retained request digest does not bind the prepared native body")
			}
		})
	}
}

func TestActualCreationBindsNormalizedBody(t *testing.T) {
	ctx := context.Background()
	m := mongofixture.New(t)
	if err := manipmongo.CreateIndex(m, api.NamespaceIdentity, indexes.GetIndexes("a3s", api.Manager())[api.NamespaceIdentity]...); err != nil {
		t.Fatal(err)
	}
	native, err := NewNativeNamespaceStore(m)
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(m)
	if err != nil {
		t.Fatal(err)
	}
	root := Namespace{ID: bson.NewObjectID().Hex(), Name: "/"}
	at := time.Now().UTC().Truncate(time.Millisecond)
	marker := "bootstrap:" + root.ID
	prepared, err := PrepareNativeNamespace(api.NewNamespace(), NativeNamespaceIdentity{Namespace: root, Parent: "root", CreatedAt: at, Marker: marker})
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
	ref := Namespace{ID: bson.NewObjectID().Hex(), Name: "/review"}
	input := api.NewNamespace()
	input.Description = "original"
	input.Opaque = map[string]any{"x": mutatingCreationOpaque{input}}
	binding, source, err := PrepareOwnerNamespace(native, input, ref, []Namespace{root}, "review-insert", at, []string{"hanni"})
	if err != nil {
		t.Fatal(err)
	}
	// Mutation after preparation must not affect the owned insert, separately
	// from the earlier callback bug. These are synchronous caller writes.
	input.Description = "late-caller-value"
	input.Opaque = map[string]any{"late": true}
	peer := &unavailableEnrollment{}
	creator, err := NewCreator(store, source, peer)
	if err != nil {
		t.Fatal(err)
	}
	state, err := creator.Create(ctx, ref, []Namespace{root}, binding)
	if !errors.Is(err, ErrPending) || state.Creation == nil || state.Creation.Phase != "applied" || peer.calls != 1 {
		t.Fatalf("expected one actual insert and Held on unavailable participant: state=%+v error=%v calls=%d", state, err, peer.calls)
	}
	oid, _ := bson.ObjectIDFromHex(ref.ID)
	var raw bson.Raw
	if err := native.schema.collection.FindOne(ctx, bson.M{"_id": oid}).Decode(&raw); err != nil {
		t.Fatal(err)
	}
	stored := api.NewNamespace()
	if err := legacybson.Unmarshal(raw, stored); err != nil {
		t.Fatal(err)
	}
	if stored.Description != "original" {
		t.Fatalf("unexpected inserted body: %+v", stored)
	}
	expected, err := creationNativeIdentity(state)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := native.Observe(ctx, expected); err != nil {
		t.Fatalf("native marker rejected mismatch: %v", err)
	}
	actual, _, err := PrepareOwnerNamespace(native, stored, ref, []Namespace{root}, "review-insert", at, []string{"hanni"})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("actual Mongo insert accepted private marker; lifecycle=%s/%s retained digest=%s inserted-body digest=%s; unavailable peer is NOT positive cross-repo proof", state.Phase, state.Creation.Phase, state.Creation.Digest, actual.Digest)
	if state.Creation.Digest != actual.Digest {
		t.Errorf("actual native inserted body does not match retained request digest")
	}
}
