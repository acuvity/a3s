//go:build integration

package namespacelifecycle

import (
	"context"
	"errors"
	"testing"
	"time"

	"go.acuvity.ai/a3s/internal/mongofixture"
	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/a3s/pkgs/indexes"
	"go.acuvity.ai/manipulate/manipmongo"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

type unavailableEnrollment struct{ calls int }

func (e *unavailableEnrollment) Enroll(context.Context, State, string) (EnrollmentProof, error) {
	e.calls++
	return EnrollmentProof{}, ErrUnavailable
}
func (*unavailableEnrollment) Observe(context.Context, State, string) (EnrollmentProof, error) {
	return EnrollmentProof{}, ErrNotFound
}

func TestCreatorNativeInsertStaysHeldWithoutParticipantProof(t *testing.T) {
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
	ref := Namespace{ID: bson.NewObjectID().Hex(), Name: "/created"}
	binding, source, err := PrepareOwnerNamespace(native, api.NewNamespace(), ref, []Namespace{root}, "create-live", at, []string{"hanni"})
	if err != nil {
		t.Fatal(err)
	}
	peer := &unavailableEnrollment{}
	creator, err := NewCreator(store, source, peer)
	if err != nil {
		t.Fatal(err)
	}
	inserts := 0
	insert := native.insert
	native.insert = func(ctx context.Context, raw bson.Raw) (*mongo.InsertOneResult, error) {
		inserts++
		return insert(ctx, raw)
	}
	state, err := creator.Create(ctx, ref, []Namespace{root}, binding)
	if !errors.Is(err, ErrPending) || state.Creation == nil || state.Creation.Phase != "applied" || peer.calls != 1 || inserts != 1 {
		t.Fatalf("unproved participant admitted: %+v %v calls=%d inserts=%d", state, err, peer.calls, inserts)
	}
	identity, err := creationNativeIdentity(state)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := native.Observe(ctx, identity); err != nil {
		t.Fatalf("exact native source missing: %v", err)
	}
	parent, err := store.Get(ctx, root.ID)
	if err != nil || len(parent.Pins) != 1 || parent.Pins[0].Terminal != nil {
		t.Fatalf("unknown enrollment released parent: %+v %v", parent, err)
	}
	// Reconstructed owner state can only read existing proof. It cannot repeat
	// native insertion or dispatch another participant enrollment.
	restarted, err := NewStore(m)
	if err != nil {
		t.Fatal(err)
	}
	cold, err := NewCreator(restarted, source, peer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cold.Reconcile(ctx, ref); !errors.Is(err, ErrPending) {
		t.Fatal("cold unknown did not hold", err)
	}
	if _, err := cold.Create(ctx, Namespace{ID: bson.NewObjectID().Hex(), Name: ref.Name}, []Namespace{root}, binding); !errors.Is(err, ErrPending) {
		t.Fatal("duplicate create did not hold", err)
	}
	if inserts != 1 || peer.calls != 1 {
		t.Fatalf("cold recovery dispatched: inserts=%d enrollments=%d", inserts, peer.calls)
	}
}
