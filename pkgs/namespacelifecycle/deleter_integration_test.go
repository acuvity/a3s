//go:build integration

package namespacelifecycle

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"go.acuvity.ai/a3s/internal/mongofixture"
	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/a3s/pkgs/indexes"
	"go.acuvity.ai/manipulate/manipmongo"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

// This participant is only a deterministic port fixture. It is NOT evidence
// of real Hanni enrollment, writer exclusion or cross-repository drain.
type ownerParticipantFixture struct {
	store    *Store
	proof    EnrollmentProof
	held     bool
	prepares int
}

func (p *ownerParticipantFixture) Enroll(ctx context.Context, state State, participant string) (EnrollmentProof, error) {
	current, err := p.store.Get(ctx, state.Namespace.ID)
	if err != nil {
		return EnrollmentProof{}, err
	}
	_, won, err := p.store.ClaimCreationEnrollment(ctx, current, participant, state.Namespace.ID)
	if err != nil || !won {
		return EnrollmentProof{}, ErrPending
	}
	p.proof = EnrollmentProof{Participant: participant, NamespaceID: state.Namespace.ID, OperationID: state.Creation.OperationID, RegistryID: state.Namespace.ID, Digest: strings.Repeat("d", 64)}
	return p.proof, nil
}
func (p *ownerParticipantFixture) Observe(context.Context, State, string) (EnrollmentProof, error) {
	if p.proof.RegistryID == "" {
		return EnrollmentProof{}, ErrNotFound
	}
	return p.proof, nil
}

type ownerDrainFixture struct{ owner *ownerParticipantFixture }

func (p ownerDrainFixture) Prepare(ctx context.Context, state State, participant string) (DrainProof, error) {
	p.owner.prepares++
	return p.Observe(ctx, state, participant)
}
func (p ownerDrainFixture) Observe(_ context.Context, state State, participant string) (DrainProof, error) {
	if p.owner.held {
		return DrainProof{}, ErrPending
	}
	return DrainProof{Participant: participant, NamespaceID: state.Namespace.ID, IntentID: state.Intent.ID, Digest: strings.Repeat("e", 64)}, nil
}

func ownedNativeLeaf(t *testing.T) (*Store, *NativeNamespaceStore, State, *ownerParticipantFixture) {
	t.Helper()
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
	ref := Namespace{ID: bson.NewObjectID().Hex(), Name: "/owned"}
	binding, source, err := PrepareOwnerNamespace(native, api.NewNamespace(), ref, []Namespace{root}, "create-leaf", at, []string{"hanni"})
	if err != nil {
		t.Fatal(err)
	}
	peer := &ownerParticipantFixture{store: store}
	creator, err := NewCreator(store, source, peer)
	if err != nil {
		t.Fatal(err)
	}
	state, err := creator.Create(ctx, ref, []Namespace{root}, binding)
	if err != nil || state.Creation.Phase != "ready" {
		t.Fatalf("owner source fixture: %+v %v", state, err)
	}
	return store, native, state, peer
}

func TestLeafDeleteHoldsThenClaimsUnattemptedNativeStageOnce(t *testing.T) {
	store, native, state, peer := ownedNativeLeaf(t)
	ctx := context.Background()
	source, err := NewNativeDeletionSource(native)
	if err != nil {
		t.Fatal(err)
	}
	deleter, err := NewDeleter(store, source, ownerDrainFixture{peer})
	if err != nil {
		t.Fatal(err)
	}
	deletes := 0
	remove := native.delete
	native.delete = func(ctx context.Context, filter bson.M) (*mongo.DeleteResult, error) {
		deletes++
		return remove(ctx, filter)
	}
	peer.held = true
	held, err := deleter.Delete(ctx, state.Namespace, "delete-leaf")
	if !errors.Is(err, ErrPending) || held.Phase != "closing" || deletes != 0 || peer.prepares != 1 {
		t.Fatalf("unproved deletion: %+v %v writes=%d", held, err, deletes)
	}
	if err := source.Verify(ctx, state); err != nil {
		t.Fatal("held namespace missing", err)
	}
	peer.held = false
	if _, err := deleter.Reconcile(ctx, state.Namespace); !errors.Is(err, ErrPending) || deletes != 0 {
		t.Fatalf("cold reconciliation deleted: %v %d", err, deletes)
	}
	deleted, err := deleter.Delete(ctx, state.Namespace, "new-request-id")
	if err != nil || deleted.Phase != "deleted" || deletes != 1 || peer.prepares != 1 {
		t.Fatalf("fresh native stage: %+v %v deletes=%d prepares=%d", deleted, err, deletes, peer.prepares)
	}
	if _, err := deleter.Delete(ctx, state.Namespace, "another-request"); err != nil || deletes != 1 {
		t.Fatalf("deleted replay: %v count=%d", err, deletes)
	}
	parent, err := store.Get(ctx, state.Ancestors[0].ID)
	if err != nil || len(parent.Pins) != 0 {
		t.Fatal("terminal deletion did not settle ancestor", err)
	}
	if err := source.Verify(ctx, state); !errors.Is(err, ErrNotFound) {
		t.Fatal("native row retained", err)
	}
}

func TestLeafDeleteUnknownAcknowledgementNeverRedispatches(t *testing.T) {
	store, native, state, peer := ownedNativeLeaf(t)
	ctx := context.Background()
	source, err := NewNativeDeletionSource(native)
	if err != nil {
		t.Fatal(err)
	}
	deleter, err := NewDeleter(store, source, ownerDrainFixture{peer})
	if err != nil {
		t.Fatal(err)
	}
	deletes := 0
	remove := native.delete
	native.delete = func(ctx context.Context, filter bson.M) (*mongo.DeleteResult, error) {
		deletes++
		if _, err := remove(ctx, filter); err != nil {
			return nil, err
		}
		return nil, errors.New("lost native deletion acknowledgement")
	}
	if _, err := deleter.Delete(ctx, state.Namespace, "delete-unknown"); !errors.Is(err, ErrUnknown) {
		t.Fatal("unknown deletion confirmed", err)
	}
	if _, err := deleter.Delete(ctx, state.Namespace, "retry"); !errors.Is(err, ErrPending) {
		t.Fatal("unknown retry", err)
	}
	if _, err := deleter.Reconcile(ctx, state.Namespace); !errors.Is(err, ErrPending) {
		t.Fatal("absence became terminal proof", err)
	}
	if deletes != 1 {
		t.Fatalf("native delete count=%d", deletes)
	}
	retained, err := store.Get(ctx, state.Namespace.ID)
	if err != nil || retained.Phase != "attempted" || retained.Deletion.ResultDigest != "" {
		t.Fatalf("unknown result lost: %+v %v", retained, err)
	}
	parent, err := store.Get(ctx, state.Ancestors[0].ID)
	if err != nil || len(parent.Pins) != 1 {
		t.Fatal("unknown native write released ancestor", err)
	}
}
