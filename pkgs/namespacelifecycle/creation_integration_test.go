//go:build integration

package namespacelifecycle

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"go.acuvity.ai/a3s/internal/mongofixture"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

func TestCreationRequiresSourceAndEnrollmentBeforeReady(t *testing.T) {
	ctx := context.Background()
	store, err := NewStore(mongofixture.New(t))
	if err != nil {
		t.Fatal(err)
	}
	ref := Namespace{ID: bson.NewObjectID().Hex(), Name: "/created"}
	ancestors := []Namespace{{ID: bson.NewObjectID().Hex(), Name: "/"}}
	create := Creation{OperationID: "create-ready", Digest: strings.Repeat("a", 64), CreatedAt: time.Now().UTC().Truncate(time.Millisecond).Format(time.RFC3339Nano), Participants: []string{"hanni"}}
	state, err := store.ReserveCreation(ctx, ref, ancestors, create)
	if err != nil {
		t.Fatal(err)
	}
	state, won, err := store.ClaimCreation(ctx, state)
	if err != nil || !won {
		t.Fatal("claim", err)
	}
	if _, _, err := store.AttemptNativeCreation(ctx, state); !errors.Is(err, ErrPending) {
		t.Fatal("missing ancestor admitted", err)
	}
	state, won, err = store.AttemptCreationAcquisition(ctx, state, 0)
	if err != nil || !won {
		t.Fatal("acquisition", err)
	}
	state, _, err = store.ConfirmCreationAcquisition(ctx, state, 0)
	if err != nil {
		t.Fatal(err)
	}
	state, won, err = store.AttemptNativeCreation(ctx, state)
	if err != nil || !won {
		t.Fatal("native attempt", err)
	}
	if _, won, err := store.AttemptNativeCreation(ctx, state); err != nil || won {
		t.Fatal("duplicate native grant", err)
	}
	digest, err := CreationMarkerDigest(state)
	if err != nil {
		t.Fatal(err)
	}
	state, _, err = store.ConfirmCreationApplied(ctx, state, digest)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.MarkCreationReady(ctx, state); !errors.Is(err, ErrPending) {
		t.Fatal("missing enrollment readied", err)
	}
	state, won, err = store.AttemptCreationEnrollment(ctx, state, "hanni")
	if err != nil || !won {
		t.Fatal("enrollment attempt", err)
	}
	proof := EnrollmentProof{Participant: "hanni", NamespaceID: ref.ID, OperationID: create.OperationID, RegistryID: ref.ID, Digest: strings.Repeat("b", 64)}
	if _, _, err := store.ConfirmCreationEnrollment(ctx, state, proof); !errors.Is(err, ErrPending) {
		t.Fatal("unclaimed recipient confirmed", err)
	}
	state, won, err = store.ClaimCreationEnrollment(ctx, state, "hanni", ref.ID)
	if err != nil || !won {
		t.Fatal("recipient claim", err)
	}
	if _, won, err := store.ClaimCreationEnrollment(ctx, state, "hanni", ref.ID); err != nil || won {
		t.Fatal("recipient claim renewed", err)
	}
	state, _, err = store.ConfirmCreationEnrollment(ctx, state, proof)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.MarkCreationReady(ctx, state); !errors.Is(err, ErrPending) {
		t.Fatal("unreleased ancestor readied", err)
	}
	state, _, err = store.RecordCreationPinTerminal(ctx, state, 0)
	if err != nil {
		t.Fatal(err)
	}
	state, _, err = store.RecordCreationPinReleased(ctx, state, 0)
	if err != nil {
		t.Fatal(err)
	}
	state, won, err = store.MarkCreationReady(ctx, state)
	if err != nil || !won || state.Phase != "open" {
		t.Fatal("ready", err)
	}
	if _, won, err := store.ClaimCreation(ctx, state); err != nil || won {
		t.Fatal("ready receipt renewed creation", err)
	}
}

func TestCreationClaimCannotBeRecoveredFromReadBack(t *testing.T) {
	ctx := context.Background()
	m := mongofixture.New(t)
	store, err := NewStore(m)
	if err != nil {
		t.Fatal(err)
	}
	ref := Namespace{ID: bson.NewObjectID().Hex(), Name: "/created"}
	ancestors := []Namespace{{ID: bson.NewObjectID().Hex(), Name: "/"}}
	create := Creation{OperationID: "create-1", Digest: strings.Repeat("a", 64), CreatedAt: time.Now().UTC().Truncate(time.Millisecond).Format(time.RFC3339Nano), Participants: []string{"hanni"}}
	state, err := store.ReserveCreation(ctx, ref, ancestors, create)
	if err != nil {
		t.Fatal(err)
	}
	if _, won, err := store.Admit(ctx, state, Pin{ID: "new-child", Kind: "namespace-create", Target: Namespace{ID: bson.NewObjectID().Hex(), Name: "/created/child"}, Digest: create.Digest}); won || err != nil {
		t.Fatalf("forming namespace admitted work: %v %v", won, err)
	}
	if _, _, err := store.Seal(ctx, state, fixtureIntent()); !errors.Is(err, ErrPending) {
		t.Fatalf("forming namespace deletion: %v", err)
	}
	update := store.update
	store.update = func(ctx context.Context, filter, change bson.M) (*mongo.UpdateResult, error) {
		if _, err := update(ctx, filter, change); err != nil {
			return nil, err
		}
		return nil, errors.New("lost owner acknowledgement")
	}
	if _, won, err := store.ClaimCreation(ctx, state); won || !errors.Is(err, ErrUnknown) {
		t.Fatalf("ambiguous owner granted: %v %v", won, err)
	}
	restarted, err := NewStore(m)
	if err != nil {
		t.Fatal(err)
	}
	state, err = restarted.Get(ctx, ref.ID)
	if err != nil || state.Creation == nil || state.Creation.Phase != "claimed" {
		t.Fatalf("creation not retained: %+v %v", state, err)
	}
	if _, won, err := restarted.ClaimCreation(ctx, state); won || err != nil {
		t.Fatalf("readback renewed owner: %v %v", won, err)
	}
}
