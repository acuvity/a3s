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

func TestRecipientClaimLostAcknowledgementDoesNotRenewEnrollment(t *testing.T) {
	ctx := context.Background()
	m := mongofixture.New(t)
	store, err := NewStore(m)
	if err != nil {
		t.Fatal(err)
	}
	ref := Namespace{ID: bson.NewObjectID().Hex(), Name: "/recipient"}
	ancestors := []Namespace{{ID: bson.NewObjectID().Hex(), Name: "/"}}
	binding := Creation{OperationID: "create-recipient", Digest: strings.Repeat("a", 64), CreatedAt: time.Now().UTC().Truncate(time.Millisecond).Format(time.RFC3339Nano), Participants: []string{"hanni"}}
	state, err := store.ReserveCreation(ctx, ref, ancestors, binding)
	if err != nil {
		t.Fatal(err)
	}
	state, _, err = store.ClaimCreation(ctx, state)
	if err != nil {
		t.Fatal(err)
	}
	state, _, err = store.AttemptCreationAcquisition(ctx, state, 0)
	if err != nil {
		t.Fatal(err)
	}
	state, _, err = store.ConfirmCreationAcquisition(ctx, state, 0)
	if err != nil {
		t.Fatal(err)
	}
	state, _, err = store.AttemptNativeCreation(ctx, state)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := CreationMarkerDigest(state)
	if err != nil {
		t.Fatal(err)
	}
	state, _, err = store.ConfirmCreationApplied(ctx, state, digest)
	if err != nil {
		t.Fatal(err)
	}
	state, _, err = store.AttemptCreationEnrollment(ctx, state, "hanni")
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := SnapshotEnrollment(state, "hanni", ref.ID)
	if err != nil || snapshot.Phase != "attempted" {
		t.Fatalf("snapshot: %+v %v", snapshot, err)
	}
	snapshot.Scope.Ancestors[0].Name = "/wrong"
	if state.Ancestors[0].Name != "/" {
		t.Fatal("snapshot aliases owner state")
	}
	if _, won, err := store.ClaimCreationEnrollment(ctx, state, "hanni", bson.NewObjectID().Hex()); won || !errors.Is(err, ErrInvalid) {
		t.Fatal("wrong registry bound", err)
	}
	update := store.update
	store.update = func(ctx context.Context, filter, change bson.M) (*mongo.UpdateResult, error) {
		if _, err := update(ctx, filter, change); err != nil {
			return nil, err
		}
		return nil, errors.New("lost recipient acknowledgement")
	}
	if _, won, err := store.ClaimCreationEnrollment(ctx, state, "hanni", ref.ID); won || !errors.Is(err, ErrUnknown) {
		t.Fatalf("ambiguous claim granted: %v %v", won, err)
	}
	restarted, err := NewStore(m)
	if err != nil {
		t.Fatal(err)
	}
	state, err = restarted.Get(ctx, ref.ID)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err = SnapshotEnrollment(state, "hanni", ref.ID)
	if err != nil || snapshot.Phase != "claimed" {
		t.Fatalf("claim not retained: %+v %v", snapshot, err)
	}
	if _, won, err := restarted.ClaimCreationEnrollment(ctx, state, "hanni", ref.ID); err != nil || won {
		t.Fatalf("readback renewed recipient grant: %v %v", won, err)
	}
	if _, _, err := restarted.MarkCreationReady(ctx, state); !errors.Is(err, ErrPending) {
		t.Fatal("unknown enrollment became ready", err)
	}
}
