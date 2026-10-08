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
)

// Metadata fixture only: real native/participant proofs belong to the owner
// orchestration integration, not to this low-level state transition test.
func readyOwnerMetadata(t *testing.T, store *Store) State {
	t.Helper()
	state := State{Version: "namespace-lifecycle.v2", Namespace: Namespace{ID: bson.NewObjectID().Hex(), Name: "/owned"}, Ancestors: []Namespace{{ID: bson.NewObjectID().Hex(), Name: "/"}}, Revision: 1, Phase: "open", Pins: []Pin{}, Drains: []DrainProof{}}
	state.Creation = &Creation{Origin: "create", OperationID: "creation", Digest: strings.Repeat("a", 64), CreatedAt: time.Now().UTC().Truncate(time.Millisecond).Format(time.RFC3339Nano), Participants: []string{"hanni"}, Phase: "ready", Acquisitions: []string{"released"}, Enrollments: []CreationEnrollment{{Participant: "hanni", Phase: "confirmed", RegistryID: state.Namespace.ID, Digest: strings.Repeat("b", 64)}}}
	digest, err := CreationMarkerDigest(state)
	if err != nil {
		t.Fatal(err)
	}
	state.Creation.ApplicationDigest = digest
	state, err = store.initialize(context.Background(), state)
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func TestOwnedDeletionRequiresOneClaimAncestorsDrainAndNativeResult(t *testing.T) {
	ctx := context.Background()
	store, err := NewStore(mongofixture.New(t))
	if err != nil {
		t.Fatal(err)
	}
	state := readyOwnerMetadata(t, store)
	intent, err := OwnedDeletionIntent(state, "delete-owned")
	if err != nil {
		t.Fatal(err)
	}
	state, won, err := store.BeginOwnedDeletion(ctx, state, intent)
	if err != nil || !won {
		t.Fatal("owner deletion claim", err)
	}
	if _, won, err := store.BeginOwnedDeletion(ctx, state, intent); err != nil || won {
		t.Fatal("deletion claim renewed", err)
	}
	pin := Pin{ID: "new-child", Kind: "namespace-create", Target: Namespace{ID: bson.NewObjectID().Hex(), Name: "/owned/child"}, Digest: strings.Repeat("c", 64)}
	if _, won, err := store.Admit(ctx, state, pin); err != nil || won {
		t.Fatal("deletion intent admitted new topology", err)
	}
	if _, _, err := store.SealOwnedDeletion(ctx, state); !errors.Is(err, ErrPending) {
		t.Fatal("unheld ancestor sealed", err)
	}
	state, won, err = store.AttemptDeletionAcquisition(ctx, state, 0)
	if err != nil || !won {
		t.Fatal(err)
	}
	state, _, err = store.ConfirmDeletionAcquisition(ctx, state, 0)
	if err != nil {
		t.Fatal(err)
	}
	state, won, err = store.SealOwnedDeletion(ctx, state)
	if err != nil || !won {
		t.Fatal(err)
	}
	if _, _, err := store.AttemptDelete(ctx, state); !errors.Is(err, ErrPending) {
		t.Fatal("undrained deletion", err)
	}
	state, _, err = store.RecordDrain(ctx, state, DrainProof{IntentID: intent.ID, NamespaceID: state.Namespace.ID, Participant: "hanni", Digest: strings.Repeat("d", 64)})
	if err != nil {
		t.Fatal(err)
	}
	state, won, err = store.AttemptDelete(ctx, state)
	if err != nil || !won {
		t.Fatal(err)
	}
	if _, won, err := store.AttemptDelete(ctx, state); err != nil || won {
		t.Fatal("native delete renewed", err)
	}
	if _, _, err := store.ConfirmDeleted(ctx, state); !errors.Is(err, ErrPending) {
		t.Fatal("missing owned native result confirmed", err)
	}
	result, err := OwnedDeletionResultDigest(state)
	if err != nil {
		t.Fatal(err)
	}
	state, won, err = store.RecordOwnedDeletionApplied(ctx, state, result)
	if err != nil || !won || state.Phase != "deleted" {
		t.Fatal("native result", err)
	}
	state, _, err = store.RecordDeletionPinTerminal(ctx, state, 0)
	if err != nil {
		t.Fatal(err)
	}
	state, _, err = store.RecordDeletionPinReleased(ctx, state, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, won, err := store.BeginOwnedDeletion(ctx, state, intent); err != nil || won {
		t.Fatal("completed delete renewed", err)
	}
}
