//go:build integration

package namespacelifecycle

import (
	"context"
	"errors"
	"strings"
	"testing"

	"go.acuvity.ai/a3s/internal/mongofixture"
)

func TestDeletionWaitsForRetainedAdmission(t *testing.T) {
	ctx := context.Background()
	store, err := NewStore(mongofixture.New(t))
	if err != nil {
		t.Fatal(err)
	}
	root := Namespace{ID: "000000000000000000000001", Name: "/"}
	ref := Namespace{ID: "000000000000000000000002", Name: "/acme"}
	state, err := store.Initialize(ctx, ref, []Namespace{root})
	if err != nil {
		t.Fatal(err)
	}
	pin := Pin{ID: "create-child", Kind: "namespace-create", Target: Namespace{ID: "000000000000000000000003", Name: "/acme/child"}, Digest: strings.Repeat("a", 64)}
	state, admitted, err := store.Admit(ctx, state, pin)
	if err != nil || !admitted {
		t.Fatalf("admit: %v %v", admitted, err)
	}
	intent := Intent{ID: "delete-acme", Digest: strings.Repeat("b", 64), Participants: []string{"hanni"}}
	state, sealed, err := store.Seal(ctx, state, intent)
	if err != nil || !sealed || len(state.Pins) != 1 {
		t.Fatalf("seal lost admission: %+v %v", state, err)
	}
	if _, granted, err := store.Admit(ctx, state, Pin{ID: "new-child", Kind: pin.Kind, Target: pin.Target, Digest: pin.Digest}); err != nil || granted {
		t.Fatalf("sealed admission: %v %v", granted, err)
	}
	proof := DrainProof{IntentID: intent.ID, NamespaceID: ref.ID, Participant: "hanni", Digest: strings.Repeat("c", 64)}
	if _, _, err := store.RecordDrain(ctx, state, proof); !errors.Is(err, ErrPending) {
		t.Fatalf("drain ignored active pin: %v", err)
	}
	// Trusted owner has durably proved that this exact create never started.
	terminal := TerminalProof{Kind: "not-started", ReferenceID: "create-receipt", Digest: strings.Repeat("d", 64)}
	state, changed, err := store.RecordTerminal(ctx, state, pin, terminal)
	if err != nil || !changed {
		t.Fatalf("terminal: %v %v", changed, err)
	}
	state, changed, err = store.Release(ctx, state, pin)
	if err != nil || !changed {
		t.Fatalf("release: %v %v", changed, err)
	}
	state, changed, err = store.RecordDrain(ctx, state, proof)
	if err != nil || !changed {
		t.Fatalf("drain: %v %v", changed, err)
	}
	state, granted, err := store.AttemptDelete(ctx, state)
	if err != nil || !granted {
		t.Fatalf("deletion dispatch: %v %v", granted, err)
	}
	readback, err := store.Get(ctx, ref.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, granted, err = store.AttemptDelete(ctx, readback); err != nil || granted {
		t.Fatalf("read-back renewed dispatch: %v %v", granted, err)
	}
	state, changed, err = store.ConfirmDeleted(ctx, state)
	if err != nil || !changed {
		t.Fatalf("deleted: %v %v", changed, err)
	}
	if _, granted, err = store.Admit(ctx, state, pin); err != nil || granted {
		t.Fatalf("deleted admission: %v %v", granted, err)
	}
	// A different native ID must not silently reopen a tombstoned name.
	replacement := Namespace{ID: "000000000000000000000004", Name: ref.Name}
	if _, err := store.Initialize(ctx, replacement, []Namespace{root}); !errors.Is(err, ErrConflict) {
		t.Fatalf("same-name replacement bypassed retained fence: %v", err)
	}
}
