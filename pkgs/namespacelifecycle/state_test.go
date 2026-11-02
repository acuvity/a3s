package namespacelifecycle

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func validFixture() State {
	return State{Version: "namespace-lifecycle.v1", Namespace: Namespace{ID: "000000000000000000000002", Name: "/acme"}, Ancestors: []Namespace{{ID: "000000000000000000000001", Name: "/"}}, Revision: 1, Phase: "open", Pins: []Pin{}, Drains: []DrainProof{}}
}

func TestInvalidOwnerBindingsAreRejectedBeforeStorage(t *testing.T) {
	var store *Store
	ctx := context.Background()
	for name, mutate := range map[string]func(*State){
		"empty":                  func(s *State) { *s = State{} },
		"version":                func(s *State) { s.Version = "next" },
		"zero-id":                func(s *State) { s.Namespace.ID = strings.Repeat("0", 24) },
		"uppercase-id":           func(s *State) { s.Namespace.ID = strings.Repeat("A", 24) },
		"relative":               func(s *State) { s.Namespace.Name = "acme" },
		"alias":                  func(s *State) { s.Namespace.Name = "/a/../acme" },
		"slash":                  func(s *State) { s.Namespace.Name = "/acme/" },
		"missing-root":           func(s *State) { s.Ancestors = nil },
		"wrong-parent":           func(s *State) { s.Ancestors[0].Name = "/other" },
		"same-incarnation":       func(s *State) { s.Ancestors[0].ID = s.Namespace.ID },
		"revision-zero":          func(s *State) { s.Revision = 0 },
		"revision-bound":         func(s *State) { s.Revision = maxRevision + 1 },
		"closing-without-intent": func(s *State) { s.Phase = "closing" },
		"unknown-phase":          func(s *State) { s.Phase = "expired" },
	} {
		t.Run(name, func(t *testing.T) {
			s := validFixture()
			mutate(&s)
			if _, _, err := store.AttemptDelete(ctx, s); !errors.Is(err, ErrInvalid) {
				t.Fatalf("invalid binding reached storage: %v", err)
			}
		})
	}
	root := validFixture()
	root.Namespace = root.Ancestors[0]
	root.Ancestors = []Namespace{}
	if _, _, err := store.Seal(ctx, root, Intent{ID: "delete-root", Digest: strings.Repeat("a", 64), Participants: []string{"hanni"}}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("root deletion accepted: %v", err)
	}
	if _, err := store.Initialize(ctx, validFixture().Namespace, validFixture().Ancestors); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("nil store: %v", err)
	}
}

func TestPersistedStateMustBeCanonicalAndOwned(t *testing.T) {
	state := validFixture()
	encoded, err := encode(state)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	decoded.Ancestors[0].Name = "/other"
	if state.Ancestors[0].Name != "/" {
		t.Fatal("decoded state aliases original")
	}
	for _, bad := range []string{
		"null", "{}", encoded + encoded, " " + encoded, encoded + " ",
		strings.Replace(encoded, `"revision":1`, `"revision":1.0`, 1),
		strings.Replace(encoded, `"revision":1`, `"revision":1,"revision":1`, 1),
		strings.Replace(encoded, `"revision":1`, `"Revision":1`, 1),
		strings.Replace(encoded, `"phase":"open"`, `"phase":"deleted"`, 1),
		strings.Replace(encoded, `"version":`, `"unknown":false,"version":`, 1),
		strings.Repeat("x", MaxStateBytes+1),
	} {
		if _, err := decode(bad); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("accepted noncanonical state: %v", err)
		}
	}
}

func TestParticipantAndTerminalProofsStayScoped(t *testing.T) {
	var store *Store
	ctx := context.Background()
	state := validFixture()
	state.Phase = "closing"
	state.Intent = &Intent{ID: "deletion", Digest: strings.Repeat("a", 64), Participants: []string{"hanni"}}
	for _, proof := range []DrainProof{
		{},
		{IntentID: "other", NamespaceID: state.Namespace.ID, Participant: "hanni", Digest: strings.Repeat("a", 64)},
		{IntentID: state.Intent.ID, NamespaceID: state.Ancestors[0].ID, Participant: "hanni", Digest: strings.Repeat("a", 64)},
		{IntentID: state.Intent.ID, NamespaceID: state.Namespace.ID, Participant: "other", Digest: strings.Repeat("a", 64)},
		{IntentID: state.Intent.ID, NamespaceID: state.Namespace.ID, Participant: "hanni", Digest: "unverified"},
	} {
		if _, _, err := store.RecordDrain(ctx, state, proof); !errors.Is(err, ErrInvalid) {
			t.Fatalf("unscoped proof: %v", err)
		}
	}
	if _, _, err := store.AttemptDelete(ctx, state); !errors.Is(err, ErrPending) {
		t.Fatalf("missing participant drained: %v", err)
	}
	pin := Pin{ID: "create", Kind: "namespace-create", Target: Namespace{ID: "000000000000000000000003", Name: "/acme/child"}, Digest: strings.Repeat("b", 64)}
	state.Pins = []Pin{pin}
	if _, _, err := store.RecordTerminal(ctx, state, pin, TerminalProof{Kind: "timeout", ReferenceID: "unknown", Digest: pin.Digest}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("timeout became terminal: %v", err)
	}
	if _, _, err := store.Release(ctx, state, pin); !errors.Is(err, ErrPending) {
		t.Fatalf("unconfirmed release: %v", err)
	}
}
