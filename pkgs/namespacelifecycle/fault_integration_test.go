//go:build integration

package namespacelifecycle

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"go.acuvity.ai/a3s/internal/mongofixture"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

func fixtureState(t *testing.T, store *Store, name string) State {
	t.Helper()
	state, err := store.Initialize(context.Background(), Namespace{ID: bson.NewObjectID().Hex(), Name: name}, []Namespace{{ID: "000000000000000000000001", Name: "/"}})
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func fixturePin(state State) Pin {
	return Pin{ID: "create", Kind: "namespace-create", Target: Namespace{ID: bson.NewObjectID().Hex(), Name: state.Namespace.Name + "/child"}, Digest: strings.Repeat("a", 64)}
}

func fixtureIntent() Intent {
	return Intent{ID: "deletion", Digest: strings.Repeat("b", 64), Participants: []string{"hanni"}}
}

func TestUnknownAdmissionRemainsRetainedAfterRestart(t *testing.T) {
	ctx := context.Background()
	m := mongofixture.New(t)
	store, err := NewStore(m)
	if err != nil {
		t.Fatal(err)
	}
	state := fixtureState(t, store, "/unknown")
	pin := fixturePin(state)
	update := store.update
	store.update = func(ctx context.Context, filter, change bson.M) (*mongo.UpdateResult, error) {
		if _, err := update(ctx, filter, change); err != nil {
			return nil, err
		}
		return nil, errors.New("lost acknowledgement")
	}
	if _, granted, err := store.Admit(ctx, state, pin); granted || !errors.Is(err, ErrUnknown) {
		t.Fatalf("unknown grant: %v %v", granted, err)
	}
	store, err = NewStore(m)
	if err != nil {
		t.Fatal(err)
	}
	state, err = store.Get(ctx, state.Namespace.ID)
	if err != nil || len(state.Pins) != 1 {
		t.Fatalf("retained: %+v %v", state, err)
	}
	if _, granted, err := store.Admit(ctx, state, pin); granted || !errors.Is(err, ErrConflict) {
		t.Fatalf("read-back renewed admission: %v %v", granted, err)
	}
	state, changed, err := store.Seal(ctx, state, fixtureIntent())
	if err != nil || !changed {
		t.Fatalf("seal: %v %v", changed, err)
	}
	if _, changed, err := store.Release(ctx, state, pin); changed || !errors.Is(err, ErrPending) {
		t.Fatalf("unknown released: %v %v", changed, err)
	}
	if _, granted, err := store.AttemptDelete(ctx, state); granted || !errors.Is(err, ErrPending) {
		t.Fatalf("unknown drained: %v %v", granted, err)
	}
}

func TestAdmissionAndSealHaveOneWinner(t *testing.T) {
	ctx := context.Background()
	store, err := NewStore(mongofixture.New(t))
	if err != nil {
		t.Fatal(err)
	}
	for i := range 12 {
		state := fixtureState(t, store, "/race-"+bson.NewObjectID().Hex())
		pin := fixturePin(state)
		start := make(chan struct{})
		outcomes := make(chan bool, 2)
		failures := make(chan error, 2)
		var wg sync.WaitGroup
		for _, admit := range []bool{true, false} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				var changed bool
				var err error
				if admit {
					_, changed, err = store.Admit(ctx, state, pin)
				} else {
					_, changed, err = store.Seal(ctx, state, fixtureIntent())
				}
				outcomes <- changed
				failures <- err
			}()
		}
		close(start)
		wg.Wait()
		first, second := <-outcomes, <-outcomes
		if first == second {
			t.Fatalf("round%d: two or zero winners: %v %v", i, first, second)
		}
		for range 2 {
			if err := <-failures; err != nil {
				t.Fatal(err)
			}
		}
		current, err := store.Get(ctx, state.Namespace.ID)
		if err != nil {
			t.Fatal(err)
		}
		if current.Phase == "open" {
			current, _, err = store.Seal(ctx, current, fixtureIntent())
			if err != nil || len(current.Pins) != 1 {
				t.Fatalf("lost accepted pin: %+v %v", current, err)
			}
		} else if len(current.Pins) != 0 {
			t.Fatal("seal winner admitted a later pin")
		}
	}
}

func TestLostDeletionDispatchCannotBeRetried(t *testing.T) {
	ctx := context.Background()
	m := mongofixture.New(t)
	store, err := NewStore(m)
	if err != nil {
		t.Fatal(err)
	}
	state := fixtureState(t, store, "/delete-unknown")
	state, _, err = store.Seal(ctx, state, fixtureIntent())
	if err != nil {
		t.Fatal(err)
	}
	state, _, err = store.RecordDrain(ctx, state, DrainProof{IntentID: state.Intent.ID, NamespaceID: state.Namespace.ID, Participant: "hanni", Digest: strings.Repeat("c", 64)})
	if err != nil {
		t.Fatal(err)
	}
	update := store.update
	store.update = func(ctx context.Context, filter, change bson.M) (*mongo.UpdateResult, error) {
		if _, err := update(ctx, filter, change); err != nil {
			return nil, err
		}
		return nil, errors.New("lost dispatch acknowledgement")
	}
	if _, granted, err := store.AttemptDelete(ctx, state); granted || !errors.Is(err, ErrUnknown) {
		t.Fatalf("unknown delete: %v %v", granted, err)
	}
	store, err = NewStore(m)
	if err != nil {
		t.Fatal(err)
	}
	state, err = store.Get(ctx, state.Namespace.ID)
	if err != nil || state.Phase != "attempted" {
		t.Fatalf("attempt retained: %+v %v", state, err)
	}
	if _, granted, err := store.AttemptDelete(ctx, state); granted || err != nil {
		t.Fatalf("repeat dispatch: %v %v", granted, err)
	}
}

func TestAdmissionReservesRevisionForTerminalProgress(t *testing.T) {
	ctx := context.Background()
	store, err := NewStore(mongofixture.New(t))
	if err != nil {
		t.Fatal(err)
	}
	state := fixtureState(t, store, "/revision-capacity")
	state.Revision = maxRevision - 1
	data, err := encode(state)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := bson.ObjectIDFromHex(state.Namespace.ID)
	if _, err := store.collection.UpdateOne(ctx, bson.M{"_id": id}, bson.M{"$set": bson.M{"revision": state.Revision, "data": data}}); err != nil {
		t.Fatal(err)
	}
	if _, granted, err := store.Admit(ctx, state, fixturePin(state)); granted || !errors.Is(err, ErrPending) {
		t.Fatalf("admission consumed final revision: %v %v", granted, err)
	}
}

func TestSealReservesParticipantAndDeletionProgress(t *testing.T) {
	ctx := context.Background()
	store, err := NewStore(mongofixture.New(t))
	if err != nil {
		t.Fatal(err)
	}
	state := fixtureState(t, store, "/seal-revision")
	state.Revision = maxRevision - 1
	data, err := encode(state)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := bson.ObjectIDFromHex(state.Namespace.ID)
	if _, err := store.collection.UpdateOne(ctx, bson.M{"_id": id}, bson.M{"$set": bson.M{"revision": state.Revision, "data": data}}); err != nil {
		t.Fatal(err)
	}
	if _, changed, err := store.Seal(ctx, state, fixtureIntent()); changed || !errors.Is(err, ErrPending) {
		t.Fatalf("seal consumed drain revision: %v %v", changed, err)
	}
}

func TestAdmittedCapacityReservesTerminalAndDeletionBytes(t *testing.T) {
	ctx := context.Background()
	store, err := NewStore(mongofixture.New(t))
	if err != nil {
		t.Fatal(err)
	}
	state := fixtureState(t, store, "/capacity")
	var pins []Pin
	for i := range MaxPins + 1 {
		pin := fixturePin(state)
		pin.ID = bson.NewObjectID().Hex() + strings.Repeat("x", 104)
		pin.Target.Name = state.Namespace.Name + "/" + strings.Repeat("a", 500)
		next, granted, err := store.Admit(ctx, state, pin)
		if errors.Is(err, ErrPending) {
			break
		}
		if err != nil || !granted {
			t.Fatalf("capacity admission%d: %v %v", i, granted, err)
		}
		state = next
		pins = append(pins, pin)
	}
	if len(pins) == 0 || len(pins) > MaxPins {
		t.Fatalf("invalid admitted capacity%d", len(pins))
	}
	for _, pin := range pins {
		state, _, err = store.RecordTerminal(ctx, state, pin, TerminalProof{Kind: "not-started", ReferenceID: strings.Repeat("r", 128), Digest: strings.Repeat("e", 64)})
		if err != nil {
			t.Fatalf("admitted terminal capacity unavailable: %v", err)
		}
	}
	participants := make([]string, MaxParticipants)
	for i := range participants {
		participants[i] = string(rune('a'+i)) + strings.Repeat("p", 127)
	}
	state, _, err = store.Seal(ctx, state, Intent{ID: strings.Repeat("d", 128), Digest: strings.Repeat("b", 64), Participants: participants})
	if err != nil {
		t.Fatalf("admitted deletion capacity unavailable: %v", err)
	}
	for _, pin := range pins {
		state, _, err = store.Release(ctx, state, pin)
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, participant := range participants {
		state, _, err = store.RecordDrain(ctx, state, DrainProof{IntentID: state.Intent.ID, NamespaceID: state.Namespace.ID, Participant: participant, Digest: strings.Repeat("f", 64)})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestCorruptStoredTypesAndCASAliasesFailClosed(t *testing.T) {
	ctx := context.Background()
	store, err := NewStore(mongofixture.New(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"revision", "zone", "zhash"} {
		t.Run(field, func(t *testing.T) {
			state := fixtureState(t, store, "/corrupt-"+field)
			id, _ := bson.ObjectIDFromHex(state.Namespace.ID)
			raw, err := store.collection.FindOne(ctx, bson.M{"_id": id}).Raw()
			if err != nil {
				t.Fatal(err)
			}
			n, _ := integer(raw.Lookup(field))
			if _, err := store.collection.UpdateOne(ctx, bson.M{"_id": id}, bson.M{"$set": bson.M{field: float64(n)}}); err != nil {
				t.Fatal(err)
			}
			if _, err := store.Get(ctx, state.Namespace.ID); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("numeric alias read: %v", err)
			}
		})
	}
	t.Run("between-read-and-CAS", func(t *testing.T) {
		state := fixtureState(t, store, "/cas-alias")
		id, _ := bson.ObjectIDFromHex(state.Namespace.ID)
		update := store.update
		store.update = func(ctx context.Context, filter, change bson.M) (*mongo.UpdateResult, error) {
			if _, err := store.collection.UpdateOne(ctx, bson.M{"_id": id}, bson.M{"$set": bson.M{"revision": float64(state.Revision)}}); err != nil {
				return nil, err
			}
			return update(ctx, filter, change)
		}
		defer func() { store.update = update }()
		if _, granted, err := store.Admit(ctx, state, fixturePin(state)); granted || err != nil {
			t.Fatalf("alias granted: %v %v", granted, err)
		}
	})
}
