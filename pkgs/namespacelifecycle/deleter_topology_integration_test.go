//go:build integration

package namespacelifecycle

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"go.acuvity.ai/a3s/pkgs/api"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

func ownedNativeChild(t *testing.T, store *Store, native *NativeNamespaceStore, parent State) (State, *ownerParticipantFixture) {
	t.Helper()
	ref := Namespace{ID: bson.NewObjectID().Hex(), Name: parent.Namespace.Name + "/child"}
	ancestors := append(append([]Namespace(nil), parent.Ancestors...), parent.Namespace)
	binding, source, err := PrepareOwnerNamespace(native, api.NewNamespace(), ref, ancestors, "create-child", time.Now(), []string{"hanni"})
	if err != nil {
		t.Fatal(err)
	}
	peer := &ownerParticipantFixture{store: store}
	creator, err := NewCreator(store, source, peer)
	if err != nil {
		t.Fatal(err)
	}
	child, err := creator.Create(context.Background(), ref, ancestors, binding)
	if err != nil || child.Creation.Phase != "ready" {
		t.Fatalf("owned child: %+v %v", child, err)
	}
	return child, peer
}

func lifecycleSnapshot(t *testing.T, store *Store, refs ...Namespace) []State {
	t.Helper()
	states := make([]State, len(refs))
	for i, ref := range refs {
		var err error
		states[i], err = store.Get(context.Background(), ref.ID)
		if err != nil {
			t.Fatal(err)
		}
	}
	return states
}

func nativeSnapshot(t *testing.T, native *NativeNamespaceStore, refs ...Namespace) []bson.Raw {
	t.Helper()
	rows := make([]bson.Raw, len(refs))
	for i, ref := range refs {
		oid, err := bson.ObjectIDFromHex(ref.ID)
		if err != nil {
			t.Fatal(err)
		}
		if err := native.schema.collection.FindOne(context.Background(), bson.M{"_id": oid}).Decode(&rows[i]); err != nil {
			t.Fatal(err)
		}
	}
	return rows
}

func TestNonleafDeleteRefusalPreservesOwnedChildDeletion(t *testing.T) {
	store, native, parent, peer := ownedNativeLeaf(t)
	child, childPeer := ownedNativeChild(t, store, native, parent)
	ctx := context.Background()
	source, err := NewNativeDeletionSource(native)
	if err != nil {
		t.Fatal(err)
	}
	deleter, err := NewDeleter(store, source, ownerDrainFixture{peer})
	if err != nil {
		t.Fatal(err)
	}
	refs := append(append([]Namespace(nil), parent.Ancestors...), parent.Namespace, child.Namespace)
	before := lifecycleSnapshot(t, store, refs...)
	rows := nativeSnapshot(t, native, refs...)
	deletes := 0
	remove := native.delete
	native.delete = func(ctx context.Context, filter bson.M) (*mongo.DeleteResult, error) {
		deletes++
		return remove(ctx, filter)
	}
	refused, err := deleter.Delete(ctx, parent.Namespace, "delete-nonleaf")
	if !errors.Is(err, ErrPending) {
		t.Fatalf("nonleaf refusal: %+v %v", refused, err)
	}
	if !reflect.DeepEqual(refused, before[len(before)-2]) || !reflect.DeepEqual(lifecycleSnapshot(t, store, refs...), before) {
		t.Errorf("nonleaf refusal consumed lifecycle state: phase=%s intent=%+v deletion=%+v", refused.Phase, refused.Intent, refused.Deletion)
	}
	if !reflect.DeepEqual(nativeSnapshot(t, native, refs...), rows) || deletes != 0 || peer.prepares != 0 {
		t.Fatalf("nonleaf refusal changed native rows or prepared participants: deletes=%d prepares=%d", deletes, peer.prepares)
	}
	// This is a separate, currently authorized owned leaf invocation, not a
	// recursive delete or permission derived from the parent's refusal.
	childDeleter, err := NewDeleter(store, source, ownerDrainFixture{childPeer})
	if err != nil {
		t.Fatal(err)
	}
	deleted, err := childDeleter.Delete(ctx, child.Namespace, "delete-child")
	if err != nil || deleted.Phase != "deleted" || deletes != 1 || childPeer.prepares != 1 {
		t.Fatalf("owned child deletion blocked after nonleaf refusal: phase=%s deletion=%+v err=%v deletes=%d prepares=%d", deleted.Phase, deleted.Deletion, err, deletes, childPeer.prepares)
	}
	if err := source.Verify(ctx, child); !errors.Is(err, ErrNotFound) {
		t.Fatal("deleted child native row retained", err)
	}
	for _, retained := range lifecycleSnapshot(t, store, refs[:len(refs)-1]...) {
		if retained.Phase != "open" || retained.Intent != nil || retained.Deletion != nil || len(retained.Pins) != 0 {
			t.Fatalf("child deletion did not settle without claiming its ancestors: %+v", retained)
		}
	}
	if !reflect.DeepEqual(nativeSnapshot(t, native, refs[:len(refs)-1]...), rows[:len(rows)-1]) {
		t.Fatal("child deletion changed native ancestors")
	}
}

// The hook schedules a source write after a real native child query. It never
// fabricates the query's result or supplies topology/lifecycle evidence.
type deletionTopologySource struct {
	DeletionSource
	afterChildren func(bool, error)
}

func (s *deletionTopologySource) HasChildren(ctx context.Context, ref Namespace) (bool, error) {
	found, err := s.DeletionSource.HasChildren(ctx, ref)
	if hook := s.afterChildren; hook != nil {
		s.afterChildren = nil
		hook(found, err)
	}
	return found, err
}

func TestLeafDeleteChildInsertionRacingPreflightRetainsHold(t *testing.T) {
	store, native, parent, peer := ownedNativeLeaf(t)
	ctx := context.Background()
	source, err := NewNativeDeletionSource(native)
	if err != nil {
		t.Fatal(err)
	}
	tracing := &deletionTopologySource{DeletionSource: source}
	deleter, err := NewDeleter(store, tracing, ownerDrainFixture{peer})
	if err != nil {
		t.Fatal(err)
	}
	deletes := 0
	remove := native.delete
	native.delete = func(ctx context.Context, filter bson.M) (*mongo.DeleteResult, error) {
		deletes++
		return remove(ctx, filter)
	}
	insert := native.insert
	var held State
	native.insert = func(ctx context.Context, raw bson.Raw) (*mongo.InsertOneResult, error) {
		// The actual Creator has already acquired the parent pin and its live
		// native dispatch grant. Insert only after the parent's preflight reads
		// no children, before its deletion claim. Child completion waits below.
		var result *mongo.InsertOneResult
		var insertErr error
		tracing.afterChildren = func(found bool, err error) {
			if err != nil || found {
				t.Fatalf("initial native preflight: children=%v err=%v", found, err)
			}
			result, insertErr = insert(ctx, raw)
		}
		var err error
		held, err = deleter.Delete(ctx, parent.Namespace, "delete-racing-parent")
		if !errors.Is(err, ErrPending) || held.Phase != "closing" || held.Deletion == nil || held.Deletion.ResultDigest != "" || !allDeletionAcquisitions(held.Deletion, "held") || len(held.Pins) != 1 || held.Pins[0].Terminal != nil {
			t.Fatalf("racing child did not retain uncertainty: %+v %v", held, err)
		}
		if result == nil || insertErr != nil {
			t.Fatalf("racing owned native insert did not run: %+v %v", result, insertErr)
		}
		return result, insertErr
	}
	child, _ := ownedNativeChild(t, store, native, parent)
	if deletes != 0 || peer.prepares != 0 {
		t.Fatalf("racing parent dispatched: deletes=%d prepares=%d", deletes, peer.prepares)
	}
	retained := lifecycleSnapshot(t, store, parent.Namespace)[0]
	if retained.Phase != "closing" || !reflect.DeepEqual(retained.Intent, held.Intent) || !reflect.DeepEqual(retained.Deletion, held.Deletion) || len(retained.Pins) != 0 {
		t.Fatalf("child completion changed retained parent hold: %+v", retained)
	}
	root := lifecycleSnapshot(t, store, parent.Ancestors...)[0]
	pin, err := DeletionPin(retained, 0)
	if err != nil || !reflect.DeepEqual(root.Pins, []Pin{pin}) || pin.Terminal != nil {
		t.Fatalf("parent deletion pin lost or fabricated terminal: %+v %v", root.Pins, err)
	}
	refs := []Namespace{root.Namespace, parent.Namespace, child.Namespace}
	before := lifecycleSnapshot(t, store, refs...)
	rows := nativeSnapshot(t, native, refs...)
	// Child creation has settled its own proven pins. The retained parent
	// intent must now be held by the authoritative post-seal native child check.
	if _, err := deleter.Delete(ctx, parent.Namespace, "retry-racing-parent"); !errors.Is(err, ErrPending) {
		t.Fatal("nonleaf replay did not hold", err)
	}
	if deletes != 0 || !reflect.DeepEqual(lifecycleSnapshot(t, store, refs...), before) || !reflect.DeepEqual(nativeSnapshot(t, native, refs...), rows) {
		t.Fatal("nonleaf replay deleted native data or changed retained uncertainty")
	}
}

func TestLeafDeleteNeverRetargetsSameNameDifferentID(t *testing.T) {
	for _, phase := range []string{"open", "deleted", "attempted"} {
		t.Run(phase, func(t *testing.T) {
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
			original := nativeSnapshot(t, native, state.Namespace)[0]
			deletes := 0
			remove := native.delete
			native.delete = func(ctx context.Context, filter bson.M) (*mongo.DeleteResult, error) {
				deletes++
				result, err := remove(ctx, filter)
				if err == nil && phase == "attempted" {
					return nil, errors.New("lost native deletion acknowledgement")
				}
				return result, err
			}
			if phase == "open" {
				oid, _ := bson.ObjectIDFromHex(state.Namespace.ID)
				if result, err := native.schema.collection.DeleteOne(ctx, bson.M{"_id": oid}); err != nil || result.DeletedCount != 1 {
					t.Fatalf("fixture removal: %+v %v", result, err)
				}
			} else {
				result, err := deleter.Delete(ctx, state.Namespace, "delete-original")
				if (phase == "deleted" && err != nil) || (phase == "attempted" && !errors.Is(err, ErrUnknown)) || result.Phase != phase {
					t.Fatalf("original deletion: %+v %v", result, err)
				}
			}
			// Inject an excluded direct writer's same-name incarnation only in
			// this owned fixture; do not reopen the retained lifecycle tombstone.
			replacement := state.Namespace
			replacement.ID = bson.NewObjectID().Hex()
			var row bson.D
			if err := bson.Unmarshal(original, &row); err != nil {
				t.Fatal(err)
			}
			for i := range row {
				if row[i].Key == "_id" {
					row[i].Value, _ = bson.ObjectIDFromHex(replacement.ID)
				}
			}
			if _, err := native.schema.collection.InsertOne(ctx, row); err != nil {
				t.Fatal(err)
			}
			refs := append(append([]Namespace(nil), state.Ancestors...), state.Namespace)
			before := lifecycleSnapshot(t, store, refs...)
			rows := nativeSnapshot(t, native, replacement)
			calls, prepares := deletes, peer.prepares
			_, err = deleter.Delete(ctx, state.Namespace, "retry-original")
			if (phase == "deleted" && err != nil) || (phase != "deleted" && !errors.Is(err, ErrPending)) {
				t.Fatal("replacement changed retained replay outcome", err)
			}
			if deletes != calls || peer.prepares != prepares || !reflect.DeepEqual(lifecycleSnapshot(t, store, refs...), before) || !reflect.DeepEqual(nativeSnapshot(t, native, replacement), rows) {
				t.Fatal("different incarnation consumed state or retargeted native deletion")
			}
		})
	}
}
