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
	"go.acuvity.ai/elemental"
	"go.acuvity.ai/manipulate"
	"go.acuvity.ai/manipulate/manipmongo"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

func TestNativeNamespaceOwnedMongo(t *testing.T) {
	ctx := context.Background()
	m := mongofixture.New(t)
	if _, err := NewNativeNamespaceStore(m); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("missing indexes accepted/repaired: %v", err)
	}
	required := indexes.GetIndexes("a3s", api.Manager())[api.NamespaceIdentity]
	if err := manipmongo.CreateIndex(m, api.NamespaceIdentity, required...); err != nil {
		t.Fatal(err)
	}
	s, err := NewNativeNamespaceStore(m)
	if err != nil {
		t.Fatal(err)
	}
	collection := s.schema.collection
	identity := nativeIdentity()
	prepared, err := PrepareNativeNamespace(api.NewNamespace(), identity)
	if err != nil {
		t.Fatal(err)
	}
	oid, _ := bson.ObjectIDFromHex(identity.Namespace.ID)

	t.Run("ordinary create overwrites preallocated ID", func(t *testing.T) {
		ordinary := api.NewNamespace()
		ordinary.ID, ordinary.Name, ordinary.Namespace = identity.Namespace.ID, "/ordinary", "/"
		if err := m.Create(manipulate.NewContext(ctx), ordinary); err != nil {
			t.Fatal(err)
		}
		if ordinary.ID == identity.Namespace.ID {
			t.Fatal("ordinary create unexpectedly preserved ID")
		}
	})

	t.Run("bound insert and mutable body update", func(t *testing.T) {
		evidence, err := s.InsertOnce(ctx, prepared)
		if err != nil || evidence.Identity != identity || len(evidence.Digest) != 64 {
			t.Fatalf("insert: %+v %v", evidence, err)
		}
		observed, err := s.Observe(ctx, identity)
		if err != nil || evidence != observed {
			t.Fatalf("observe: %+v %v", observed, err)
		}
		var raw bson.Raw
		if err := collection.FindOne(ctx, bson.M{"_id": oid}).Decode(&raw); err != nil {
			t.Fatal(err)
		}
		var original api.Namespace
		if err := legacybson.Unmarshal(raw, &original); err != nil {
			t.Fatal(err)
		}
		updated := api.NewNamespace()
		updated.ID, updated.Name, updated.Namespace, updated.CreateTime = original.ID, original.Name, original.Namespace, original.CreateTime
		updated.Description, updated.Opaque, updated.CreationMarker = "changed", map[string]any{"mutable": true}, "forged"
		elemental.BackportUnexposedFields(&original, updated)
		if err := m.Update(manipulate.NewContext(ctx), updated); err != nil {
			t.Fatal(err)
		}
		observed, err = s.Observe(ctx, identity)
		if err != nil || evidence != observed {
			t.Fatalf("mutable body blocked proof: %+v %v", observed, err)
		}
	})

	t.Run("conditional predicate cannot delete wrong identity or aliases", func(t *testing.T) {
		for _, change := range []func(*NativeNamespaceIdentity){
			func(i *NativeNamespaceIdentity) { i.Namespace.ID = "000000000000000000000088" },
			func(i *NativeNamespaceIdentity) { i.Marker = "wrong-marker" },
		} {
			wrong := identity
			change(&wrong)
			tuple, err := nativeNamespaceTuple(wrong)
			if err != nil {
				t.Fatal(err)
			}
			result, err := collection.DeleteOne(ctx, nativeNamespaceDeleteFilter(tuple))
			if err != nil || result.DeletedCount != 0 {
				t.Fatalf("wrong tuple deleted: %+v %v", result, err)
			}
		}
		for _, field := range []string{"name", "namespace", "zone", "zhash", "createtime", "creationmarker"} {
			t.Run(field, func(t *testing.T) {
				original := prepared.raw.Lookup(field)
				var value any
				if err := original.Unmarshal(&value); err != nil {
					t.Fatal(err)
				}
				if _, err := collection.UpdateOne(ctx, bson.M{"_id": oid}, bson.M{"$set": bson.M{field: bson.A{value}}}); err != nil {
					t.Fatal(err)
				}
				if _, err := s.Observe(ctx, identity); !errors.Is(err, ErrUnavailable) {
					t.Fatalf("alias observed: %v", err)
				}
				tuple, _ := nativeNamespaceTuple(identity)
				result, err := collection.DeleteOne(ctx, nativeNamespaceDeleteFilter(tuple))
				if err != nil || result.DeletedCount != 0 {
					t.Fatalf("array alias deleted: %+v %v", result, err)
				}
				if _, err := collection.UpdateOne(ctx, bson.M{"_id": oid}, bson.M{"$set": bson.M{field: value}}); err != nil {
					t.Fatal(err)
				}
			})
		}
		if _, err := collection.UpdateOne(ctx, bson.M{"_id": oid}, bson.M{"$set": bson.M{"zone": float64(0)}}); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Observe(ctx, identity); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("numeric alias: %v", err)
		}
		tuple, _ := nativeNamespaceTuple(identity)
		result, err := collection.DeleteOne(ctx, nativeNamespaceDeleteFilter(tuple))
		if err != nil || result.DeletedCount != 0 {
			t.Fatalf("numeric alias deleted: %+v %v", result, err)
		}
		if _, err := collection.UpdateOne(ctx, bson.M{"_id": oid}, bson.M{"$set": bson.M{"zone": int32(0)}}); err != nil {
			t.Fatal(err)
		}
		if _, err := collection.UpdateOne(ctx, bson.M{"_id": oid}, bson.M{"$unset": bson.M{"creationmarker": ""}}); err != nil {
			t.Fatal(err)
		}
		if err := s.DeleteOnce(ctx, identity); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("missing marker: %v", err)
		}
		if _, err := collection.UpdateOne(ctx, bson.M{"_id": oid}, bson.M{"$set": bson.M{"creationmarker": identity.Marker}}); err != nil {
			t.Fatal(err)
		}
		duplicate := make(bson.D, 0, 16)
		if err := bson.Unmarshal(prepared.raw, &duplicate); err != nil {
			t.Fatal(err)
		}
		duplicate = append(duplicate, bson.E{Key: "creationmarker", Value: identity.Marker})
		if _, err := collection.ReplaceOne(ctx, bson.M{"_id": oid}, duplicate); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Observe(ctx, identity); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("duplicate marker: %v", err)
		}
		result, err = collection.DeleteOne(ctx, nativeNamespaceDeleteFilter(tuple))
		if err != nil || result.DeletedCount != 0 {
			t.Fatalf("duplicate marker deleted: %+v %v", result, err)
		}
		if _, err := collection.ReplaceOne(ctx, bson.M{"_id": oid}, prepared.raw); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("changed immutable binding between proof and delete holds", func(t *testing.T) {
		originalDelete := s.delete
		defer func() { s.delete = originalDelete }()
		calls := 0
		s.delete = func(ctx context.Context, filter bson.M) (*mongo.DeleteResult, error) {
			calls++
			if _, err := collection.UpdateOne(ctx, bson.M{"_id": oid}, bson.M{"$set": bson.M{"creationmarker": "raced"}}); err != nil {
				return nil, err
			}
			return originalDelete(ctx, filter)
		}
		if err := s.DeleteOnce(ctx, identity); !errors.Is(err, ErrUnknown) || calls != 1 {
			t.Fatalf("conditional race: %v calls=%d", err, calls)
		}
		if _, err := collection.UpdateOne(ctx, bson.M{"_id": oid}, bson.M{"$set": bson.M{"creationmarker": identity.Marker, "description": "new body", "opaque": bson.M{"changed": true}}}); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("lost delete acknowledgement never deletes again", func(t *testing.T) {
		originalDelete := s.delete
		defer func() { s.delete = originalDelete }()
		calls := 0
		s.delete = func(ctx context.Context, filter bson.M) (*mongo.DeleteResult, error) {
			calls++
			result, err := originalDelete(ctx, filter)
			if err != nil || result.DeletedCount != 1 {
				t.Fatalf("native delete: %+v %v", result, err)
			}
			return nil, errors.New("injected lost acknowledgement")
		}
		if err := s.DeleteOnce(ctx, identity); !errors.Is(err, ErrUnknown) || calls != 1 {
			t.Fatalf("lost delete: %v calls=%d", err, calls)
		}
		if _, err := s.Observe(ctx, identity); !errors.Is(err, ErrNotFound) {
			t.Fatalf("missing is not deletion proof: %v", err)
		}
		if err := s.DeleteOnce(ctx, identity); !errors.Is(err, ErrNotFound) || calls != 1 {
			t.Fatalf("missing dispatched again: %v calls=%d", err, calls)
		}
	})

	t.Run("lost insert acknowledgement is observation only", func(t *testing.T) {
		identity.Namespace.ID = "000000000000000000000098"
		identity.Namespace.Name = "/acme/lost"
		p, err := PrepareNativeNamespace(api.NewNamespace(), identity)
		if err != nil {
			t.Fatal(err)
		}
		originalInsert := s.insert
		defer func() { s.insert = originalInsert }()
		calls := 0
		s.insert = func(ctx context.Context, raw bson.Raw) (*mongo.InsertOneResult, error) {
			calls++
			deadline, ok := ctx.Deadline()
			if !ok || time.Until(deadline) > 10*time.Second {
				t.Fatal("unbounded attempt")
			}
			if _, err := originalInsert(ctx, raw); err != nil {
				t.Fatal(err)
			}
			return nil, errors.New("injected lost acknowledgement")
		}
		if _, err := s.InsertOnce(ctx, p); !errors.Is(err, ErrUnknown) || calls != 1 {
			t.Fatalf("lost insert: %v calls=%d", err, calls)
		}
		if _, err := s.Observe(ctx, identity); err != nil || calls != 1 {
			t.Fatalf("readback rewrote: %v calls=%d", err, calls)
		}
		if err := s.DeleteOnce(ctx, identity); err != nil {
			t.Fatalf("exact acknowledged deletion: %v", err)
		}
	})

	t.Run("insert acknowledgement requires exact ID", func(t *testing.T) {
		originalInsert := s.insert
		defer func() { s.insert = originalInsert }()
		for _, result := range []*mongo.InsertOneResult{nil, {}, {Acknowledged: true, InsertedID: identity.Namespace.ID}, {Acknowledged: true, InsertedID: bson.NewObjectID()}} {
			calls := 0
			s.insert = func(context.Context, bson.Raw) (*mongo.InsertOneResult, error) { calls++; return result, nil }
			if _, err := s.InsertOnce(ctx, prepared); !errors.Is(err, ErrUnknown) || calls != 1 {
				t.Fatalf("unqualified ack: %v calls=%d", err, calls)
			}
		}
	})

	t.Run("literal immediate children only", func(t *testing.T) {
		ref := Namespace{ID: "000000000000000000000097", Name: "/a.b"}
		for _, parent := range []string{"/axb", "/a.b/deeper", "/a.b-other"} {
			child := api.NewNamespace()
			child.Namespace, child.Name = parent, parent+"/child"
			if err := m.Create(manipulate.NewContext(ctx), child); err != nil {
				t.Fatal(err)
			}
		}
		if found, err := s.HasChildren(ctx, ref); err != nil || found {
			t.Fatalf("prefix/regex child: %v %v", found, err)
		}
		child := api.NewNamespace()
		child.Namespace, child.Name = ref.Name, ref.Name+"/child"
		if err := m.Create(manipulate.NewContext(ctx), child); err != nil {
			t.Fatal(err)
		}
		if found, err := s.HasChildren(ctx, ref); err != nil || !found {
			t.Fatalf("literal child missing: %v %v", found, err)
		}
	})

	t.Run("dropped native index holds without repair", func(t *testing.T) {
		if err := collection.Indexes().DropOne(ctx, "index_namespace_namespace_name"); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Observe(ctx, identity); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("index loss: %v", err)
		}
		if _, err := NewNativeNamespaceStore(m); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("constructor repaired DDL: %v", err)
		}
	})
}
