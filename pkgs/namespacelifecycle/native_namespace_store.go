package namespacelifecycle

import (
	"context"
	"time"

	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/a3s/pkgs/indexes"
	"go.acuvity.ai/manipulate"
	"go.acuvity.ai/manipulate/manipmongo"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readconcern"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"
	"go.mongodb.org/mongo-driver/v2/mongo/writeconcern"
)

// NativeNamespaceStore is a dormant, namespace-only native adapter. Each method
// makes at most one application-level mutation call, without retry/upsert or
// readback-to-write recovery. Driver retryable writes are a client qualification
// requirement, not disabled by collection concerns. Insert/Delete require an
// acknowledged live lifecycle grant held by the caller; inputs grant nothing.
// The caller must enforce request filters and exclude old/direct writers and
// privileged DDL. Index qualification is not a concurrent DDL fence.
type NativeNamespaceStore struct {
	// Reuse the existing index qualifier only; never lifecycle CRUD on this
	// collection. Unlike NewStore, this constructor never creates indexes.
	schema Store
	insert func(context.Context, bson.Raw) (*mongo.InsertOneResult, error)
	delete func(context.Context, bson.M) (*mongo.DeleteResult, error)
}

func NewNativeNamespaceStore(m manipulate.Manipulator) (*NativeNamespaceStore, error) {
	if !manipmongo.IsMongoManipulator(m) {
		return nil, ErrUnavailable
	}
	db, err := manipmongo.GetDatabase(m)
	if err != nil {
		return nil, ErrUnavailable
	}
	required := indexes.GetIndexes("a3s", api.Manager())[api.NamespaceIdentity]
	if len(required) == 0 {
		return nil, ErrUnavailable
	}
	s := &NativeNamespaceStore{schema: Store{required: required, collection: db.Collection(api.NamespaceIdentity.Name,
		options.Collection().SetReadPreference(readpref.Primary()).SetReadConcern(readconcern.Majority()).SetWriteConcern(writeconcern.Majority()))}}
	s.insert = func(ctx context.Context, raw bson.Raw) (*mongo.InsertOneResult, error) {
		return s.schema.collection.InsertOne(ctx, raw)
	}
	s.delete = func(ctx context.Context, filter bson.M) (*mongo.DeleteResult, error) {
		return s.schema.collection.DeleteOne(ctx, filter, options.DeleteOne().SetHint("_id_"))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.schema.checkIndexes(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

// InsertOnce requires an original, acknowledged live creation dispatch grant.
// Unknown acknowledgement leaves Held: Observe may prove an applied insertion,
// but neither missing rows nor a reconstructed prepared value permits another.
func (s *NativeNamespaceStore) InsertOnce(ctx context.Context, prepared PreparedNativeNamespace) (NativeNamespaceEvidence, error) {
	if prepared.model == nil || len(prepared.raw) == 0 || len(prepared.raw) > maxNativeNamespaceBytes {
		return NativeNamespaceEvidence{}, ErrInvalid
	}
	tuple, err := nativeNamespaceTuple(prepared.identity)
	if err != nil {
		return NativeNamespaceEvidence{}, err
	}
	encoded, err := bson.Marshal(tuple)
	if err != nil {
		return NativeNamespaceEvidence{}, ErrInvalid
	}
	// Verify that legacy encoding retained the preallocated ID and tuple before
	// dispatch. The rest of this private owned record was validated at prepare.
	for _, field := range tuple {
		if !prepared.raw.Lookup(field.Key).Equal(bson.Raw(encoded).Lookup(field.Key)) {
			return NativeNamespaceEvidence{}, ErrInvalid
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if s == nil {
		return NativeNamespaceEvidence{}, ErrUnavailable
	}
	if err := s.schema.checkIndexes(ctx); err != nil {
		return NativeNamespaceEvidence{}, err
	}
	result, err := s.insert(ctx, prepared.raw)
	if err != nil || result == nil || !result.Acknowledged {
		return NativeNamespaceEvidence{}, ErrUnknown
	}
	id, ok := result.InsertedID.(bson.ObjectID)
	if !ok || id.Hex() != prepared.identity.Namespace.ID {
		return NativeNamespaceEvidence{}, ErrUnknown
	}
	return nativeNamespaceEvidence(encoded, prepared.identity)
}

func (s *NativeNamespaceStore) Observe(ctx context.Context, expected NativeNamespaceIdentity) (NativeNamespaceEvidence, error) {
	if _, err := nativeNamespaceTuple(expected); err != nil {
		return NativeNamespaceEvidence{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if s == nil {
		return NativeNamespaceEvidence{}, ErrUnavailable
	}
	if err := s.schema.checkIndexes(ctx); err != nil {
		return NativeNamespaceEvidence{}, err
	}
	return s.observe(ctx, expected)
}

func (s *NativeNamespaceStore) observe(ctx context.Context, expected NativeNamespaceIdentity) (NativeNamespaceEvidence, error) {
	oid, _ := bson.ObjectIDFromHex(expected.Namespace.ID)
	cursor, err := s.schema.collection.Find(ctx, bson.M{"_id": oid}, options.Find().SetHint("_id_").SetLimit(2).SetBatchSize(2).SetProjection(nativeNamespaceProjection()))
	if err != nil {
		return NativeNamespaceEvidence{}, ErrUnavailable
	}
	defer func() { _ = cursor.Close(ctx) }()
	var rows []bson.Raw
	if cursor.All(ctx, &rows) != nil || len(rows) > 1 {
		return NativeNamespaceEvidence{}, ErrUnavailable
	}
	if len(rows) == 0 {
		return NativeNamespaceEvidence{}, ErrNotFound
	}
	return nativeNamespaceEvidence(rows[0], expected)
}

// DeleteOnce requires the original live deletion grant. A pre-read qualifies
// the proof; the mutation independently matches the complete immutable tuple.
// Missing/no-match/unknown results never count as deletion or permit a retry.
func (s *NativeNamespaceStore) DeleteOnce(ctx context.Context, expected NativeNamespaceIdentity) error {
	tuple, err := nativeNamespaceTuple(expected)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if s == nil {
		return ErrUnavailable
	}
	if err := s.schema.checkIndexes(ctx); err != nil {
		return err
	}
	if _, err := s.observe(ctx, expected); err != nil {
		return err
	}
	result, err := s.delete(ctx, nativeNamespaceDeleteFilter(tuple))
	if err != nil || result == nil || !result.Acknowledged || result.DeletedCount != 1 {
		return ErrUnknown
	}
	return nil
}

// HasChildren checks immediate owning-namespace equality, not a name prefix.
// A false result is not writer coverage or a topology fence. The owner must hold
// its sealed/drained ancestor barrier and qualify all writers independently.
func (s *NativeNamespaceStore) HasChildren(ctx context.Context, ref Namespace) (bool, error) {
	if !validNamespace(ref) {
		return false, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if s == nil {
		return false, ErrUnavailable
	}
	if err := s.schema.checkIndexes(ctx); err != nil {
		return false, err
	}
	cursor, err := s.schema.collection.Find(ctx, bson.M{"namespace": ref.Name}, options.Find().SetHint("index_namespace_namespace_name").SetLimit(1).SetBatchSize(1).SetProjection(bson.M{"_id": 1}))
	if err != nil {
		return false, ErrUnavailable
	}
	defer func() { _ = cursor.Close(ctx) }()
	found := cursor.Next(ctx)
	if cursor.Err() != nil {
		return false, ErrUnavailable
	}
	return found, nil
}
