package namespacelifecycle

import (
	"context"
	"errors"
	"time"

	legacybson "github.com/globalsign/mgo/bson"
	"go.acuvity.ai/a3s/internal/hasher"
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

// Store retains namespace-owner coordination outside ordinary subtree cleanup.
// Each mutation uses at most one primary/majority conditional write. Ten seconds
// bounds a data attempt, never the lifetime of an unknown operation or deletion.
type Store struct {
	collection *mongo.Collection
	required   []mongo.IndexModel
	insert     func(context.Context, bson.Raw) (*mongo.InsertOneResult, error)
	update     func(context.Context, bson.M, bson.M) (*mongo.UpdateResult, error)
}

func NewStore(m manipulate.Manipulator) (*Store, error) {
	if !manipmongo.IsMongoManipulator(m) {
		return nil, ErrUnavailable
	}
	required := indexes.GetIndexes("a3s", api.Manager())[api.NamespaceLifecycleIdentity]
	if len(required) == 0 {
		return nil, ErrUnavailable
	}
	if err := manipmongo.CreateIndex(m, api.NamespaceLifecycleIdentity, required...); err != nil {
		return nil, ErrUnavailable
	}
	db, err := manipmongo.GetDatabase(m)
	if err != nil {
		return nil, ErrUnavailable
	}
	s := &Store{required: required, collection: db.Collection(api.NamespaceLifecycleIdentity.Name, options.Collection().SetReadPreference(readpref.Primary()).SetReadConcern(readconcern.Majority()).SetWriteConcern(writeconcern.Majority()))}
	s.insert = func(ctx context.Context, raw bson.Raw) (*mongo.InsertOneResult, error) {
		return s.collection.InsertOne(ctx, raw)
	}
	s.update = func(ctx context.Context, filter, update bson.M) (*mongo.UpdateResult, error) {
		return s.collection.UpdateOne(ctx, filter, update, options.UpdateOne().SetHint("_id_"))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.checkIndexes(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

// Initialize is explicit trusted bootstrap/enrollment, NEVER a missing-record
// recovery path. The caller must already own every required ancestor reservation
// (or perform reviewed offline bootstrap). It must bind authoritative native IDs;
// this low-level store does not infer existence, authenticate or enroll a writer.
func (s *Store) Initialize(ctx context.Context, ref Namespace, ancestors []Namespace) (State, error) {
	state := State{Version: "namespace-lifecycle.v1", Namespace: ref, Ancestors: ancestors, Revision: 1, Phase: "open", Pins: []Pin{}, Drains: []DrainProof{}}
	if state.Ancestors == nil {
		state.Ancestors = []Namespace{}
	}
	return s.initialize(ctx, state)
}

func (s *Store) initialize(ctx context.Context, state State) (State, error) {
	ref := state.Namespace
	data, err := encode(state)
	if err != nil {
		return State{}, err
	}
	state = copyState(state)
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := s.checkIndexes(ctx); err != nil {
		return State{}, err
	}
	if _, _, err := s.read(ctx, ref.ID); !errors.Is(err, ErrNotFound) {
		if err == nil {
			err = ErrConflict
		}
		return State{}, err
	}
	model := api.NewNamespaceLifecycle()
	model.ID, model.Namespace, model.Revision, model.Data = ref.ID, "/", 1, data
	model.NamespaceName = ref.Name
	if err := (&hasher.Hasher{}).Hash(model); err != nil {
		return State{}, ErrUnavailable
	}
	raw, err := legacybson.Marshal(model)
	if err != nil {
		return State{}, ErrUnavailable
	}
	result, err := s.insert(ctx, bson.Raw(raw))
	var writeError mongo.WriteException
	if errors.As(err, &writeError) && writeError.WriteConcernError != nil {
		return State{}, ErrUnknown
	}
	if mongo.IsDuplicateKeyError(err) {
		return State{}, ErrConflict
	}
	if err != nil || result == nil || !result.Acknowledged {
		return State{}, ErrUnknown
	}
	id, ok := result.InsertedID.(bson.ObjectID)
	if !ok || id.Hex() != ref.ID {
		return State{}, ErrUnknown
	}
	return state, nil
}

func (s *Store) Get(ctx context.Context, namespaceID string) (State, error) {
	if !idPattern.MatchString(namespaceID) {
		return State{}, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := s.checkIndexes(ctx); err != nil {
		return State{}, err
	}
	state, _, err := s.read(ctx, namespaceID)
	return state, err
}

func (s *Store) cas(ctx context.Context, expected, next State) (State, bool, error) {
	before, err := encode(expected)
	if err != nil || expected.Revision >= maxRevision {
		return State{}, false, ErrInvalid
	}
	next.Revision++
	if maxRevision-next.Revision < progressRevisions(next) {
		return State{}, false, ErrPending
	}
	after, err := encode(next)
	if err != nil {
		return State{}, false, err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := s.checkIndexes(ctx); err != nil {
		return State{}, false, err
	}
	stored, raw, err := s.read(ctx, expected.Namespace.ID)
	if err != nil {
		return State{}, false, err
	}
	actual, _ := encode(stored)
	if actual != before {
		return State{}, false, nil
	}
	result, err := s.update(ctx, casFilter(raw), bson.M{"$set": bson.M{"data": after, "revision": next.Revision}})
	if err != nil || result == nil || !result.Acknowledged {
		return State{}, false, ErrUnknown
	}
	if result.MatchedCount == 0 {
		return State{}, false, nil
	}
	if result.MatchedCount != 1 || result.ModifiedCount != 1 || result.UpsertedCount != 0 {
		return State{}, false, ErrUnknown
	}
	return copyState(next), true, nil
}
