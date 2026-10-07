package namespacelifecycle

import (
	"context"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// GetByName locates retained owner state, including a permanent tombstone. It
// does not adopt that state, resolve a name to new authority, or initialize it.
func (s *Store) GetByName(ctx context.Context, name string) (State, error) {
	if !validNamespace(Namespace{ID: "000000000000000000000001", Name: name}) {
		return State{}, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := s.checkIndexes(ctx); err != nil {
		return State{}, err
	}
	cursor, err := s.collection.Find(ctx, bson.M{"namespacename": name}, options.Find().SetHint(bson.D{{Key: "namespacename", Value: 1}}).SetLimit(2).SetBatchSize(2))
	if err != nil {
		return State{}, ErrUnavailable
	}
	defer func() { _ = cursor.Close(ctx) }()
	var rows []bson.Raw
	if cursor.All(ctx, &rows) != nil {
		return State{}, ErrUnavailable
	}
	if len(rows) == 0 {
		return State{}, ErrNotFound
	}
	if len(rows) != 1 {
		return State{}, ErrUnavailable
	}
	state, err := decodeDocument(rows[0])
	if err != nil || state.Namespace.Name != name {
		return State{}, ErrUnavailable
	}
	return state, nil
}
