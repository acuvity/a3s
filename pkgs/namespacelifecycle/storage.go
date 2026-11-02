package namespacelifecycle

import (
	"context"
	"fmt"

	"go.acuvity.ai/a3s/internal/hasher"
	"go.acuvity.ai/a3s/pkgs/api"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// Repeated bounded qualification is not a fence against concurrent privileged
// DDL. Index mutation and direct/old writers are unsupported during activation.
func (s *Store) checkIndexes(ctx context.Context) error {
	if s == nil || s.collection == nil {
		return ErrUnavailable
	}
	cursor, err := s.collection.Indexes().List(ctx)
	if err != nil {
		return ErrUnavailable
	}
	defer func() { _ = cursor.Close(ctx) }()
	type index struct {
		Name      string `bson:"name"`
		Key       bson.D `bson:"key"`
		Unique    bool   `bson:"unique"`
		Sparse    bool   `bson:"sparse"`
		Hidden    bool   `bson:"hidden"`
		Partial   any    `bson:"partialFilterExpression"`
		Collation any    `bson:"collation"`
		Expiry    any    `bson:"expireAfterSeconds"`
	}
	found := map[string]index{}
	for cursor.Next(ctx) {
		var value index
		if len(found) >= 128 || cursor.Decode(&value) != nil || value.Expiry != nil {
			return ErrUnavailable
		}
		if _, ok := found[value.Name]; ok {
			return ErrUnavailable
		}
		found[value.Name] = value
	}
	if cursor.Err() != nil {
		return ErrUnavailable
	}
	primary, ok := found["_id_"]
	if !ok || !sameKeys(primary.Key, bson.D{{Key: "_id", Value: 1}}) || primary.Sparse || primary.Hidden || primary.Partial != nil || primary.Collation != nil {
		return ErrUnavailable
	}
	for _, required := range s.required {
		opts := &options.IndexOptions{}
		for _, apply := range required.Options.List() {
			if apply(opts) != nil {
				return ErrUnavailable
			}
		}
		if opts.Name == nil {
			return ErrUnavailable
		}
		actual, ok := found[*opts.Name]
		keys, keysOK := required.Keys.(bson.D)
		if !ok || !keysOK || actual.Unique != (opts.Unique != nil && *opts.Unique) || actual.Sparse || actual.Hidden || actual.Partial != nil || actual.Collation != nil || !sameKeys(actual.Key, keys) {
			return ErrUnavailable
		}
	}
	return nil
}

func sameKeys(a, b bson.D) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Key != b[i].Key || fmt.Sprint(a[i].Value) != fmt.Sprint(b[i].Value) {
			return false
		}
	}
	return true
}

func (s *Store) read(ctx context.Context, id string) (State, bson.Raw, error) {
	oid, err := bson.ObjectIDFromHex(id)
	if err != nil {
		return State{}, nil, ErrInvalid
	}
	cursor, err := s.collection.Find(ctx, bson.M{"_id": oid}, options.Find().SetHint("_id_").SetLimit(2).SetBatchSize(2))
	if err != nil {
		return State{}, nil, ErrUnavailable
	}
	defer func() { _ = cursor.Close(ctx) }()
	var rows []bson.Raw
	if cursor.All(ctx, &rows) != nil {
		return State{}, nil, ErrUnavailable
	}
	if len(rows) == 0 {
		return State{}, nil, ErrNotFound
	}
	if len(rows) != 1 {
		return State{}, nil, ErrUnavailable
	}
	state, err := decodeDocument(rows[0])
	if err != nil || state.Namespace.ID != id {
		return State{}, nil, ErrUnavailable
	}
	return state, rows[0], nil
}

func integer(value bson.RawValue) (int64, bool) {
	switch value.Type {
	case bson.TypeInt32:
		return int64(value.Int32()), true
	case bson.TypeInt64:
		return value.Int64(), true
	default:
		return 0, false
	}
}

func decodeDocument(raw bson.Raw) (State, error) {
	if len(raw) > MaxStateBytes+1024 {
		return State{}, ErrUnavailable
	}
	elements, err := raw.Elements()
	if err != nil {
		return State{}, ErrUnavailable
	}
	required := map[string]bson.Type{"_id": bson.TypeObjectID, "namespace": bson.TypeString, "namespacename": bson.TypeString, "data": bson.TypeString, "revision": bson.TypeInt64, "zone": bson.TypeInt64, "zhash": bson.TypeInt64}
	seen := map[string]bool{}
	for _, e := range elements {
		key, value := e.Key(), e.Value()
		if seen[key] {
			return State{}, ErrUnavailable
		}
		seen[key] = true
		if key == "_modelversion" {
			if n, ok := integer(value); !ok || n != 1 {
				return State{}, ErrUnavailable
			}
			continue
		}
		kind, ok := required[key]
		if !ok {
			return State{}, ErrUnavailable
		}
		if kind == bson.TypeInt64 {
			if _, ok := integer(value); !ok {
				return State{}, ErrUnavailable
			}
		} else if value.Type != kind {
			return State{}, ErrUnavailable
		}
	}
	for key := range required {
		if !seen[key] {
			return State{}, ErrUnavailable
		}
	}
	state, err := decode(raw.Lookup("data").StringValue())
	if err != nil {
		return State{}, err
	}
	model := api.NewNamespaceLifecycle()
	model.ID, model.NamespaceName = state.Namespace.ID, state.Namespace.Name
	if err := (&hasher.Hasher{}).Hash(model); err != nil {
		return State{}, ErrUnavailable
	}
	revision, _ := integer(raw.Lookup("revision"))
	zone, _ := integer(raw.Lookup("zone"))
	hash, _ := integer(raw.Lookup("zhash"))
	if raw.Lookup("_id").ObjectID().Hex() != state.Namespace.ID || raw.Lookup("namespace").StringValue() != "/" || raw.Lookup("namespacename").StringValue() != state.Namespace.Name || revision != state.Revision || zone != int64(model.Zone) || hash != int64(model.ZHash) {
		return State{}, ErrUnavailable
	}
	return state, nil
}

// Full raw snapshot plus scalar types prevents BSON numeric/array aliases or
// mutation between validation and CAS from matching an admission predicate.
func casFilter(raw bson.Raw) bson.M {
	elements, _ := raw.Elements()
	checks := make(bson.A, 1, 1+len(elements))
	checks[0] = bson.M{"$eq": bson.A{"$$ROOT", bson.M{"$literal": raw}}}
	for _, e := range elements {
		var kind string
		switch e.Value().Type {
		case bson.TypeObjectID:
			kind = "objectId"
		case bson.TypeString:
			kind = "string"
		case bson.TypeInt32:
			kind = "int"
		case bson.TypeInt64:
			kind = "long"
		}
		checks = append(checks, bson.M{"$eq": bson.A{bson.M{"$type": "$" + e.Key()}, kind}})
	}
	return bson.M{"_id": raw.Lookup("_id").ObjectID(), "$expr": bson.M{"$and": checks}}
}
