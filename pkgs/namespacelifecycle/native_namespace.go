package namespacelifecycle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"path"
	"time"

	legacybson "github.com/globalsign/mgo/bson"
	"go.acuvity.ai/a3s/internal/hasher"
	"go.acuvity.ai/a3s/pkgs/api"
	"go.mongodb.org/mongo-driver/v2/bson"
)

const maxNativeNamespaceBytes = 32 * 1024

// NativeNamespaceIdentity is an expected immutable binding, not proof of native
// existence or authority to mutate. The owner must supply its retained binding.
type NativeNamespaceIdentity struct {
	Namespace Namespace
	Parent    string
	CreatedAt time.Time
	Marker    string
}

// NativeNamespaceEvidence binds only identity, creation clock, native shards and
// the private marker. Mutable description/opaque/import metadata is not proof.
type NativeNamespaceEvidence struct {
	Identity NativeNamespaceIdentity
	Digest   string
}

// PreparedNativeNamespace owns a detached native model and its bounded legacy
// BSON encoding. It conveys no lifecycle dispatch grant and exposes no aliases.
type PreparedNativeNamespace struct {
	model    *api.Namespace
	raw      bson.Raw
	identity NativeNamespaceIdentity
}

// PrepareNativeNamespace replaces caller-supplied identity, clocks, marker and
// shards with the trusted binding, then uses native validation/hash/GetBSON.
// As with native CRUD, callers must not mutate input concurrently with this call.
func PrepareNativeNamespace(input *api.Namespace, expected NativeNamespaceIdentity) (PreparedNativeNamespace, error) {
	if input == nil {
		return PreparedNativeNamespace{}, ErrInvalid
	}
	if _, err := nativeNamespaceTuple(expected); err != nil {
		return PreparedNativeNamespace{}, err
	}
	expected.CreatedAt = expected.CreatedAt.UTC()
	model := *input
	model.ID, model.Name, model.Namespace = expected.Namespace.ID, expected.Namespace.Name, expected.Parent
	model.CreateTime, model.UpdateTime, model.CreationMarker = expected.CreatedAt, expected.CreatedAt, expected.Marker
	if err := model.Validate(); err != nil {
		return PreparedNativeNamespace{}, ErrInvalid
	}
	if err := (&hasher.Hasher{}).Hash(&model); err != nil {
		return PreparedNativeNamespace{}, ErrInvalid
	}
	encoded, err := legacybson.Marshal(&model)
	if err != nil || len(encoded) > maxNativeNamespaceBytes {
		return PreparedNativeNamespace{}, ErrInvalid
	}
	// Roundtripping, rather than retaining a shallow model copy, also detaches
	// all nested Opaque maps/slices. The insert itself always uses these bytes.
	owned := api.NewNamespace()
	if err := legacybson.Unmarshal(encoded, owned); err != nil {
		return PreparedNativeNamespace{}, ErrInvalid
	}
	return PreparedNativeNamespace{model: owned, raw: bson.Raw(encoded), identity: expected}, nil
}

func nativeNamespaceTuple(expected NativeNamespaceIdentity) (bson.D, error) {
	ref, clock := expected.Namespace, expected.CreatedAt
	if !validNamespace(ref) || !keyPattern.MatchString(expected.Marker) || clock.IsZero() || clock.Year() < 1 || clock.Year() > 9999 || !clock.Equal(clock.Truncate(time.Millisecond)) {
		return nil, ErrInvalid
	}
	if ref.Name == "/" && expected.Parent != "root" || ref.Name != "/" && expected.Parent != path.Dir(ref.Name) {
		return nil, ErrInvalid
	}
	model := api.NewNamespace()
	model.Name = ref.Name
	if err := (&hasher.Hasher{}).Hash(model); err != nil {
		return nil, ErrInvalid
	}
	oid, err := bson.ObjectIDFromHex(ref.ID)
	if err != nil {
		return nil, ErrInvalid
	}
	return bson.D{
		{Key: "_id", Value: oid},
		{Key: "name", Value: ref.Name},
		{Key: "namespace", Value: expected.Parent},
		{Key: "zone", Value: model.Zone},
		{Key: "zhash", Value: model.ZHash},
		{Key: "createtime", Value: clock},
		{Key: "creationmarker", Value: expected.Marker},
	}, nil
}

func nativeNamespaceEvidence(raw bson.Raw, expected NativeNamespaceIdentity) (NativeNamespaceEvidence, error) {
	tuple, err := nativeNamespaceTuple(expected)
	if err != nil {
		return NativeNamespaceEvidence{}, err
	}
	encoded, err := bson.Marshal(tuple)
	if err != nil || len(raw) > maxNativeNamespaceBytes {
		return NativeNamespaceEvidence{}, ErrUnavailable
	}
	elements, err := raw.Elements()
	if err != nil || len(elements) != len(tuple) {
		return NativeNamespaceEvidence{}, ErrUnavailable
	}
	seen := make(map[string]bool, len(elements))
	for _, element := range elements {
		key, actual := element.Key(), element.Value()
		wanted := bson.Raw(encoded).Lookup(key)
		if seen[key] || wanted.Type == 0 || wanted.Type != actual.Type || !bytes.Equal(wanted.Value, actual.Value) {
			return NativeNamespaceEvidence{}, ErrUnavailable
		}
		seen[key] = true
	}
	// Versioned domain separation and canonical tuple order; body order and
	// mutable fields never change this digest. GetBSON omits _modelversion.
	digest := sha256.Sum256(append([]byte("native-namespace.v1\x00"), encoded...))
	expected.CreatedAt = expected.CreatedAt.UTC()
	return NativeNamespaceEvidence{Identity: expected, Digest: hex.EncodeToString(digest[:])}, nil
}

// Inclusion projections collapse duplicate BSON keys. Count the original
// immutable fields before projection; missing/duplicate fields cannot produce
// a complete proof. Mutable fields are deliberately not part of this count.
func nativeNamespaceFieldCount() bson.M {
	keys := bson.A{"_id", "name", "namespace", "zone", "zhash", "createtime", "creationmarker"}
	return bson.M{"$eq": bson.A{7, bson.M{"$size": bson.M{"$filter": bson.M{
		"input": bson.M{"$objectToArray": "$$ROOT"}, "as": "field",
		"cond": bson.M{"$in": bson.A{"$$field.k", bson.M{"$literal": keys}}},
	}}}}}
}

func nativeNamespaceProjection() bson.M {
	return bson.M{"_id": bson.M{"$cond": bson.A{nativeNamespaceFieldCount(), "$_id", "$$REMOVE"}}, "name": 1, "namespace": 1, "zone": 1, "zhash": 1, "createtime": 1, "creationmarker": 1}
}

// The exact immutable tuple, not $$ROOT against a projection. Scalar checks
// prevent query equality's array and numeric aliases from authorizing deletion.
func nativeNamespaceDeleteFilter(tuple bson.D) bson.M {
	encoded, _ := bson.Marshal(tuple)
	elements, _ := bson.Raw(encoded).Elements()
	filter := make(bson.M, len(tuple)+1)
	checks := make(bson.A, 1, len(tuple)+1)
	checks[0] = nativeNamespaceFieldCount()
	for i, element := range elements {
		key := element.Key()
		filter[key] = tuple[i].Value
		kind := map[bson.Type]string{bson.TypeObjectID: "objectId", bson.TypeString: "string", bson.TypeInt32: "int", bson.TypeInt64: "long", bson.TypeDateTime: "date"}[element.Value().Type]
		checks = append(checks, bson.M{"$eq": bson.A{bson.M{"$type": "$" + key}, kind}})
	}
	filter["$expr"] = bson.M{"$and": checks}
	return filter
}
