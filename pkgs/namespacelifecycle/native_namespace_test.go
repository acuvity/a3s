package namespacelifecycle

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	legacybson "github.com/globalsign/mgo/bson"
	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/elemental"
	"go.mongodb.org/mongo-driver/v2/bson"
)

func nativeIdentity() NativeNamespaceIdentity {
	return NativeNamespaceIdentity{Namespace: Namespace{ID: "000000000000000000000099", Name: "/acme/leaf"}, Parent: "/acme", CreatedAt: time.Date(2026, 10, 7, 1, 2, 3, 456000000, time.UTC), Marker: "owner-create-99"}
}

func TestNativeNamespacePreparation(t *testing.T) {
	identity := nativeIdentity()
	input := api.NewNamespace()
	input.ID, input.Name, input.Namespace, input.CreationMarker = "invalid", "untrusted", "/other", "forged"
	input.CreateTime, input.UpdateTime, input.Zone, input.ZHash = time.Now(), time.Now(), 17, 18
	input.Opaque = map[string]any{"nested": map[string]any{"body": "original"}}
	prepared, err := PrepareNativeNamespace(input, identity)
	if err != nil {
		t.Fatal(err)
	}
	input.Opaque["nested"].(map[string]any)["body"] = "changed"
	input.Description = "changed"
	if prepared.model.Opaque["nested"].(map[string]any)["body"] != "original" || prepared.model.Description != "" {
		t.Fatal("preparation retained caller aliases")
	}
	if prepared.model.ID != identity.Namespace.ID || prepared.model.Name != identity.Namespace.Name || prepared.model.Namespace != identity.Parent || prepared.model.CreationMarker != identity.Marker || !prepared.model.CreateTime.Equal(identity.CreatedAt) || !prepared.model.UpdateTime.Equal(identity.CreatedAt) {
		t.Fatal("trusted binding was not installed")
	}
	if prepared.raw.Lookup("_modelversion").Type != 0 {
		t.Fatal("native GetBSON unexpectedly emits model version")
	}
	var roundtrip api.Namespace
	if err := legacybson.Unmarshal(prepared.raw, &roundtrip); err != nil || roundtrip.CreationMarker != identity.Marker {
		t.Fatalf("marker BSON roundtrip: %v", err)
	}
	encoded, err := json.Marshal(&roundtrip)
	if err != nil || bytes.Contains(encoded, []byte(identity.Marker)) || bytes.Contains(encoded, []byte("creationMarker")) {
		t.Fatalf("private marker exposed: %s %v", encoded, err)
	}
	target := api.NewNamespace()
	target.CreationMarker = "caller-forgery"
	elemental.BackportUnexposedFields(&roundtrip, target)
	if target.CreationMarker != identity.Marker {
		t.Fatal("full update lost marker")
	}
	sparse := target.ToSparse().(*api.SparseNamespace)
	if sparse.CreationMarker == nil || *sparse.CreationMarker != identity.Marker {
		t.Fatal("sparse conversion lost marker")
	}
	legacy, err := legacybson.Marshal(api.NewNamespace())
	if err != nil || bson.Raw(legacy).Lookup("creationmarker").Type != 0 {
		t.Fatal("empty marker not omitted")
	}
	input.Description = strings.Repeat("x", 32*1024)
	if _, err := PrepareNativeNamespace(input, identity); !errors.Is(err, ErrInvalid) {
		t.Fatalf("oversized: %v", err)
	}
	identity.CreatedAt = identity.CreatedAt.Add(time.Nanosecond)
	if _, err := PrepareNativeNamespace(api.NewNamespace(), identity); !errors.Is(err, ErrInvalid) {
		t.Fatalf("fractional clock: %v", err)
	}
}

func TestNativeNamespaceProofRejectsAliases(t *testing.T) {
	identity := nativeIdentity()
	tuple, err := nativeNamespaceTuple(identity)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		change func(bson.D) bson.D
	}{
		{"missing", func(d bson.D) bson.D { return d[:len(d)-1] }},
		{"duplicate", func(d bson.D) bson.D { return append(d, d[0]) }},
		{"array", func(d bson.D) bson.D { d[1].Value = bson.A{identity.Namespace.Name}; return d }},
		{"numeric", func(d bson.D) bson.D { d[3].Value = float64(0); return d }},
		{"marker", func(d bson.D) bson.D { d[len(d)-1].Value = "forged"; return d }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := bson.Marshal(tc.change(append(bson.D(nil), tuple...)))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := nativeNamespaceEvidence(raw, identity); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("accepted proof: %v", err)
			}
		})
	}
}
