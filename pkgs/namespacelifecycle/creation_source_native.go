package namespacelifecycle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path"
	"reflect"
	"slices"
	"time"

	"go.acuvity.ai/a3s/pkgs/api"
)

// NativeCreationSource is the outer native adapter for one owned create payload.
// Reconciliation reads the supplied retained State, never substitutes this
// invocation's fresh ID/clock for an existing reservation.
type NativeCreationSource struct {
	store    *NativeNamespaceStore
	prepared PreparedNativeNamespace
	digest   string
}

// PrepareOwnerNamespace freezes native create input before any source claim.
// Namespace CRUD validation and current authorization remain the caller's job.
func PrepareOwnerNamespace(store *NativeNamespaceStore, input *api.Namespace, ref Namespace, ancestors []Namespace, operationID string, at time.Time, participants []string) (Creation, *NativeCreationSource, error) {
	if store == nil || input == nil || !validNamespace(ref) || ref.Name == "/" || at.IsZero() {
		return Creation{}, nil, ErrInvalid
	}
	logical := struct {
		Name        string         `json:"name"`
		Parent      string         `json:"parent"`
		Description string         `json:"description"`
		Label       string         `json:"label"`
		ImportLabel string         `json:"importLabel"`
		ImportHash  string         `json:"importHash"`
		Opaque      map[string]any `json:"opaque"`
	}{ref.Name, path.Dir(ref.Name), input.Description, input.Label, input.ImportLabel, input.ImportHash, input.Opaque}
	encoded, err := json.Marshal(logical)
	if err != nil || len(encoded) > maxNativeNamespaceBytes {
		return Creation{}, nil, ErrInvalid
	}
	// Normalize into callback-free, detached JSON values before deriving either
	// commitment or native bytes. Never serialize the original Opaque twice:
	// custom JSON/BSON encoders can disagree or mutate their enclosing input.
	owned := logical
	owned.Opaque = nil
	if json.Unmarshal(encoded, &owned) != nil {
		return Creation{}, nil, ErrInvalid
	}
	if len(owned.Opaque) == 0 {
		owned.Opaque = nil // Native omit-empty storage canonicalizes this too.
	}
	encoded, err = json.Marshal(owned)
	if err != nil || len(encoded) > maxNativeNamespaceBytes {
		return Creation{}, nil, ErrInvalid
	}
	body := api.NewNamespace()
	body.Description, body.Label = owned.Description, owned.Label
	body.ImportLabel, body.ImportHash, body.Opaque = owned.ImportLabel, owned.ImportHash, owned.Opaque
	digest := sha256.Sum256(append([]byte("namespace-request.v1\x00"), encoded...))
	binding := Creation{OperationID: operationID, Digest: hex.EncodeToString(digest[:]), CreatedAt: at.UTC().Truncate(time.Millisecond).Format(time.RFC3339Nano), Participants: slices.Clone(participants)}
	// Build the immutable marker without pretending the source claim exists.
	projection := binding
	projection.Origin = "create"
	state := State{Namespace: ref, Ancestors: ancestors, Creation: &projection}
	expected, err := creationNativeIdentity(state)
	if err != nil {
		return Creation{}, nil, err
	}
	prepared, err := PrepareNativeNamespace(body, expected)
	if err != nil {
		return Creation{}, nil, err
	}
	return binding, &NativeCreationSource{store: store, prepared: prepared, digest: binding.Digest}, nil
}

func creationNativeIdentity(state State) (NativeNamespaceIdentity, error) {
	if state.Creation == nil {
		return NativeNamespaceIdentity{}, ErrInvalid
	}
	clock, err := time.Parse(time.RFC3339Nano, state.Creation.CreatedAt)
	if err != nil {
		return NativeNamespaceIdentity{}, ErrInvalid
	}
	parent := path.Dir(state.Namespace.Name)
	var marker string
	if state.Creation.Origin == "bootstrap" {
		if state.Namespace.Name != "/" {
			return NativeNamespaceIdentity{}, ErrInvalid
		}
		parent, marker = "root", state.Creation.OperationID
	} else {
		marker, err = CreationMarkerDigest(state)
		if err != nil {
			return NativeNamespaceIdentity{}, err
		}
	}
	return NativeNamespaceIdentity{Namespace: state.Namespace, Parent: parent, CreatedAt: clock, Marker: marker}, nil
}

func (s *NativeCreationSource) Verify(ctx context.Context, state State) error {
	expected, err := creationNativeIdentity(state)
	if err != nil {
		return err
	}
	evidence, err := s.store.Observe(ctx, expected)
	if err != nil {
		return err
	}
	if state.Creation.Origin == "bootstrap" && evidence.Digest != state.Creation.ApplicationDigest {
		return ErrConflict
	}
	return nil
}
func (s *NativeCreationSource) Insert(ctx context.Context, state State) error {
	expected, err := creationNativeIdentity(state)
	if err != nil {
		return err
	}
	if state.Creation == nil || state.Creation.Phase != "native-attempted" || state.Creation.Digest != s.digest || !reflect.DeepEqual(expected, s.prepared.identity) {
		return ErrConflict
	}
	_, err = s.store.InsertOnce(ctx, s.prepared)
	return err
}
func (s *NativeCreationSource) Observe(ctx context.Context, state State) (string, error) {
	if state.Creation == nil || state.Creation.Origin != "create" {
		return "", ErrInvalid
	}
	expected, err := creationNativeIdentity(state)
	if err != nil {
		return "", err
	}
	if _, err := s.store.Observe(ctx, expected); err != nil {
		return "", err
	}
	return expected.Marker, nil
}
