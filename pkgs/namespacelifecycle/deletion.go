package namespacelifecycle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strconv"
)

const maxOwnedDeletionBytes = 4096

// OwnedDeletion retains the single source deletion invocation and its topology
// progress. Intent/Drains remain the one canonical binding, not a second journal.
type OwnedDeletion struct {
	Acquisitions []string `json:"acquisitions"`
	ResultDigest string   `json:"resultDigest,omitempty"`
}

func OwnedDeletionIntent(s State, operationID string) (Intent, error) {
	if s.Creation == nil || s.Creation.Origin != "create" || s.Creation.Phase != "ready" || s.Namespace.Name == "/" || !keyPattern.MatchString(operationID) {
		return Intent{}, ErrInvalid
	}
	marker, err := CreationMarkerDigest(s)
	if err != nil {
		return Intent{}, err
	}
	encoded, err := json.Marshal(struct {
		Version             string
		Namespace           Namespace
		Ancestors           []Namespace
		Creation, Operation string
		Participants        []string
	}{"namespace-deletion.v1", s.Namespace, s.Ancestors, marker, operationID, s.Creation.Participants})
	if err != nil {
		return Intent{}, ErrInvalid
	}
	digest := sha256.Sum256(encoded)
	return Intent{ID: operationID, Digest: hex.EncodeToString(digest[:]), Participants: append([]string(nil), s.Creation.Participants...)}, nil
}

func OwnedDeletionResultDigest(s State) (string, error) {
	if s.Deletion == nil || s.Intent == nil {
		return "", ErrInvalid
	}
	intent, err := OwnedDeletionIntent(s, s.Intent.ID)
	if err != nil || !reflect.DeepEqual(intent, *s.Intent) {
		return "", ErrInvalid
	}
	digest := sha256.Sum256([]byte("namespace-deletion-applied.v1\x00" + intent.Digest))
	return hex.EncodeToString(digest[:]), nil
}

func DeletionPin(s State, index int) (Pin, error) {
	if s.Deletion == nil || s.Intent == nil || index < 0 || index >= len(s.Ancestors) {
		return Pin{}, ErrInvalid
	}
	id := sha256.Sum256([]byte(s.Intent.Digest + ":ancestor:" + strconv.Itoa(index)))
	return Pin{ID: "delete:" + hex.EncodeToString(id[:]), Kind: "namespace-delete", Target: s.Namespace, Digest: s.Intent.Digest}, nil
}

func validOwnedDeletion(s State) bool {
	if s.Deletion == nil {
		return s.Version == "namespace-lifecycle.v1" || s.Intent == nil
	}
	if s.Version != "namespace-lifecycle.v2" || s.Creation == nil || s.Intent == nil || len(s.Deletion.Acquisitions) != len(s.Ancestors) {
		return false
	}
	intent, err := OwnedDeletionIntent(s, s.Intent.ID)
	if err != nil || !reflect.DeepEqual(intent, *s.Intent) {
		return false
	}
	encoded, err := json.Marshal(s.Deletion)
	if err != nil || len(encoded) > maxOwnedDeletionBytes {
		return false
	}
	switch s.Phase {
	case "open":
		if s.Deletion.ResultDigest != "" || len(s.Drains) != 0 {
			return false
		}
		pastHeld := false
		for _, phase := range s.Deletion.Acquisitions {
			if phase == "held" && !pastHeld {
				continue
			}
			if phase == "attempted" && !pastHeld {
				pastHeld = true
				continue
			}
			if phase != "planned" {
				return false
			}
			pastHeld = true
		}
		return true
	case "closing", "attempted":
		return allDeletionAcquisitions(s.Deletion, "held") && s.Deletion.ResultDigest == ""
	case "deleted":
		want, err := OwnedDeletionResultDigest(s)
		if err != nil || s.Deletion.ResultDigest != want {
			return false
		}
		pastHeld := false
		for _, phase := range s.Deletion.Acquisitions {
			if phase == "held" && !pastHeld {
				continue
			}
			if phase == "terminal" && !pastHeld {
				pastHeld = true
				continue
			}
			if phase != "released" {
				return false
			}
			pastHeld = true
		}
		return true
	default:
		return false
	}
}

func allDeletionAcquisitions(d *OwnedDeletion, phase string) bool {
	for _, p := range d.Acquisitions {
		if p != phase {
			return false
		}
	}
	return true
}

// BeginOwnedDeletion grants one live source invocation before any ancestor or
// participant mutation. Replays only observe; there is no takeover or reset.
func (s *Store) BeginOwnedDeletion(ctx context.Context, expected State, intent Intent) (State, bool, error) {
	if !validState(expected) || expected.Creation == nil {
		return State{}, false, ErrInvalid
	}
	want, err := OwnedDeletionIntent(expected, intent.ID)
	if err != nil || !reflect.DeepEqual(want, intent) {
		return State{}, false, ErrInvalid
	}
	if expected.Deletion != nil {
		if !reflect.DeepEqual(*expected.Intent, intent) {
			return State{}, false, ErrConflict
		}
		return copyState(expected), false, nil
	}
	if expected.Phase != "open" {
		return State{}, false, ErrPending
	}
	next := copyState(expected)
	next.Intent = &want
	next.Deletion = &OwnedDeletion{Acquisitions: make([]string, len(next.Ancestors))}
	for i := range next.Deletion.Acquisitions {
		next.Deletion.Acquisitions[i] = "planned"
	}
	return s.cas(ctx, expected, next)
}

func (s *Store) SealOwnedDeletion(ctx context.Context, expected State) (State, bool, error) {
	if !validState(expected) || expected.Deletion == nil {
		return State{}, false, ErrInvalid
	}
	if expected.Phase != "open" {
		return copyState(expected), false, nil
	}
	if !allDeletionAcquisitions(expected.Deletion, "held") {
		return State{}, false, ErrPending
	}
	next := copyState(expected)
	next.Phase = "closing"
	return s.cas(ctx, expected, next)
}

// RecordOwnedDeletionApplied requires this live caller's acknowledged exact
// native delete. A missing namespace or attempted receipt is NOT that proof.
func (s *Store) RecordOwnedDeletionApplied(ctx context.Context, expected State, digest string) (State, bool, error) {
	if !validState(expected) || expected.Deletion == nil {
		return State{}, false, ErrInvalid
	}
	want, err := OwnedDeletionResultDigest(expected)
	if err != nil || want != digest {
		return State{}, false, ErrInvalid
	}
	if expected.Phase == "deleted" {
		return copyState(expected), false, nil
	}
	if expected.Phase != "attempted" {
		return State{}, false, ErrPending
	}
	next := copyState(expected)
	next.Phase = "deleted"
	next.Deletion.ResultDigest = digest
	return s.cas(ctx, expected, next)
}
