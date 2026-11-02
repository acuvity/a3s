package namespacelifecycle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
)

// CreationMarker binds immutable owner input, not mutable namespace attributes.
// Its bytes are private native-row metadata, never a caller-supplied grant.
func CreationMarker(s State) (string, error) {
	c := s.Creation
	if c == nil || c.Origin != "create" || !validNamespace(s.Namespace) || !keyPattern.MatchString(c.OperationID) || !digestPattern.MatchString(c.Digest) {
		return "", ErrInvalid
	}
	ancestors, err := json.Marshal(s.Ancestors)
	if err != nil {
		return "", ErrInvalid
	}
	participants, err := json.Marshal(c.Participants)
	if err != nil {
		return "", ErrInvalid
	}
	ancestry := sha256.Sum256(ancestors)
	policy := sha256.Sum256(participants)
	marker := struct {
		Version      string    `json:"version"`
		Namespace    Namespace `json:"namespace"`
		OperationID  string    `json:"operationID"`
		Digest       string    `json:"digest"`
		CreatedAt    string    `json:"createdAt"`
		Ancestry     string    `json:"ancestry"`
		Participants string    `json:"participants"`
	}{"namespace-creation.v1", s.Namespace, c.OperationID, c.Digest, c.CreatedAt, hex.EncodeToString(ancestry[:]), hex.EncodeToString(policy[:])}
	encoded, err := json.Marshal(marker)
	if err != nil || len(encoded) > 2048 {
		return "", ErrInvalid
	}
	return string(encoded), nil
}

func CreationMarkerDigest(s State) (string, error) {
	marker, err := CreationMarker(s)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(marker))
	return hex.EncodeToString(digest[:]), nil
}

func CreationPin(s State, index int) (Pin, error) {
	if s.Creation == nil || index < 0 || index >= len(s.Ancestors) {
		return Pin{}, ErrInvalid
	}
	marker, err := CreationMarker(s)
	if err != nil {
		return Pin{}, err
	}
	digest := sha256.Sum256([]byte(marker))
	id := sha256.Sum256([]byte(marker + ":ancestor:" + strconv.Itoa(index)))
	return Pin{ID: "create:" + hex.EncodeToString(id[:]), Kind: "namespace-create", Target: s.Namespace, Digest: hex.EncodeToString(digest[:])}, nil
}
