package namespacelifecycle

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
)

// HTTPDeletionParticipants is a distinct interface adapter so read-only
// enrollment Observe cannot accidentally be used as a drain or fence operation.
type HTTPDeletionParticipants struct{ transport *HTTPParticipants }

func NewHTTPDeletionParticipants(trustedURL string, client *http.Client, tokenProvider ParticipantTokenProvider, participantID string) (*HTTPDeletionParticipants, error) {
	transport, err := NewHTTPParticipants(trustedURL, client, tokenProvider, participantID)
	if err != nil {
		return nil, err
	}
	return &HTTPDeletionParticipants{transport: transport}, nil
}
func (p *HTTPDeletionParticipants) Prepare(ctx context.Context, state State, participant string) (DrainProof, error) {
	return p.request(ctx, state, participant, "PrepareDelete")
}
func (p *HTTPDeletionParticipants) Observe(ctx context.Context, state State, participant string) (DrainProof, error) {
	return p.request(ctx, state, participant, "InspectDelete")
}
func (p *HTTPDeletionParticipants) request(ctx context.Context, state State, participant, action string) (DrainProof, error) {
	if p == nil || p.transport == nil || participant != p.transport.participant || state.Intent == nil {
		return DrainProof{}, ErrInvalid
	}
	snapshot, err := SnapshotDeletion(state, participant, state.Namespace.ID, state.Intent.ID)
	if err != nil {
		return DrainProof{}, err
	}
	command := struct {
		Action           string `json:"action"`
		NamespaceID      string `json:"namespaceID"`
		OperationID      string `json:"operationID"`
		Participant      string `json:"participant"`
		RegistryID       string `json:"registryID"`
		DeletionIntentID string `json:"deletionIntentID"`
	}{action, snapshot.Scope.Namespace.ID, snapshot.OperationID, participant, snapshot.RegistryID, snapshot.Intent.ID}
	body, err := json.Marshal(command)
	if err != nil {
		return DrainProof{}, ErrInvalid
	}
	data, err := p.transport.post(ctx, snapshot.Scope.Namespace.Name, body)
	if err != nil {
		return DrainProof{}, err
	}
	proof, registryID, err := decodeDrainProof(data)
	if err != nil || registryID != snapshot.RegistryID || proof.IntentID != snapshot.Intent.ID || proof.NamespaceID != snapshot.Scope.Namespace.ID || proof.Participant != participant || !digestPattern.MatchString(proof.Digest) {
		return DrainProof{}, ErrConflict
	}
	return proof, nil
}

func decodeDrainProof(data []byte) (DrainProof, string, error) {
	var proof DrainProof
	var registryID string
	d := json.NewDecoder(bytes.NewReader(data))
	for _, want := range []any{json.Delim('{'), "drain", json.Delim('{')} {
		token, err := d.Token()
		if err != nil || token != want {
			return proof, "", ErrInvalid
		}
	}
	fields := map[string]*string{"intentID": &proof.IntentID, "namespaceID": &proof.NamespaceID, "participant": &proof.Participant, "registryID": &registryID, "digest": &proof.Digest}
	for d.More() {
		token, err := d.Token()
		name, ok := token.(string)
		field, found := fields[name]
		if err != nil || !ok || !found {
			return proof, "", ErrInvalid
		}
		token, err = d.Token()
		value, ok := token.(string)
		if err != nil || !ok {
			return proof, "", ErrInvalid
		}
		*field = value
		delete(fields, name)
	}
	if len(fields) != 0 {
		return proof, "", ErrInvalid
	}
	for range 2 {
		token, err := d.Token()
		if err != nil || token != json.Delim('}') {
			return proof, "", ErrInvalid
		}
	}
	if _, err := d.Token(); err != io.EOF {
		return proof, "", ErrInvalid
	}
	return proof, registryID, nil
}
