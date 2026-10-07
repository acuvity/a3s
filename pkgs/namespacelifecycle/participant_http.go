package namespacelifecycle

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

const participantHTTPMaxBytes = 32 * 1024

// ParticipantTokenProvider supplies a trusted short-lived bearer for one
// attempt. It must honor ctx; neither token values nor callback errors are logged
// or retained. The callback, not a token value, is retained by the client.
type ParticipantTokenProvider func(context.Context) (string, error)

// HTTPParticipants is the explicit, trusted Hanni adapter. Observe is read-only
// even when the participant registry is absent. No runtime wiring enables it.
type HTTPParticipants struct {
	endpoint    string
	client      http.Client
	token       ParticipantTokenProvider
	participant string
}

var _ CreationParticipants = (*HTTPParticipants)(nil)

func NewHTTPParticipants(trustedURL string, client *http.Client, tokenProvider ParticipantTokenProvider, participantID string) (*HTTPParticipants, error) {
	u, err := url.Parse(trustedURL)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" || (u.Path != "" && u.Path != "/") || client == nil || tokenProvider == nil || participantID != "hanni" {
		return nil, ErrInvalid
	}
	if u.Scheme != "https" {
		ip := net.ParseIP(u.Hostname())
		if u.Scheme != "http" || ip == nil || !ip.IsLoopback() {
			return nil, ErrInvalid
		}
	}
	u.Path = "/findingpublicationnamespaces"
	owned := *client
	owned.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	owned.Jar = nil
	if owned.Timeout <= 0 || owned.Timeout > 10*time.Second {
		owned.Timeout = 10 * time.Second
	}
	return &HTTPParticipants{endpoint: u.String(), client: owned, token: tokenProvider, participant: participantID}, nil
}

func (p *HTTPParticipants) Enroll(ctx context.Context, state State, participant string) (EnrollmentProof, error) {
	return p.request(ctx, state, participant, "Enroll")
}

func (p *HTTPParticipants) Observe(ctx context.Context, state State, participant string) (EnrollmentProof, error) {
	return p.request(ctx, state, participant, "Inspect")
}

func (p *HTTPParticipants) request(ctx context.Context, state State, participant, action string) (EnrollmentProof, error) {
	if participant != p.participant {
		return EnrollmentProof{}, ErrInvalid
	}
	// Snapshot and digest are computed before any callback/network work from a
	// detached, validated source snapshot, never from response authority flags.
	snapshot, err := SnapshotEnrollment(state, participant, state.Namespace.ID)
	if err != nil {
		return EnrollmentProof{}, err
	}
	digest, err := participantEnrollmentDigest(snapshot)
	if err != nil {
		return EnrollmentProof{}, err
	}
	expected := EnrollmentProof{Participant: participant, NamespaceID: snapshot.Scope.Namespace.ID, OperationID: snapshot.OperationID, RegistryID: snapshot.RegistryID, Digest: digest}
	command := struct {
		Action      string `json:"action"`
		NamespaceID string `json:"namespaceID"`
		OperationID string `json:"operationID"`
		Participant string `json:"participant"`
		RegistryID  string `json:"registryID"`
	}{action, expected.NamespaceID, expected.OperationID, participant, expected.RegistryID}
	body, err := json.Marshal(command)
	if err != nil || len(body) > participantHTTPMaxBytes {
		return EnrollmentProof{}, ErrInvalid
	}
	data, err := p.post(ctx, snapshot.Scope.Namespace.Name, body)
	if err != nil {
		return EnrollmentProof{}, err
	}
	proof, err := decodeParticipantProof(data)
	if err != nil || proof != expected {
		return EnrollmentProof{}, ErrConflict
	}
	return proof, nil
}

// This field order is the participant-enrollment.v1 wire contract. Go's ordinary
// compact JSON encoding (including its string escaping) is part of the digest.
func participantEnrollmentDigest(snapshot EnrollmentSnapshot) (string, error) {
	wire := struct {
		SchemaVersion string `json:"schemaVersion"`
		RegistryID    string `json:"registryID"`
		Enrollment    struct {
			OperationID string          `json:"operationID"`
			Digest      string          `json:"digest"`
			Scope       EnrollmentScope `json:"scope"`
		} `json:"enrollment"`
	}{SchemaVersion: "participant-enrollment.v1", RegistryID: snapshot.RegistryID}
	wire.Enrollment.OperationID, wire.Enrollment.Digest = snapshot.OperationID, snapshot.Digest
	wire.Enrollment.Scope = snapshot.Scope
	data, err := json.Marshal(wire)
	if err != nil || len(data) > participantHTTPMaxBytes {
		return "", ErrInvalid
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:]), nil
}

func decodeParticipantProof(data []byte) (EnrollmentProof, error) {
	var out EnrollmentProof
	d := json.NewDecoder(bytes.NewReader(data))
	if token, err := d.Token(); err != nil || token != json.Delim('{') {
		return out, ErrInvalid
	}
	if token, err := d.Token(); err != nil || token != "proof" {
		return out, ErrInvalid
	}
	if token, err := d.Token(); err != nil || token != json.Delim('{') {
		return out, ErrInvalid
	}
	fields := map[string]*string{"participant": &out.Participant, "namespaceID": &out.NamespaceID, "operationID": &out.OperationID, "registryID": &out.RegistryID, "digest": &out.Digest}
	for d.More() {
		token, err := d.Token()
		if err != nil {
			return out, ErrInvalid
		}
		key, ok := token.(string)
		field, exists := fields[key]
		if !ok || !exists {
			return out, ErrInvalid
		}
		token, err = d.Token()
		value, ok := token.(string)
		if err != nil || !ok {
			return out, ErrInvalid
		}
		*field = value
		delete(fields, key)
	}
	if len(fields) != 0 {
		return out, ErrInvalid
	}
	for range 2 {
		if token, err := d.Token(); err != nil || token != json.Delim('}') {
			return out, ErrInvalid
		}
	}
	if _, err := d.Token(); err != io.EOF {
		return out, ErrInvalid
	}
	return out, nil
}
