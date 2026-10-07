package namespacelifecycle

import "slices"

// DeletionSnapshot binds the enrolled source incarnation and its current sealed
// owner intent. It is metadata, not a native-delete or participant-write grant.
type DeletionSnapshot struct {
	SchemaVersion string          `json:"schemaVersion"`
	Scope         EnrollmentScope `json:"scope"`
	OperationID   string          `json:"operationID"`
	Digest        string          `json:"digest"`
	Participant   string          `json:"participant"`
	RegistryID    string          `json:"registryID"`
	SourcePhase   string          `json:"sourcePhase"`
	Intent        Intent          `json:"intent"`
}

func SnapshotDeletion(state State, participant, registryID, intentID string) (DeletionSnapshot, error) {
	if !validState(state) || state.Creation == nil || state.Creation.Origin != "create" || state.Creation.Phase != "ready" || state.Deletion == nil || state.Intent == nil || registryID != state.Namespace.ID || state.Intent.ID != intentID || !slices.Contains(state.Intent.Participants, participant) {
		return DeletionSnapshot{}, ErrInvalid
	}
	if state.Phase != "closing" && state.Phase != "attempted" && state.Phase != "deleted" {
		return DeletionSnapshot{}, ErrPending
	}
	digest, err := CreationMarkerDigest(state)
	if err != nil {
		return DeletionSnapshot{}, err
	}
	intent := *state.Intent
	intent.Participants = slices.Clone(intent.Participants)
	return DeletionSnapshot{SchemaVersion: "namespace-deletion.v1", Scope: EnrollmentScope{Namespace: state.Namespace, Ancestors: slices.Clone(state.Ancestors)}, OperationID: state.Creation.OperationID, Digest: digest, Participant: participant, RegistryID: registryID, SourcePhase: state.Phase, Intent: intent}, nil
}
