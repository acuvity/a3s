package namespacelifecycle

import "slices"

type EnrollmentScope struct {
	Namespace Namespace   `json:"namespace"`
	Ancestors []Namespace `json:"ancestors"`
}

// EnrollmentSnapshot is bounded owner metadata, not a live mutation capability.
// Only a fresh acknowledged ClaimCreationEnrollment result can grant insertion.
type EnrollmentSnapshot struct {
	SchemaVersion string          `json:"schemaVersion"`
	Scope         EnrollmentScope `json:"scope"`
	OperationID   string          `json:"operationID"`
	Digest        string          `json:"digest"`
	Participant   string          `json:"participant"`
	RegistryID    string          `json:"registryID"`
	SourcePhase   string          `json:"sourcePhase"`
	Phase         string          `json:"phase"`
}

func SnapshotEnrollment(state State, participant, registryID string) (EnrollmentSnapshot, error) {
	if !validState(state) || state.Creation == nil || state.Creation.Origin != "create" || registryID != state.Namespace.ID {
		return EnrollmentSnapshot{}, ErrInvalid
	}
	if (state.Phase != "forming" && state.Phase != "open") || (state.Creation.Phase != "applied" && state.Creation.Phase != "ready") {
		return EnrollmentSnapshot{}, ErrPending
	}
	for _, enrollment := range state.Creation.Enrollments {
		if enrollment.Participant != participant {
			continue
		}
		if enrollment.RegistryID != registryID || (enrollment.Phase != "attempted" && enrollment.Phase != "claimed" && enrollment.Phase != "confirmed") {
			return EnrollmentSnapshot{}, ErrPending
		}
		digest, err := CreationMarkerDigest(state)
		if err != nil {
			return EnrollmentSnapshot{}, err
		}
		return EnrollmentSnapshot{SchemaVersion: "namespace-enrollment.v1", Scope: EnrollmentScope{Namespace: state.Namespace, Ancestors: slices.Clone(state.Ancestors)}, OperationID: state.Creation.OperationID, Digest: digest, Participant: participant, RegistryID: registryID, SourcePhase: state.Creation.Phase, Phase: enrollment.Phase}, nil
	}
	return EnrollmentSnapshot{}, ErrInvalid
}
