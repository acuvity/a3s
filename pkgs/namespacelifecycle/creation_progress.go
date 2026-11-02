package namespacelifecycle

import "context"

// The source coordinator must hold the current live creation claim before
// initiating any acquisition/enrollment/native mutation. These low-level record
// transitions do not turn reconstructed state into that invocation capability.
func (s *Store) AttemptCreationAcquisition(ctx context.Context, expected State, index int) (State, bool, error) {
	if !validState(expected) || expected.Creation == nil || index < 0 || index >= len(expected.Ancestors) {
		return State{}, false, ErrInvalid
	}
	c := expected.Creation
	if c.Phase != "claimed" {
		return State{}, false, ErrPending
	}
	if c.Acquisitions[index] != "planned" {
		return State{}, false, nil
	}
	for i := 0; i < index; i++ {
		if c.Acquisitions[i] != "held" {
			return State{}, false, ErrPending
		}
	}
	next := copyState(expected)
	next.Creation.Acquisitions[index] = "attempted"
	return s.cas(ctx, expected, next)
}

// ConfirmCreationAcquisition records only an acknowledged exact ancestor grant.
// Reading a matching ancestor pin is not a substitute for that acknowledgement.
func (s *Store) ConfirmCreationAcquisition(ctx context.Context, expected State, index int) (State, bool, error) {
	if !validState(expected) || expected.Creation == nil || index < 0 || index >= len(expected.Ancestors) {
		return State{}, false, ErrInvalid
	}
	c := expected.Creation
	if c.Phase != "claimed" || c.Acquisitions[index] != "attempted" {
		return State{}, false, ErrPending
	}
	next := copyState(expected)
	next.Creation.Acquisitions[index] = "held"
	return s.cas(ctx, expected, next)
}

// AttemptNativeCreation is one acknowledged dispatch transition within the live
// owner invocation. Reconciliation can never acquire a second native insertion.
func (s *Store) AttemptNativeCreation(ctx context.Context, expected State) (State, bool, error) {
	if !validState(expected) || expected.Creation == nil {
		return State{}, false, ErrInvalid
	}
	c := expected.Creation
	if c.Phase == "native-attempted" || c.Phase == "applied" || c.Phase == "ready" {
		return State{}, false, nil
	}
	if c.Phase != "claimed" || !allAcquisitions(c, "held") {
		return State{}, false, ErrPending
	}
	next := copyState(expected)
	next.Creation.Phase = "native-attempted"
	return s.cas(ctx, expected, next)
}

// ConfirmCreationApplied requires the adapter's exact native-row marker proof.
// The digest alone is not that proof and absence can never confirm application.
func (s *Store) ConfirmCreationApplied(ctx context.Context, expected State, markerDigest string) (State, bool, error) {
	if !validState(expected) || expected.Creation == nil {
		return State{}, false, ErrInvalid
	}
	want, err := CreationMarkerDigest(expected)
	if err != nil || markerDigest != want {
		return State{}, false, ErrInvalid
	}
	if expected.Creation.Phase == "applied" || expected.Creation.Phase == "ready" {
		return State{}, false, nil
	}
	if expected.Creation.Phase != "native-attempted" {
		return State{}, false, ErrPending
	}
	next := copyState(expected)
	next.Creation.Phase = "applied"
	next.Creation.ApplicationDigest = markerDigest
	return s.cas(ctx, expected, next)
}

func (s *Store) AttemptCreationEnrollment(ctx context.Context, expected State, participant string) (State, bool, error) {
	if !validState(expected) || expected.Creation == nil {
		return State{}, false, ErrInvalid
	}
	if expected.Creation.Phase != "applied" {
		return State{}, false, ErrPending
	}
	for i, e := range expected.Creation.Enrollments {
		if e.Participant != participant {
			continue
		}
		if e.Phase != "planned" {
			return State{}, false, nil
		}
		for j := 0; j < i; j++ {
			if expected.Creation.Enrollments[j].Phase != "confirmed" {
				return State{}, false, ErrPending
			}
		}
		next := copyState(expected)
		next.Creation.Enrollments[i].Phase = "attempted"
		next.Creation.Enrollments[i].RegistryID = expected.Namespace.ID
		return s.cas(ctx, expected, next)
	}
	return State{}, false, ErrInvalid
}

// ClaimCreationEnrollment is called by the authenticated recipient before its
// one registry insertion. Only an acknowledged matching CAS grants that live
// invocation; an existing claimed/confirmed state is observation, not a grant.
func (s *Store) ClaimCreationEnrollment(ctx context.Context, expected State, participant, registryID string) (State, bool, error) {
	if !validState(expected) || expected.Creation == nil || registryID != expected.Namespace.ID {
		return State{}, false, ErrInvalid
	}
	if expected.Creation.Phase != "applied" || expected.Phase != "forming" {
		return State{}, false, ErrPending
	}
	for i, enrollment := range expected.Creation.Enrollments {
		if enrollment.Participant != participant {
			continue
		}
		if enrollment.RegistryID != registryID {
			return State{}, false, ErrConflict
		}
		if enrollment.Phase == "claimed" || enrollment.Phase == "confirmed" {
			return copyState(expected), false, nil
		}
		if enrollment.Phase != "attempted" {
			return State{}, false, ErrPending
		}
		next := copyState(expected)
		next.Creation.Enrollments[i].Phase = "claimed"
		return s.cas(ctx, expected, next)
	}
	return State{}, false, ErrInvalid
}

// ConfirmCreationEnrollment requires an authenticated participant's exact
// retained enrollment proof. It does not authorize or dispatch enrollment.
func (s *Store) ConfirmCreationEnrollment(ctx context.Context, expected State, proof EnrollmentProof) (State, bool, error) {
	if !validState(expected) || expected.Creation == nil || expected.Namespace.ID != proof.NamespaceID || expected.Creation.OperationID != proof.OperationID || proof.RegistryID != expected.Namespace.ID || !digestPattern.MatchString(proof.Digest) {
		return State{}, false, ErrInvalid
	}
	if expected.Creation.Phase != "applied" {
		return State{}, false, ErrPending
	}
	for i, e := range expected.Creation.Enrollments {
		if e.Participant != proof.Participant {
			continue
		}
		if e.Phase == "confirmed" {
			if e.RegistryID != proof.RegistryID || e.Digest != proof.Digest {
				return State{}, false, ErrConflict
			}
			return State{}, false, nil
		}
		if e.Phase != "claimed" || e.RegistryID != proof.RegistryID {
			return State{}, false, ErrPending
		}
		next := copyState(expected)
		next.Creation.Enrollments[i] = CreationEnrollment{Participant: e.Participant, Phase: "confirmed", RegistryID: proof.RegistryID, Digest: proof.Digest}
		return s.cas(ctx, expected, next)
	}
	return State{}, false, ErrInvalid
}

// RecordCreationPinTerminal/Released are called only after the corresponding
// exact ancestor transition is durably proved. Never clear or infer another pin.
func (s *Store) RecordCreationPinTerminal(ctx context.Context, expected State, index int) (State, bool, error) {
	return s.creationPinProgress(ctx, expected, index, "held", "terminal")
}
func (s *Store) RecordCreationPinReleased(ctx context.Context, expected State, index int) (State, bool, error) {
	return s.creationPinProgress(ctx, expected, index, "terminal", "released")
}
func (s *Store) creationPinProgress(ctx context.Context, expected State, index int, from, to string) (State, bool, error) {
	if !validState(expected) || expected.Creation == nil || index < 0 || index >= len(expected.Ancestors) {
		return State{}, false, ErrInvalid
	}
	c := expected.Creation
	if c.Phase != "applied" || !allEnrolled(c) {
		return State{}, false, ErrPending
	}
	if c.Acquisitions[index] == to {
		return State{}, false, nil
	}
	if c.Acquisitions[index] != from {
		return State{}, false, ErrPending
	}
	for i := index + 1; i < len(c.Acquisitions); i++ {
		if c.Acquisitions[i] != "released" {
			return State{}, false, ErrPending
		}
	}
	next := copyState(expected)
	next.Creation.Acquisitions[index] = to
	return s.cas(ctx, expected, next)
}

func (s *Store) MarkCreationReady(ctx context.Context, expected State) (State, bool, error) {
	if !validState(expected) || expected.Creation == nil {
		return State{}, false, ErrInvalid
	}
	c := expected.Creation
	if c.Phase == "ready" {
		return State{}, false, nil
	}
	if c.Phase != "applied" || !allEnrolled(c) || !allAcquisitions(c, "released") {
		return State{}, false, ErrPending
	}
	next := copyState(expected)
	next.Creation.Phase = "ready"
	next.Phase = "open"
	return s.cas(ctx, expected, next)
}
