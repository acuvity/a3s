package namespacelifecycle

import "context"

func (s *Store) AttemptDeletionAcquisition(ctx context.Context, expected State, index int) (State, bool, error) {
	if !validState(expected) || expected.Deletion == nil || index < 0 || index >= len(expected.Ancestors) {
		return State{}, false, ErrInvalid
	}
	if expected.Phase != "open" {
		return State{}, false, ErrPending
	}
	if expected.Deletion.Acquisitions[index] != "planned" {
		return State{}, false, nil
	}
	for i := 0; i < index; i++ {
		if expected.Deletion.Acquisitions[i] != "held" {
			return State{}, false, ErrPending
		}
	}
	next := copyState(expected)
	next.Deletion.Acquisitions[index] = "attempted"
	return s.cas(ctx, expected, next)
}
func (s *Store) ConfirmDeletionAcquisition(ctx context.Context, expected State, index int) (State, bool, error) {
	if !validState(expected) || expected.Deletion == nil || index < 0 || index >= len(expected.Ancestors) {
		return State{}, false, ErrInvalid
	}
	if expected.Phase != "open" || expected.Deletion.Acquisitions[index] != "attempted" {
		return State{}, false, ErrPending
	}
	next := copyState(expected)
	next.Deletion.Acquisitions[index] = "held"
	return s.cas(ctx, expected, next)
}
func (s *Store) RecordDeletionPinTerminal(ctx context.Context, expected State, index int) (State, bool, error) {
	return s.deletionPinProgress(ctx, expected, index, "held", "terminal")
}
func (s *Store) RecordDeletionPinReleased(ctx context.Context, expected State, index int) (State, bool, error) {
	return s.deletionPinProgress(ctx, expected, index, "terminal", "released")
}
func (s *Store) deletionPinProgress(ctx context.Context, expected State, index int, from, to string) (State, bool, error) {
	if !validState(expected) || expected.Deletion == nil || index < 0 || index >= len(expected.Ancestors) {
		return State{}, false, ErrInvalid
	}
	if expected.Phase != "deleted" {
		return State{}, false, ErrPending
	}
	if expected.Deletion.Acquisitions[index] == to {
		return State{}, false, nil
	}
	if expected.Deletion.Acquisitions[index] != from {
		return State{}, false, ErrPending
	}
	for i := index + 1; i < len(expected.Ancestors); i++ {
		if expected.Deletion.Acquisitions[i] != "released" {
			return State{}, false, ErrPending
		}
	}
	next := copyState(expected)
	next.Deletion.Acquisitions[index] = to
	return s.cas(ctx, expected, next)
}
