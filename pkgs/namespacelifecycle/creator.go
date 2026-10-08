package namespacelifecycle

import (
	"context"
	"errors"
	"reflect"
	"time"
)

// CreationSource is a trusted outer adapter, with owned/prevalidated input. It
// verifies native immutable bindings, performs one native insert only when
// called, and reads exact application evidence. It does not grant authorization.
type CreationSource interface {
	Verify(context.Context, State) error
	Insert(context.Context, State) error
	Observe(context.Context, State) (string, error)
}

// CreationParticipants authenticates real source-owned enrollment. Observe must
// only retrieve existing retained proof; it must never initialize on a miss.
type CreationParticipants interface {
	Enroll(context.Context, State, string) (EnrollmentProof, error)
	Observe(context.Context, State, string) (EnrollmentProof, error)
}

// OwnerOperationTimeout bounds one cooperative source attempt, not an unknown
// write's lifetime or server rollback. Retained work never expires with it.
const OwnerOperationTimeout = 30 * time.Second

type Creator struct {
	store        *Store
	source       CreationSource
	participants CreationParticipants
}

func NewCreator(store *Store, source CreationSource, participants CreationParticipants) (*Creator, error) {
	if store == nil || source == nil || participants == nil {
		return nil, ErrUnavailable
	}
	return &Creator{store: store, source: source, participants: participants}, nil
}

// Create is invoked only after ordinary current namespace-CRUD authorization.
// Existing reservations can reconcile but never receive another invocation claim.
func (c *Creator) Create(ctx context.Context, ref Namespace, ancestors []Namespace, binding Creation) (State, error) {
	if c == nil || ctx == nil {
		return State{}, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, OwnerOperationTimeout)
	defer cancel()
	existing, err := c.store.GetByName(ctx, ref.Name)
	if err == nil {
		if existing.Creation == nil || existing.Creation.Origin != "create" {
			return existing, ErrPending
		}
		if existing.Creation.Digest != binding.Digest || !reflect.DeepEqual(existing.Ancestors, ancestors) || !reflect.DeepEqual(existing.Creation.Participants, binding.Participants) {
			return State{}, ErrConflict
		}
		return c.Reconcile(ctx, existing.Namespace)
	}
	if !errors.Is(err, ErrNotFound) {
		return State{}, err
	}
	state, err := c.store.ReserveCreation(ctx, ref, ancestors, binding)
	if err != nil {
		return State{}, err
	}
	state, won, err := c.store.ClaimCreation(ctx, state)
	if err != nil {
		return State{}, err
	}
	if !won {
		return State{}, ErrPending
	}
	// This lexical invocation is the only live owner. A cold claimed snapshot
	// never reenters this path, even when no native insert is visible yet.
	for i := range state.Ancestors {
		state, err = c.acquire(ctx, state, i)
		if err != nil {
			return state, err
		}
	}
	// Verify every exact source incarnation while all topology pins are held.
	for i, ref := range state.Ancestors {
		ancestor, err := c.ancestor(ctx, state, i)
		if err != nil {
			return state, err
		}
		if ancestor.Namespace != ref {
			return state, ErrConflict
		}
		if err := c.source.Verify(ctx, copyState(ancestor)); err != nil {
			return state, ErrPending
		}
	}
	state, won, err = c.store.AttemptNativeCreation(ctx, state)
	if err != nil {
		return state, err
	}
	if !won {
		return state, ErrPending
	}
	// Always use exact read-back, including after an ambiguous insert. No new
	// application insert is issued from a return value, timeout or read-back.
	_ = c.source.Insert(ctx, copyState(state))
	state, err = c.confirmSource(ctx, state)
	if err != nil {
		return state, err
	}
	for _, participant := range state.Creation.Participants {
		state, won, err = c.store.AttemptCreationEnrollment(ctx, state, participant)
		if err != nil {
			return state, err
		}
		if !won {
			return state, ErrPending
		}
		_, _ = c.participants.Enroll(ctx, copyState(state), participant)
		state, err = c.confirmEnrollment(ctx, state, participant)
		if err != nil {
			return state, err
		}
	}
	return c.settle(ctx, state)
}

func (c *Creator) ancestor(ctx context.Context, child State, index int) (State, error) {
	ref := child.Ancestors[index]
	state, err := c.store.Get(ctx, ref.ID)
	if err != nil {
		return State{}, err
	}
	if state.Namespace != ref || state.Creation == nil || state.Creation.Phase != "ready" || !reflect.DeepEqual(state.Ancestors, child.Ancestors[:index]) {
		return State{}, ErrPending
	}
	return state, nil
}

func (c *Creator) acquire(ctx context.Context, state State, index int) (State, error) {
	state, won, err := c.store.AttemptCreationAcquisition(ctx, state, index)
	if err != nil {
		return state, err
	}
	if !won {
		return state, ErrPending
	}
	pin, err := CreationPin(state, index)
	if err != nil {
		return state, err
	}
	// Only known zero-match contention can retry, serially and with the exact
	// same binding. Ambiguous outcomes stop this live invocation immediately.
	for range 4 {
		ancestor, err := c.ancestor(ctx, state, index)
		if err != nil {
			return state, err
		}
		if ancestor.Phase != "open" {
			return state, ErrPending
		}
		_, won, err := c.store.Admit(ctx, ancestor, pin)
		if err != nil {
			return state, err
		}
		if won {
			next, recorded, err := c.store.ConfirmCreationAcquisition(ctx, state, index)
			if err != nil {
				return state, err
			}
			if !recorded {
				return state, ErrPending
			}
			return next, nil
		}
	}
	return state, ErrPending
}

// Reconcile never initiates native creation or participant enrollment. It only
// records existing exact evidence and settles its terminal topology pins.
func (c *Creator) Reconcile(ctx context.Context, ref Namespace) (State, error) {
	if c == nil || ctx == nil {
		return State{}, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, OwnerOperationTimeout)
	defer cancel()
	state, err := c.store.Get(ctx, ref.ID)
	if err != nil {
		return State{}, err
	}
	if state.Namespace != ref || state.Creation == nil || state.Creation.Origin != "create" {
		return State{}, ErrConflict
	}
	if state.Creation.Phase == "ready" {
		if state.Phase != "open" {
			return state, ErrPending
		}
		if err := c.verifyReadyEvidence(ctx, state); err != nil {
			return state, err
		}
		return state, nil
	}
	if state.Creation.Phase == "native-attempted" {
		state, err = c.confirmSource(ctx, state)
		if err != nil {
			return state, err
		}
	}
	if state.Creation.Phase != "applied" {
		return state, ErrPending
	}
	for _, enrollment := range state.Creation.Enrollments {
		if enrollment.Phase == "confirmed" {
			continue
		}
		if enrollment.Phase != "attempted" && enrollment.Phase != "claimed" {
			return state, ErrPending
		}
		state, err = c.confirmEnrollment(ctx, state, enrollment.Participant)
		if err != nil {
			return state, err
		}
	}
	return c.settle(ctx, state)
}

func (c *Creator) confirmSource(ctx context.Context, state State) (State, error) {
	proof, err := c.source.Observe(ctx, copyState(state))
	if err != nil {
		return state, ErrPending
	}
	next, changed, err := c.store.ConfirmCreationApplied(ctx, state, proof)
	if err != nil {
		return state, err
	}
	if !changed {
		return state, ErrPending
	}
	return next, nil
}
func (c *Creator) confirmEnrollment(ctx context.Context, state State, participant string) (State, error) {
	proof, err := c.participants.Observe(ctx, copyState(state), participant)
	if err != nil {
		return state, ErrPending
	}
	// The recipient consumes its owner claim through a separate request. Refresh
	// that acknowledged phase without adopting a different immutable creation.
	current, err := c.store.Get(ctx, state.Namespace.ID)
	if err != nil {
		return state, err
	}
	before, beforeErr := CreationMarkerDigest(state)
	after, afterErr := CreationMarkerDigest(current)
	if beforeErr != nil || afterErr != nil || before != after {
		return state, ErrConflict
	}
	next, changed, err := c.store.ConfirmCreationEnrollment(ctx, current, proof)
	if err != nil {
		return state, err
	}
	if !changed {
		for _, enrollment := range current.Creation.Enrollments {
			if enrollment.Participant == participant && enrollment.Phase == "confirmed" && enrollment.RegistryID == proof.RegistryID && enrollment.Digest == proof.Digest {
				return current, nil
			}
		}
		return state, ErrPending
	}
	return next, nil
}

// These are fresh exact evidence checks, not a lease. The cooperative owner
// protocol must still fence deletion/replacement throughout forming/readiness.
func (c *Creator) verifyReadyEvidence(ctx context.Context, state State) error {
	if c.source.Verify(ctx, copyState(state)) != nil {
		return ErrPending
	}
	for _, enrollment := range state.Creation.Enrollments {
		if enrollment.Phase != "confirmed" {
			return ErrPending
		}
		proof, err := c.participants.Observe(ctx, copyState(state), enrollment.Participant)
		if err != nil || proof.Participant != enrollment.Participant || proof.OperationID != state.Creation.OperationID || proof.NamespaceID != state.Namespace.ID || proof.RegistryID != enrollment.RegistryID || proof.Digest != enrollment.Digest {
			return ErrPending
		}
	}
	return nil
}

func (c *Creator) settle(ctx context.Context, state State) (State, error) {
	if err := c.verifyReadyEvidence(ctx, state); err != nil {
		return state, err
	}
	for i := len(state.Ancestors) - 1; i >= 0; i-- {
		if state.Creation.Acquisitions[i] == "released" {
			continue
		}
		pin, err := CreationPin(state, i)
		if err != nil {
			return state, err
		}
		ancestor, err := c.ancestor(ctx, state, i)
		if err != nil {
			return state, err
		}
		proof := TerminalProof{Kind: "applied", ReferenceID: state.Creation.OperationID, Digest: state.Creation.ApplicationDigest}
		found := false
		for _, retained := range ancestor.Pins {
			if retained.ID != pin.ID {
				continue
			}
			found = true
			exact := retained
			exact.Terminal = nil
			if !reflect.DeepEqual(exact, pin) {
				return state, ErrConflict
			}
			if retained.Terminal == nil {
				var changed bool
				ancestor, changed, err = c.store.RecordTerminal(ctx, ancestor, pin, proof)
				if err != nil {
					return state, err
				}
				if !changed {
					return state, ErrPending
				}
			} else if *retained.Terminal != proof {
				return state, ErrConflict
			}
		}
		if !found {
			return state, ErrPending
		} // Missing is not an exact release receipt.
		if state.Creation.Acquisitions[i] == "held" {
			var changed bool
			state, changed, err = c.store.RecordCreationPinTerminal(ctx, state, i)
			if err != nil {
				return state, err
			}
			if !changed {
				return state, ErrPending
			}
		}
		_, changed, err := c.store.Release(ctx, ancestor, pin)
		if err != nil {
			return state, err
		}
		if !changed {
			return state, ErrPending
		}
		state, changed, err = c.store.RecordCreationPinReleased(ctx, state, i)
		if err != nil {
			return state, err
		}
		if !changed {
			return state, ErrPending
		}
	}
	if err := c.verifyReadyEvidence(ctx, state); err != nil {
		return state, err
	}
	next, changed, err := c.store.MarkCreationReady(ctx, state)
	if err != nil {
		return state, err
	}
	if !changed {
		return state, ErrPending
	}
	return next, nil
}
