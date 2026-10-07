package namespacelifecycle

import (
	"context"
	"reflect"
	"slices"
	"strings"
)

// Admit grants ONLY this acknowledged live invocation a registration/topology
// reservation. A separate durable operation record must prevent re-admission of
// a previously completed operation. Existing pins never renew execution rights.
func (s *Store) Admit(ctx context.Context, expected State, pin Pin) (State, bool, error) {
	if !validState(expected) || !validPin(pin, expected.Namespace) || pin.Terminal != nil {
		return State{}, false, ErrInvalid
	}
	if expected.Phase != "open" {
		return State{}, false, nil
	}
	if len(expected.Pins) >= MaxPins {
		return State{}, false, ErrPending
	}
	for _, p := range expected.Pins {
		if p.ID == pin.ID {
			return State{}, false, ErrConflict
		}
	}
	next := copyState(expected)
	next.Pins = append(next.Pins, pin)
	slices.SortFunc(next.Pins, func(a, b Pin) int { return strings.Compare(a.ID, b.ID) })
	if !admissionFits(next) {
		return State{}, false, ErrPending
	}
	return s.cas(ctx, expected, next)
}

// RecordTerminal is trusted owner composition. The owner MUST establish durable
// exact application evidence, or retain the live single-use authority proving
// no write was invoked. Missing documents, timeouts and cancellation are not proof.
func (s *Store) RecordTerminal(ctx context.Context, expected State, pin Pin, proof TerminalProof) (State, bool, error) {
	if !validState(expected) || !validPin(pin, expected.Namespace) || pin.Terminal != nil || !validTerminal(proof) {
		return State{}, false, ErrInvalid
	}
	next := copyState(expected)
	for i, p := range next.Pins {
		if p.ID != pin.ID {
			continue
		}
		terminal := p.Terminal
		p.Terminal = nil
		if !reflect.DeepEqual(p, pin) {
			return State{}, false, ErrConflict
		}
		if terminal != nil {
			if *terminal != proof {
				return State{}, false, ErrConflict
			}
			return State{}, false, nil
		}
		next.Pins[i].Terminal = &proof
		return s.cas(ctx, expected, next)
	}
	return State{}, false, ErrConflict
}

// Release removes only a matching durably terminal pin, including while sealed.
// No implicit expiration, cleanup-on-return or cold recovery release exists.
func (s *Store) Release(ctx context.Context, expected State, pin Pin) (State, bool, error) {
	if !validState(expected) || !validPin(pin, expected.Namespace) || pin.Terminal != nil {
		return State{}, false, ErrInvalid
	}
	next := copyState(expected)
	for i, p := range next.Pins {
		if p.ID != pin.ID {
			continue
		}
		terminal := p.Terminal
		p.Terminal = nil
		if !reflect.DeepEqual(p, pin) {
			return State{}, false, ErrConflict
		}
		if terminal == nil {
			return State{}, false, ErrPending
		}
		next.Pins = slices.Delete(next.Pins, i, i+1)
		return s.cas(ctx, expected, next)
	}
	return State{}, false, ErrConflict
}

// Seal records the immutable owner deletion intent before destructive work.
// Existing admissions are preserved. There is deliberately no reopen operation.
func (s *Store) Seal(ctx context.Context, expected State, intent Intent) (State, bool, error) {
	if !validState(expected) || expected.Namespace.Name == "/" || !validIntent(intent) {
		return State{}, false, ErrInvalid
	}
	if expected.Intent != nil {
		if !reflect.DeepEqual(*expected.Intent, intent) {
			return State{}, false, ErrConflict
		}
		return State{}, false, nil
	}
	next := copyState(expected)
	next.Phase = "closing"
	intent.Participants = slices.Clone(intent.Participants)
	next.Intent = &intent
	return s.cas(ctx, expected, next)
}

// RecordDrain accepts only an exact configured participant proof after local
// topology/registration reservations settle. The authenticated participant
// adapter, not a request body or digest, must establish the proof's authority.
func (s *Store) RecordDrain(ctx context.Context, expected State, proof DrainProof) (State, bool, error) {
	if !validState(expected) || expected.Phase != "closing" || proof.IntentID != expected.Intent.ID || proof.NamespaceID != expected.Namespace.ID || !slices.Contains(expected.Intent.Participants, proof.Participant) || !digestPattern.MatchString(proof.Digest) {
		return State{}, false, ErrInvalid
	}
	if len(expected.Pins) != 0 {
		return State{}, false, ErrPending
	}
	for _, p := range expected.Drains {
		if p.Participant != proof.Participant {
			continue
		}
		if p != proof {
			return State{}, false, ErrConflict
		}
		return State{}, false, nil
	}
	next := copyState(expected)
	next.Drains = append(next.Drains, proof)
	slices.SortFunc(next.Drains, func(a, b DrainProof) int { return strings.Compare(a.Participant, b.Participant) })
	return s.cas(ctx, expected, next)
}

// AttemptDelete grants one live invocation deletion dispatch only on an
// acknowledged matching CAS. Read-back of attempted state cannot grant it again.
func (s *Store) AttemptDelete(ctx context.Context, expected State) (State, bool, error) {
	if !validState(expected) {
		return State{}, false, ErrInvalid
	}
	if expected.Phase == "attempted" || expected.Phase == "deleted" {
		return State{}, false, nil
	}
	if expected.Phase != "closing" || len(expected.Pins) != 0 || len(expected.Drains) != len(expected.Intent.Participants) {
		return State{}, false, ErrPending
	}
	next := copyState(expected)
	next.Phase = "attempted"
	return s.cas(ctx, expected, next)
}

// ConfirmDeleted is called ONLY after the owner proves deletion of the exact
// native incarnation and settles its native mutation. It neither performs that
// deletion nor authorizes cleanup/recreation. The retained name fence remains.
func (s *Store) ConfirmDeleted(ctx context.Context, expected State) (State, bool, error) {
	if !validState(expected) {
		return State{}, false, ErrInvalid
	}
	if expected.Phase == "deleted" {
		return State{}, false, nil
	}
	if expected.Phase != "attempted" {
		return State{}, false, ErrConflict
	}
	next := copyState(expected)
	next.Phase = "deleted"
	return s.cas(ctx, expected, next)
}
