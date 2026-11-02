package namespacelifecycle

import (
	"context"
	"reflect"
)

// DeletionSource is an exact native boundary. Delete returns nil only for an
// acknowledged one-row deletion, never for absence or an uncertain outcome.
type DeletionSource interface {
	Verify(context.Context, State) error
	HasChildren(context.Context, Namespace) (bool, error)
	Delete(context.Context, State) error
}

// DeletionParticipants must verify real retained, authenticated participant
// fences/drains. Observe never initiates a fence or repairs a missing record.
type DeletionParticipants interface {
	Prepare(context.Context, State, string) (DrainProof, error)
	Observe(context.Context, State, string) (DrainProof, error)
}

type Deleter struct {
	store        *Store
	source       DeletionSource
	participants DeletionParticipants
}

func NewDeleter(store *Store, source DeletionSource, participants DeletionParticipants) (*Deleter, error) {
	if store == nil || source == nil || participants == nil {
		return nil, ErrUnavailable
	}
	return &Deleter{store: store, source: source, participants: participants}, nil
}

// Delete requires a currently authorized source DELETE invocation. Initial
// preparation is single-use. A later authorized invocation may claim the still
// UNATTEMPTED native-delete stage only after exact retained drain proof; it can
// never replay an attempted native deletion or unfinished initial preparation.
func (d *Deleter) Delete(ctx context.Context, ref Namespace, operationID string) (State, error) {
	if d == nil || ctx == nil {
		return State{}, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, OwnerOperationTimeout)
	defer cancel()
	state, err := d.store.Get(ctx, ref.ID)
	if err != nil {
		return State{}, err
	}
	if state.Namespace != ref || state.Creation == nil || state.Creation.Phase != "ready" || ref.Name == "/" {
		return state, ErrInvalid
	}
	fresh := state.Deletion == nil
	if fresh {
		intent, err := OwnedDeletionIntent(state, operationID)
		if err != nil {
			return state, err
		}
		// Refuse an already-observed nonleaf before consuming its single-use
		// claim or ancestor pins. This read is not a topology fence: the
		// post-seal leaf checks remain authoritative. Retained deletion/replay
		// paths must not require a native row that may already be deleted.
		if d.source.Verify(ctx, copyState(state)) != nil {
			return state, ErrPending
		}
		children, err := d.source.HasChildren(ctx, state.Namespace)
		if err != nil || children {
			return state, ErrPending
		}
		var won bool
		state, won, err = d.store.BeginOwnedDeletion(ctx, state, intent)
		if err != nil {
			return state, err
		}
		if !won {
			return state, ErrPending
		}
		for i := range state.Ancestors {
			state, err = d.acquire(ctx, state, i)
			if err != nil {
				return state, err
			}
		}
		state, won, err = d.store.SealOwnedDeletion(ctx, state)
		if err != nil {
			return state, err
		}
		if !won {
			return state, ErrPending
		}
	}
	if state.Phase == "deleted" {
		return d.settle(ctx, state)
	}
	if state.Phase != "closing" {
		return state, ErrPending
	}
	if err := d.leaf(ctx, state); err != nil {
		return state, err
	}
	if fresh {
		// Initiate every configured participant once, even if another is held.
		// Existing/cold intents use Observe only, never reissue preparation.
		for _, participant := range state.Intent.Participants {
			_, _ = d.participants.Prepare(ctx, copyState(state), participant)
		}
	}
	state, err = d.observeDrains(ctx, state)
	if err != nil {
		return state, err
	}
	if err := d.leaf(ctx, state); err != nil {
		return state, err
	}
	// The fresh acknowledged CAS is the only native dispatch grant. Merely
	// observing closing/drained state never grants deletion.
	state, won, err := d.store.AttemptDelete(ctx, state)
	if err != nil {
		return state, err
	}
	if !won {
		return state, ErrPending
	}
	if err := d.source.Delete(ctx, copyState(state)); err != nil {
		return state, ErrUnknown
	}
	digest, err := OwnedDeletionResultDigest(state)
	if err != nil {
		return state, err
	}
	state, won, err = d.store.RecordOwnedDeletionApplied(ctx, state, digest)
	if err != nil {
		return state, err
	}
	if !won {
		return state, ErrPending
	}
	return d.settle(ctx, state)
}

// Reconcile is read/metadata-only: it cannot prepare participants or claim a
// native delete. An attempted native result with no durable proof remains held.
func (d *Deleter) Reconcile(ctx context.Context, ref Namespace) (State, error) {
	if d == nil || ctx == nil {
		return State{}, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, OwnerOperationTimeout)
	defer cancel()
	state, err := d.store.Get(ctx, ref.ID)
	if err != nil {
		return State{}, err
	}
	if state.Namespace != ref || state.Deletion == nil {
		return state, ErrConflict
	}
	if state.Phase == "deleted" {
		return d.settle(ctx, state)
	}
	if state.Phase == "closing" {
		state, err = d.observeDrains(ctx, state)
		if err != nil {
			return state, err
		}
	}
	return state, ErrPending
}

func (d *Deleter) ancestor(ctx context.Context, state State, index int) (State, error) {
	ancestor, err := d.store.Get(ctx, state.Ancestors[index].ID)
	if err != nil {
		return State{}, err
	}
	if ancestor.Namespace != state.Ancestors[index] || ancestor.Creation == nil || ancestor.Creation.Phase != "ready" || !reflect.DeepEqual(ancestor.Ancestors, state.Ancestors[:index]) {
		return State{}, ErrPending
	}
	return ancestor, nil
}
func (d *Deleter) acquire(ctx context.Context, state State, index int) (State, error) {
	state, won, err := d.store.AttemptDeletionAcquisition(ctx, state, index)
	if err != nil {
		return state, err
	}
	if !won {
		return state, ErrPending
	}
	pin, err := DeletionPin(state, index)
	if err != nil {
		return state, err
	}
	for range 4 {
		ancestor, err := d.ancestor(ctx, state, index)
		if err != nil {
			return state, err
		}
		if ancestor.Phase != "open" || ancestor.Deletion != nil {
			return state, ErrPending
		}
		_, won, err := d.store.Admit(ctx, ancestor, pin)
		if err != nil {
			return state, err
		}
		if won {
			next, changed, err := d.store.ConfirmDeletionAcquisition(ctx, state, index)
			if err != nil {
				return state, err
			}
			if !changed {
				return state, ErrPending
			}
			return next, nil
		}
	}
	return state, ErrPending
}
func (d *Deleter) leaf(ctx context.Context, state State) error {
	current, err := d.store.Get(ctx, state.Namespace.ID)
	if err != nil {
		return err
	}
	if current.Deletion == nil || current.Phase != "closing" || !reflect.DeepEqual(current.Intent, state.Intent) || len(current.Pins) != 0 {
		return ErrPending
	}
	if d.source.Verify(ctx, copyState(current)) != nil {
		return ErrPending
	}
	for i := range current.Ancestors {
		ancestor, err := d.ancestor(ctx, current, i)
		if err != nil {
			return err
		}
		if d.source.Verify(ctx, copyState(ancestor)) != nil {
			return ErrPending
		}
	}
	children, err := d.source.HasChildren(ctx, current.Namespace)
	if err != nil || children {
		return ErrPending
	}
	return nil
}
func (d *Deleter) observeDrains(ctx context.Context, state State) (State, error) {
	for _, participant := range state.Intent.Participants {
		proof, err := d.participants.Observe(ctx, copyState(state), participant)
		if err != nil {
			return state, ErrPending
		}
		if proof.Participant != participant || proof.NamespaceID != state.Namespace.ID || proof.IntentID != state.Intent.ID {
			return state, ErrConflict
		}
		current, err := d.store.Get(ctx, state.Namespace.ID)
		if err != nil {
			return state, err
		}
		if !reflect.DeepEqual(current.Intent, state.Intent) || current.Phase != "closing" {
			return state, ErrPending
		}
		next, changed, err := d.store.RecordDrain(ctx, current, proof)
		if err != nil {
			return state, err
		}
		if changed {
			state = next
		} else {
			state = current
			found := false
			for _, p := range state.Drains {
				if p == proof {
					found = true
				}
			}
			if !found {
				return state, ErrPending
			}
		}
	}
	return state, nil
}

func (d *Deleter) settle(ctx context.Context, state State) (State, error) {
	for i := len(state.Ancestors) - 1; i >= 0; i-- {
		if state.Deletion.Acquisitions[i] == "released" {
			continue
		}
		pin, err := DeletionPin(state, i)
		if err != nil {
			return state, err
		}
		ancestor, err := d.ancestor(ctx, state, i)
		if err != nil {
			return state, err
		}
		proof := TerminalProof{Kind: "applied", ReferenceID: state.Intent.ID, Digest: state.Deletion.ResultDigest}
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
				ancestor, changed, err = d.store.RecordTerminal(ctx, ancestor, pin, proof)
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
		}
		if state.Deletion.Acquisitions[i] == "held" {
			var changed bool
			state, changed, err = d.store.RecordDeletionPinTerminal(ctx, state, i)
			if err != nil {
				return state, err
			}
			if !changed {
				return state, ErrPending
			}
		}
		_, changed, err := d.store.Release(ctx, ancestor, pin)
		if err != nil {
			return state, err
		}
		if !changed {
			return state, ErrPending
		}
		state, changed, err = d.store.RecordDeletionPinReleased(ctx, state, i)
		if err != nil {
			return state, err
		}
		if !changed {
			return state, ErrPending
		}
	}
	return state, nil
}
