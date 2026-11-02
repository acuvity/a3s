package namespacelifecycle

import (
	"context"
	"encoding/json"
	"reflect"
	"slices"
)

// CaptureInspector reads current owner/source evidence only. It grants no
// admission, lease, historical provenance or retry, and never changes a row.
// Use at the original producer boundary before its first async/WAL handoff;
// this cannot bind already-buffered or previously unbound physical events.
type CaptureInspector struct {
	store  *Store
	source *NativeCreationSource
}

func NewCaptureInspector(store *Store, native *NativeNamespaceStore) (*CaptureInspector, error) {
	if store == nil || native == nil {
		return nil, ErrInvalid
	}
	return &CaptureInspector{store: store, source: &NativeCreationSource{store: native}}, nil
}

// Capture resolves the target by name, never by a caller incarnation assertion.
// check must revalidate the original request's current native authority; API
// permission is not proxy traffic or writer authority. Repeated reads detect
// observed drift, not a transaction or a fence against subsequent changes.
func (c *CaptureInspector) Capture(ctx context.Context, name string, check func() error) (EnrollmentSnapshot, error) {
	if c == nil || ctx == nil || check == nil {
		return EnrollmentSnapshot{}, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, OwnerOperationTimeout)
	defer cancel()
	guard := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := check(); err != nil {
			return err
		}
		return ctx.Err()
	}
	if err := guard(); err != nil {
		return EnrollmentSnapshot{}, err
	}
	target, err := c.store.GetByName(ctx, name)
	if err != nil {
		return EnrollmentSnapshot{}, err
	}
	if err := guard(); err != nil {
		return EnrollmentSnapshot{}, err
	}
	if !captureReady(target) {
		return EnrollmentSnapshot{}, ErrPending
	}
	snapshot, err := SnapshotEnrollment(target, "hanni", target.Namespace.ID)
	if err != nil || snapshot.SourcePhase != "ready" || snapshot.Phase != "confirmed" {
		return EnrollmentSnapshot{}, ErrPending
	}
	refs := append(slices.Clone(target.Ancestors), target.Namespace)
	retained := make([]State, len(refs))
	// Recheck the complete chain and native tuples after asynchronous reads.
	// At most 32 levels, two passes, bounded store attempts, one whole deadline.
	for pass := range 2 {
		for i, ref := range refs {
			if err := guard(); err != nil {
				return EnrollmentSnapshot{}, err
			}
			state, err := c.store.Get(ctx, ref.ID)
			if err != nil {
				return EnrollmentSnapshot{}, err
			}
			if err := guard(); err != nil {
				return EnrollmentSnapshot{}, err
			}
			if !captureReady(state) || state.Namespace != ref || !slices.Equal(state.Ancestors, refs[:i]) ||
				pass == 1 && !reflect.DeepEqual(state, retained[i]) || i == len(refs)-1 && !reflect.DeepEqual(state, target) {
				return EnrollmentSnapshot{}, ErrPending
			}
			if err := c.source.Verify(ctx, state); err != nil {
				return EnrollmentSnapshot{}, err
			}
			if err := guard(); err != nil {
				return EnrollmentSnapshot{}, err
			}
			retained[i] = state
		}
	}
	current, err := c.store.GetByName(ctx, name)
	if err != nil || !reflect.DeepEqual(current, target) {
		return EnrollmentSnapshot{}, ErrPending
	}
	if err := guard(); err != nil {
		return EnrollmentSnapshot{}, err
	}
	// The existing detached wire shape fits the participant transport's 32 KiB
	// envelope (including the granted/snapshot wrapper).
	encoded, err := json.Marshal(snapshot)
	if err != nil || len(encoded) > 32*1024-64 {
		return EnrollmentSnapshot{}, ErrInvalid
	}
	return snapshot, nil
}

func captureReady(state State) bool {
	return validState(state) && state.Version == "namespace-lifecycle.v2" && state.Phase == "open" &&
		state.Intent == nil && state.Deletion == nil && state.Creation != nil && state.Creation.Phase == "ready"
}
