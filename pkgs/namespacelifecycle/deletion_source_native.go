package namespacelifecycle

import "context"

// NativeDeletionSource reuses the exact source identity adapter. It performs no
// cleanup and cannot recreate missing objects or infer deletion from absence.
type NativeDeletionSource struct{ store *NativeNamespaceStore }

func NewNativeDeletionSource(store *NativeNamespaceStore) (*NativeDeletionSource, error) {
	if store == nil {
		return nil, ErrInvalid
	}
	return &NativeDeletionSource{store: store}, nil
}
func (s *NativeDeletionSource) Verify(ctx context.Context, state State) error {
	return (&NativeCreationSource{store: s.store}).Verify(ctx, state)
}
func (s *NativeDeletionSource) HasChildren(ctx context.Context, ref Namespace) (bool, error) {
	return s.store.HasChildren(ctx, ref)
}
func (s *NativeDeletionSource) Delete(ctx context.Context, state State) error {
	if !validState(state) || state.Deletion == nil || state.Phase != "attempted" {
		return ErrInvalid
	}
	expected, err := creationNativeIdentity(state)
	if err != nil {
		return err
	}
	return s.store.DeleteOnce(ctx, expected)
}
