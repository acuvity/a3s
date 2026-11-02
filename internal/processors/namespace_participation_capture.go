package processors

import (
	"context"
	"net/http"

	"go.acuvity.ai/a3s/pkgs/namespacelifecycle"
	"go.acuvity.ai/bahamut"
)

// NewNamespaceCaptureProcessor explicitly adds read-only current-scope capture
// to the dormant participant endpoint. Normal main registration is unchanged;
// the native auth chain remains required. Existing constructor/store fakes do
// not acquire a capture capability or a new storage-interface method.
func NewNamespaceCaptureProcessor(store *namespacelifecycle.Store, native *namespacelifecycle.NativeNamespaceStore, authorizer *NamespaceParticipationAuthorizer) (*NamespaceParticipationProcessor, error) {
	capture, err := namespacelifecycle.NewCaptureInspector(store, native)
	if err != nil {
		return nil, err
	}
	p, err := NewNamespaceParticipationProcessor(store, authorizer)
	if err != nil {
		return nil, err
	}
	p.capture = capture
	return p, nil
}

func (p *NamespaceParticipationProcessor) processCapture(bctx bahamut.Context, command namespaceParticipationCommand) error {
	if p.capture == nil {
		return participationError(http.StatusConflict)
	}
	// Includes cryptographic and uncached permission/revocation reads, not just
	// storage work. Timeout is an operation bound, never a lease or retry grant.
	ctx, cancel := context.WithTimeout(bctx.Context(), namespacelifecycle.OwnerOperationTimeout)
	defer cancel()
	check, err := p.authorizer.bindContext(ctx, bctx, command)
	if err != nil {
		return err
	}
	snapshot, err := p.capture.Capture(ctx, bctx.Request().Namespace, check)
	if err != nil {
		return participationError(http.StatusConflict)
	}
	bctx.SetOutputData(namespaceParticipationResult{Granted: false, Snapshot: snapshot})
	return nil
}
