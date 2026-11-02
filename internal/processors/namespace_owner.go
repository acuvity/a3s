package processors

import (
	"context"
	"net/http"
	"slices"

	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/a3s/pkgs/crud"
	"go.acuvity.ai/a3s/pkgs/namespacelifecycle"
	"go.acuvity.ai/bahamut"
	"go.acuvity.ai/elemental"
	"go.acuvity.ai/manipulate"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// NamespaceOwnerOptions is trusted, explicit development composition. No main
// path or configuration option enables it. Callers must retain normal native
// HTTP authentication/authorization and qualified writer/cleaner exclusion.
type NamespaceOwnerOptions struct {
	Store                *namespacelifecycle.Store
	Native               *namespacelifecycle.NativeNamespaceStore
	Participants         namespacelifecycle.CreationParticipants
	RequiredParticipants []string
	DeletionParticipants namespacelifecycle.DeletionParticipants
	Authorize            NamespaceOwnerAuthorityFactory
}

func NewOwnerNamespacesProcessor(m manipulate.Manipulator, pubsub bahamut.PubSubClient, owner NamespaceOwnerOptions) (*NamespacesProcessor, error) {
	if m == nil || owner.Store == nil || owner.Native == nil || owner.Participants == nil || owner.Authorize == nil || len(owner.RequiredParticipants) == 0 || len(owner.RequiredParticipants) > namespacelifecycle.MaxParticipants {
		return nil, namespacelifecycle.ErrInvalid
	}
	owner.RequiredParticipants = slices.Clone(owner.RequiredParticipants)
	for i, p := range owner.RequiredParticipants {
		if p == "" || i > 0 && p <= owner.RequiredParticipants[i-1] {
			return nil, namespacelifecycle.ErrInvalid
		}
	}
	processor := NewNamespacesProcessor(m, pubsub)
	processor.owner = &owner
	return processor, nil
}

func ownerNamespaceError() error {
	return elemental.NewError("Conflict", "Namespace lifecycle is held", "a3s", http.StatusConflict)
}

func ownerNamespaceRequest(bctx bahamut.Context) error {
	r := bctx.Request()
	if r == nil || r.Namespace == "" || r.Recursive || r.Propagated || r.OverrideProtection || r.ParentID != "" || !ownerNamespaceNoQuery(r) || len(r.Order) != 0 || r.Page != 0 || r.PageSize != 0 || r.After != "" || r.Limit != 0 {
		return elemental.NewError("Validation Error", "Namespace lifecycle request options are unsupported", "a3s", http.StatusUnprocessableEntity)
	}
	return nil
}

func ownerNamespaceNoQuery(r *elemental.Request) bool {
	if h := r.HTTPRequest(); h != nil && h.URL != nil && (h.URL.RawQuery != "" || h.URL.ForceQuery) {
		return false
	}
	// Elemental installs the empty schema-defined q parameter for DELETE even
	// without a URL query. It is not a caller filter and must not block the path.
	for name, parameter := range r.Parameters {
		if name != "q" || len(parameter.Values()) != 0 || parameter.StringValue() != "" {
			return false
		}
	}
	return true
}

func (p *NamespacesProcessor) createOwnedNamespace(bctx bahamut.Context, ns *api.Namespace) error {
	if err := ownerNamespaceRequest(bctx); err != nil {
		return err
	}
	check, err := p.owner.Authorize(bctx)
	if err != nil || check == nil {
		return participationError(http.StatusForbidden)
	}
	adapter := &namespaceOwnerMutator{Manipulator: p.manipulator, owner: p.owner, scope: bctx.Request().Namespace, authorize: check}
	return crud.Create(bctx, adapter, ns, crud.OptionPostWriteHook(func(obj elemental.Identifiable) {
		if adapter.created {
			p.makeNotify(elemental.OperationCreate)(obj)
		}
	}))
}

func (p *NamespacesProcessor) deleteOwnedNamespace(bctx bahamut.Context) error {
	if err := ownerNamespaceRequest(bctx); err != nil {
		return err
	}
	check, authErr := p.owner.Authorize(bctx)
	if authErr != nil || check == nil {
		return participationError(http.StatusForbidden)
	}
	if p.owner.DeletionParticipants == nil {
		return ownerNamespaceError()
	}
	// An exact retained terminal owner record may finish metadata-only release
	// after the native row is gone. It never authorizes another native delete.
	state, err := p.owner.Store.Get(bctx.Context(), bctx.Request().ObjectID)
	if err == nil && state.Phase == "deleted" && state.Deletion != nil {
		if len(state.Ancestors) == 0 || state.Ancestors[len(state.Ancestors)-1].Name != bctx.Request().Namespace {
			return ownerNamespaceError()
		}
		source, err := namespacelifecycle.NewNativeDeletionSource(p.owner.Native)
		if err != nil {
			return ownerNamespaceError()
		}
		deleter, err := namespacelifecycle.NewDeleter(p.owner.Store, authorizedNamespaceDeletion{source: source, check: check}, p.owner.DeletionParticipants)
		if err != nil {
			return ownerNamespaceError()
		}
		if _, err := deleter.Reconcile(bctx.Context(), state.Namespace); err != nil {
			return ownerNamespaceError()
		}
		if err := check(bctx.Context()); err != nil {
			return err
		}
		// Terminal metadata can outlive a lost acknowledgement/notification. A
		// replay repairs only non-destructive cache invalidation, never deletion.
		p.makeNotify(elemental.OperationUpdate)(&api.Namespace{ID: state.Namespace.ID, Name: state.Namespace.Name, Namespace: bctx.Request().Namespace})
		bctx.SetStatusCode(http.StatusNoContent)
		bctx.SetOutputData(nil)
		return nil
	}
	// Keep scoped native retrieval. A successful owner deletion invalidates
	// caches with Update, never name-only destructive cleanup or a legacy record.
	adapter := &namespaceOwnerMutator{Manipulator: p.manipulator, owner: p.owner, scope: bctx.Request().Namespace, authorize: check}
	return crud.Delete(bctx, adapter, api.NewNamespace(), crud.OptionPostWriteHook(p.makeNotify(elemental.OperationUpdate)))
}

type namespaceOwnerMutator struct {
	manipulate.Manipulator
	owner     *NamespaceOwnerOptions
	scope     string
	created   bool
	authorize func(context.Context) error
}

func (m *namespaceOwnerMutator) Create(mctx manipulate.Context, obj elemental.Identifiable) error {
	ns, ok := obj.(*api.Namespace)
	if !ok || ns.Namespace != m.scope || m.authorize == nil || m.authorize(mctx.Context()) != nil {
		return ownerNamespaceError()
	}
	parent, err := m.owner.Store.GetByName(mctx.Context(), m.scope)
	if err != nil || parent.Creation == nil || parent.Creation.Phase != "ready" || parent.Phase != "open" {
		return ownerNamespaceError()
	}
	ancestors := append(slices.Clone(parent.Ancestors), parent.Namespace)
	ref := namespacelifecycle.Namespace{ID: bson.NewObjectID().Hex(), Name: ns.Name}
	operationID := bson.NewObjectID().Hex()
	binding, source, err := namespacelifecycle.PrepareOwnerNamespace(m.owner.Native, ns, ref, ancestors, operationID, ns.CreateTime, m.owner.RequiredParticipants)
	if err != nil {
		return ownerNamespaceError()
	}
	creator, err := namespacelifecycle.NewCreator(m.owner.Store, authorizedNamespaceCreation{source: source, check: m.authorize}, m.owner.Participants)
	if err != nil {
		return ownerNamespaceError()
	}
	state, err := creator.Create(mctx.Context(), ref, ancestors, binding)
	if err != nil {
		return ownerNamespaceError()
	}
	stored := api.NewNamespace()
	stored.ID = state.Namespace.ID
	if err := m.Retrieve(manipulate.NewContext(mctx.Context(), manipulate.ContextOptionNamespace(m.scope), manipulate.ContextOptionReadConsistency(manipulate.ReadConsistencyStrong)), stored); err != nil {
		return ownerNamespaceError()
	}
	if stored.ID != state.Namespace.ID || stored.Name != state.Namespace.Name || stored.Namespace != m.scope {
		return ownerNamespaceError()
	}
	*ns = *stored
	m.created = state.Creation.OperationID == operationID
	return nil
}

func (m *namespaceOwnerMutator) Delete(mctx manipulate.Context, obj elemental.Identifiable) error {
	ns, ok := obj.(*api.Namespace)
	if !ok || ns.Namespace != m.scope || m.owner.DeletionParticipants == nil || m.authorize == nil || m.authorize(mctx.Context()) != nil {
		return ownerNamespaceError()
	}
	source, err := namespacelifecycle.NewNativeDeletionSource(m.owner.Native)
	if err != nil {
		return ownerNamespaceError()
	}
	deleter, err := namespacelifecycle.NewDeleter(m.owner.Store, authorizedNamespaceDeletion{source: source, check: m.authorize}, m.owner.DeletionParticipants)
	if err != nil {
		return ownerNamespaceError()
	}
	if _, err := deleter.Delete(mctx.Context(), namespacelifecycle.Namespace{ID: ns.ID, Name: ns.Name}, bson.NewObjectID().Hex()); err != nil {
		return ownerNamespaceError()
	}
	return nil
}
