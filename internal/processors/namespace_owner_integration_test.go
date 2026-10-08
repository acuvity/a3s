//go:build integration

package processors

import (
	"context"
	"testing"
	"time"

	"go.acuvity.ai/a3s/internal/mongofixture"
	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/a3s/pkgs/indexes"
	"go.acuvity.ai/a3s/pkgs/namespacelifecycle"
	"go.acuvity.ai/bahamut"
	"go.acuvity.ai/elemental"
	"go.acuvity.ai/manipulate"
	"go.acuvity.ai/manipulate/manipmongo"
	"go.mongodb.org/mongo-driver/v2/bson"
)

type unavailableNamespaceParticipant struct{ enrolls int }

func (p *unavailableNamespaceParticipant) Enroll(context.Context, namespacelifecycle.State, string) (namespacelifecycle.EnrollmentProof, error) {
	p.enrolls++
	return namespacelifecycle.EnrollmentProof{}, namespacelifecycle.ErrUnavailable
}
func (*unavailableNamespaceParticipant) Observe(context.Context, namespacelifecycle.State, string) (namespacelifecycle.EnrollmentProof, error) {
	return namespacelifecycle.EnrollmentProof{}, namespacelifecycle.ErrNotFound
}

func TestOwnerNamespaceProcessorKeepsUnprovedCreationAndDeletionHeld(t *testing.T) {
	ctx := context.Background()
	m := mongofixture.New(t)
	if err := manipmongo.CreateIndex(m, api.NamespaceIdentity, indexes.GetIndexes("a3s", api.Manager())[api.NamespaceIdentity]...); err != nil {
		t.Fatal(err)
	}
	native, err := namespacelifecycle.NewNativeNamespaceStore(m)
	if err != nil {
		t.Fatal(err)
	}
	store, err := namespacelifecycle.NewStore(m)
	if err != nil {
		t.Fatal(err)
	}
	root := namespacelifecycle.Namespace{ID: bson.NewObjectID().Hex(), Name: "/"}
	at := time.Now().UTC().Truncate(time.Millisecond)
	marker := "bootstrap:" + root.ID
	prepared, err := namespacelifecycle.PrepareNativeNamespace(api.NewNamespace(), namespacelifecycle.NativeNamespaceIdentity{Namespace: root, Parent: "root", CreatedAt: at, Marker: marker})
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := native.InsertOnce(ctx, prepared)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.BootstrapRoot(ctx, root, marker, evidence.Digest, at); err != nil {
		t.Fatal(err)
	}
	peer := &unavailableNamespaceParticipant{}
	processor, err := NewOwnerNamespacesProcessor(m, nil, NamespaceOwnerOptions{Store: store, Native: native, Participants: peer, RequiredParticipants: []string{"hanni"}, Authorize: func(bahamut.Context) (func(context.Context) error, error) {
		return func(context.Context) error { return nil }, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	create := func() *bahamut.MockContext {
		bctx := bahamut.NewMockContext(ctx)
		bctx.MockRequest = &elemental.Request{Namespace: "/", Operation: elemental.OperationCreate, Identity: api.NamespaceIdentity}
		input := api.NewNamespace()
		input.Name = "owned"
		bctx.SetInputData(input)
		return bctx
	}
	if err := processor.ProcessCreate(create()); err == nil {
		t.Fatal("unavailable participant produced successful create")
	}
	state, err := store.GetByName(ctx, "/owned")
	if err != nil || state.Creation.Phase != "applied" {
		t.Fatalf("source operation not retained: %+v %v", state, err)
	}
	namespace := api.NewNamespace()
	namespace.ID = state.Namespace.ID
	if err := m.Retrieve(manipulate.NewContext(ctx, manipulate.ContextOptionNamespace("/")), namespace); err != nil {
		t.Fatal(err)
	}
	if namespace.Name != "/owned" || namespace.CreationMarker == "" {
		t.Fatal("prebound native namespace/marker not retained")
	}
	if err := processor.ProcessCreate(create()); err == nil || peer.enrolls != 1 {
		t.Fatalf("replay dispatched enrollment: %v count=%d", err, peer.enrolls)
	}
	remove := bahamut.NewMockContext(ctx)
	remove.MockRequest = &elemental.Request{Namespace: "/", Operation: elemental.OperationDelete, Identity: api.NamespaceIdentity, ObjectID: namespace.ID}
	if err := processor.ProcessDelete(remove); err == nil {
		t.Fatal("unqualified drain deleted native namespace")
	}
	if err := m.Retrieve(manipulate.NewContext(ctx, manipulate.ContextOptionNamespace("/")), namespace); err != nil {
		t.Fatal("held delete lost namespace", err)
	}
	count, err := m.Count(manipulate.NewContext(ctx), api.NamespaceDeletionRecordIdentity)
	if err != nil || count != 0 {
		t.Fatalf("held delete emitted cleanup authority: %d %v", count, err)
	}
	parent, err := store.Get(ctx, root.ID)
	if err != nil || len(parent.Pins) != 1 {
		t.Fatal("unproved source operation released topology pin", err)
	}
}
