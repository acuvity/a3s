package processors

import (
	"context"
	"testing"

	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/a3s/pkgs/namespacelifecycle"
	"go.acuvity.ai/bahamut"
	"go.acuvity.ai/elemental"
)

type namespaceMutationProbe struct{ inserts, deletes int }

func (*namespaceMutationProbe) Verify(context.Context, namespacelifecycle.State) error { return nil }
func (p *namespaceMutationProbe) Insert(context.Context, namespacelifecycle.State) error {
	p.inserts++
	return nil
}
func (*namespaceMutationProbe) Observe(context.Context, namespacelifecycle.State) (string, error) {
	return "", nil
}
func (*namespaceMutationProbe) HasChildren(context.Context, namespacelifecycle.Namespace) (bool, error) {
	return false, nil
}
func (p *namespaceMutationProbe) Delete(context.Context, namespacelifecycle.State) error {
	p.deletes++
	return nil
}

func TestNamespaceOwnerReauthorizesOriginalUserBeforeMutation(t *testing.T) {
	for _, operation := range []elemental.Operation{elemental.OperationCreate, elemental.OperationDelete} {
		t.Run(string(operation), func(t *testing.T) {
			f := participationAuth(t)
			f.policy.Permissions = []string{"namespaces:" + string(operation)}
			r := elemental.NewRequest()
			r.Namespace = "/target"
			r.Identity = api.NamespaceIdentity
			r.Operation = operation
			r.ClientIP = "127.0.0.1"
			r.Password = f.bearer(t, nil)
			if operation == elemental.OperationDelete {
				r.ObjectID = "111111111111111111111111"
			}
			b := bahamut.NewMockContext(context.Background())
			b.MockRequest = r
			factory, err := NewNamespaceOwnerAuthorizer(f.auth.authenticator, f.retriever)
			if err != nil {
				t.Fatal(err)
			}
			check, err := factory(b)
			if err != nil {
				t.Fatal(err)
			}
			probe := &namespaceMutationProbe{}
			create := authorizedNamespaceCreation{source: probe, check: check}
			remove := authorizedNamespaceDeletion{source: probe, check: check}
			if err := check(context.Background()); err != nil {
				t.Fatal(err)
			}
			// Source/participant work can outlive the admission permission. The
			// current original user, not the participant service, owns this write.
			f.retriever.revoked = true
			if operation == elemental.OperationCreate {
				err = create.Insert(context.Background(), namespacelifecycle.State{})
			} else {
				err = remove.Delete(context.Background(), namespacelifecycle.State{})
			}
			if err == nil || probe.inserts != 0 || probe.deletes != 0 {
				t.Fatalf("revoked user mutated source: %v %+v", err, probe)
			}
			f.retriever.revoked = false
			r.Namespace = "/retargeted"
			if err := check(context.Background()); err == nil {
				t.Fatal("request authority retargeted")
			}
			r.Namespace = "/target"
			f.policy.Permissions = []string{"namespaceparticipations:create"}
			if err := check(context.Background()); err == nil {
				t.Fatal("participant right substituted for namespace mutation")
			}
		})
	}
}
