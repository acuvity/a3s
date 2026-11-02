package notification

import (
	"context"
	"testing"

	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/elemental"
	"go.acuvity.ai/manipulate"
	"go.acuvity.ai/manipulate/maniptest"
)

type namespaceCleanerModelManager struct {
	elemental.ModelManager
	identities []elemental.Identity
}

func (m namespaceCleanerModelManager) AllIdentities() []elemental.Identity {
	return m.identities
}

func TestNamespaceCleanerLiteralSubtree(t *testing.T) {
	for _, target := range []string{"/a.b", "/"} {
		t.Run(target, func(t *testing.T) {
			namespaces := []string{"/", "/a.b", "/a.b/c", "/a.b/c/d", "/axb", "/axb/c", "/a.bc", "/a.bc/c", "relative"}
			identities := []elemental.Identity{api.GroupIdentity, api.NamespaceDeletionRecordIdentity}
			stored := map[elemental.Identity]map[string]*api.Group{}
			for _, identity := range identities {
				stored[identity] = map[string]*api.Group{}
				for _, ns := range namespaces {
					stored[identity][ns] = &api.Group{Namespace: ns}
				}
			}

			m := maniptest.NewTestManipulator()
			calls := 0
			m.MockDeleteMany(t, func(mctx manipulate.Context, identity elemental.Identity) error {
				calls++
				// Model storage's intersection of implicit namespace and explicit filters.
				var filters []*elemental.Filter
				if mctx.Namespace() != "" {
					filters = append(filters, manipulate.NewNamespaceFilter(mctx.Namespace(), mctx.Recursive()))
				}
				if mctx.Filter() != nil {
					filters = append(filters, mctx.Filter())
				}
				filter := elemental.NewFilterComposer().And(filters...).Done()
				for ns, object := range stored[identity] {
					matched, err := elemental.MatchesFilter(object, filter)
					if err != nil {
						return err
					}
					if matched {
						delete(stored[identity], ns)
					}
				}
				return nil
			})

			handler := MakeNamespaceCleaner(context.Background(), m,
				namespaceCleanerModelManager{identities: identities}, api.NamespaceDeletionRecordIdentity)
			handler(&Message{Type: string(elemental.OperationCreate), Data: target})
			if calls != 0 {
				t.Fatal("non-delete notification invoked cleanup")
			}
			handler(&Message{Type: string(elemental.OperationDelete), Data: target})
			if calls != 1 {
				t.Fatalf("DeleteMany calls = %d, want 1 (ignored identity must be skipped)", calls)
			}
			for _, identity := range identities {
				for _, ns := range namespaces {
					inSubtree := ns == "/a.b" || ns == "/a.b/c" || ns == "/a.b/c/d"
					if target == "/" {
						inSubtree = ns != "relative"
					}
					wantDeleted := identity == api.GroupIdentity && inSubtree
					_, remains := stored[identity][ns]
					if remains == wantDeleted {
						t.Errorf("%s namespace %q: deleted = %t, want %t", identity.Category, ns, !remains, wantDeleted)
					}
				}
			}
		})
	}
}
