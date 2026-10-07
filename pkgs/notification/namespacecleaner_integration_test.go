//go:build integration

package notification

import (
	"context"
	"testing"

	"go.acuvity.ai/a3s/internal/mongofixture"
	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/elemental"
	"go.acuvity.ai/manipulate"
)

func TestNamespaceCleanerLiteralSubtreeMongo(t *testing.T) {
	ctx := context.Background()
	m := mongofixture.New(t)
	namespaces := []string{"/a.b", "/a.b/c", "/axb", "/axb/c", "/a.bc", "/a.bc/c"}
	groups := make(map[string]*api.Group, len(namespaces))
	for _, namespace := range namespaces {
		group := api.NewGroup()
		group.Name, group.Namespace = "fixture", namespace
		mctx := manipulate.NewContext(ctx, manipulate.ContextOptionNamespace(namespace))
		if err := m.Create(mctx, group); err != nil {
			t.Fatal(err)
		}
		if err := m.Retrieve(mctx, group); err != nil {
			t.Fatalf("fixture read-back %s: %v", namespace, err)
		}
		groups[namespace] = group
	}
	MakeNamespaceCleaner(ctx, m, namespaceCleanerModelManager{identities: []elemental.Identity{api.GroupIdentity}})(&Message{Type: string(elemental.OperationDelete), Data: "/a.b"})
	for namespace, group := range groups {
		mctx := manipulate.NewContext(ctx, manipulate.ContextOptionNamespace(namespace))
		err := m.Retrieve(mctx, group)
		wantDeleted := namespace == "/a.b" || namespace == "/a.b/c"
		if wantDeleted {
			if !manipulate.IsObjectNotFoundError(err) {
				t.Fatalf("%s not deleted: %v", namespace, err)
			}
		} else if err != nil {
			t.Fatalf("literal sibling %s was affected: %v", namespace, err)
		}
	}
}
