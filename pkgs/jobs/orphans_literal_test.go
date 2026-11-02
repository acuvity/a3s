package jobs

import (
	"context"
	"fmt"
	"regexp"
	"testing"
	"time"

	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/elemental"
	"go.acuvity.ai/manipulate"
	"go.acuvity.ai/manipulate/maniptest"
)

type orphanCleanupDocument struct {
	namespace string
	created   *time.Time
}

// Evaluate the emitted filter over mock documents. The Elemental matcher does
// not support LesserThan, and manipmemory does not implement DeleteMany.
func matchesOrphanCleanupFilter(t *testing.T, f *elemental.Filter, document orphanCleanupDocument) bool {
	t.Helper()
	for i, operator := range f.Operators() {
		switch operator {
		case elemental.AndFilterOperator:
			for _, child := range f.AndFilters()[i] {
				if !matchesOrphanCleanupFilter(t, child, document) {
					return false
				}
			}
		case elemental.OrFilterOperator:
			matched := false
			for _, child := range f.OrFilters()[i] {
				matched = matched || matchesOrphanCleanupFilter(t, child, document)
			}
			if !matched {
				return false
			}
		case elemental.AndOperator:
			matched := false
			switch key, comparator := f.Keys()[i], f.Comparators()[i]; {
			case key == "namespace" && comparator == elemental.EqualComparator:
				matched = document.namespace == f.Values()[i][0].(string)
			case key == "namespace" && comparator == elemental.MatchComparator:
				pattern, err := regexp.Compile(f.Values()[i][0].(string))
				if err != nil {
					t.Fatal(err)
				}
				matched = pattern.MatchString(document.namespace)
			case key == "createTime" && comparator == elemental.NotExistsComparator:
				matched = document.created == nil
			case key == "createTime" && comparator == elemental.LesserComparator:
				matched = document.created != nil && document.created.Before(f.Values()[i][0].(time.Time))
			default:
				t.Fatalf("unsupported filter key %q comparator %v", key, comparator)
			}
			if !matched {
				return false
			}
		default:
			t.Fatalf("unsupported filter operator %v", operator)
		}
	}
	return true
}

func TestDeleteOrphanedObjectsLiteralSubtree(t *testing.T) {
	for _, target := range []string{"/a.b", "/"} {
		t.Run(target, func(t *testing.T) {
			cutoff := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
			before, after := cutoff.Add(-time.Second), cutoff.Add(time.Second)
			namespaces := []string{"/", "/a.b", "/a.b/c", "/a.b/c/d", "/axb", "/axb/c", "/a.bc", "/a.bc/c", "relative"}
			identities := []elemental.Identity{api.GroupIdentity, api.NamespaceDeletionRecordIdentity}
			stored := map[elemental.Identity]map[string]orphanCleanupDocument{}
			wantDeleted := map[elemental.Identity]map[string]bool{}
			for _, identity := range identities {
				stored[identity] = map[string]orphanCleanupDocument{}
				wantDeleted[identity] = map[string]bool{}
				for _, ns := range namespaces {
					inSubtree := ns == "/a.b" || ns == "/a.b/c" || ns == "/a.b/c/d"
					if target == "/" {
						inSubtree = ns != "relative"
					}
					for i, created := range []*time.Time{nil, &before, &cutoff, &after} {
						id := fmt.Sprintf("%s/time-%d", ns, i)
						stored[identity][id] = orphanCleanupDocument{namespace: ns, created: created}
						wantDeleted[identity][id] = identity == api.GroupIdentity && inSubtree && i < 2
					}
				}
			}

			nsm := maniptest.NewTestManipulator()
			nsm.MockRetrieveMany(t, func(_ manipulate.Context, dest elemental.Identifiables) error {
				id := "deletion-record"
				*dest.(*api.SparseNamespaceDeletionRecordsList) = api.SparseNamespaceDeletionRecordsList{
					{ID: &id, Namespace: &target, DeleteTime: &cutoff},
				}
				return nil
			})
			m := maniptest.NewTestManipulator()
			calls := 0
			m.MockDeleteMany(t, func(mctx manipulate.Context, identity elemental.Identity) error {
				calls++
				if mctx.Filter() == nil {
					t.Fatal("cleanup must be filtered")
				}
				for id, document := range stored[identity] {
					if matchesOrphanCleanupFilter(t, mctx.Filter(), document) {
						delete(stored[identity], id)
					}
				}
				return nil
			})
			if err := DeleteOrphanedObjects(context.Background(), nsm, m, identities); err != nil {
				t.Fatal(err)
			}
			if calls != 1 {
				t.Fatalf("DeleteMany calls = %d, want 1 (deletion records must be skipped)", calls)
			}
			for identity, documents := range wantDeleted {
				for id, deleted := range documents {
					_, remains := stored[identity][id]
					if remains == deleted {
						t.Errorf("%s %q: deleted = %t, want %t", identity.Category, id, !remains, deleted)
					}
				}
			}
		})
	}
}
