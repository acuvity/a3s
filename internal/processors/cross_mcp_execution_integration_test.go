//go:build integration

package processors

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/a3s/pkgs/namespacelifecycle"
	"go.acuvity.ai/elemental"
	"go.acuvity.ai/manipulate"
	"go.mongodb.org/mongo-driver/v2/bson"
)

type crossMCPParentStatus struct {
	Nonce    string
	Registry *struct {
		ID, NamespaceName       string
		Issued, TerminalThrough int64
		Enrollment              struct {
			OperationID, Digest string
			Scope               namespacelifecycle.EnrollmentScope
		}
		DeletionFence *crossFence
	}
	Control *struct {
		ID            string
		CASRevision   int64
		Active        json.RawMessage
		DeletionFence *crossFence
	}
	Source *struct {
		Producer, OwnerOperationID, OwnerDigest string
		Scope                                   namespacelifecycle.EnrollmentScope
	}
	Phase, AdmissionID, ChildID, SnapshotID, BirthSHA256     string
	Result                                                   int
	Finished                                                 bool
	RemovedAfterSet                                          bool
	Parents, Findings, Definitions, ProofObserves, ProofSets int64
}
type crossMCPToriiStatus struct {
	Nonce                                                                                                                                                  string
	Paused                                                                                                                                                 bool
	ChildPhase                                                                                                                                             string
	Children, Snapshots, Extractions, AnalyzerCalls, AnalyzerActive, ClaimACKs, SnapshotWrites, EnrichmentWrites, TerminalWrites, ProofObserves, ProofSets int64
}

func TestCrossMCPA3SChildDrainHTTP(t *testing.T) {
	hanniBinary, toriiBinary := os.Getenv("CROSS_ENROLLMENT_HELPER"), os.Getenv("CROSS_MCP_TORII_HELPER")
	if hanniBinary == "" || toriiBinary == "" {
		t.Skip("owned three-process MCP runner only")
	}
	for _, mode := range []string{"paused", "completed", "missing-child"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 100*time.Second)
			defer cancel()
			dir := t.TempDir()
			crossMust(t, os.Chmod(dir, 0700))
			rights := map[string][]string{}
			for role, grants := range crossRights {
				rights[role] = append([]string(nil), grants...)
			}
			reads := []string{"aigateways:retrieve", "aigatewayconnectors:retrieve", "providers:retrieve", "mcptoolsnapshots:retrieve", "mcptoolsnapshots:retrieve-many"}
			rights["hanni"] = append(rights["hanni"], reads...)
			rights["hanni"] = append(rights["hanni"], "capturedmcppreparations:create", "capturedmcpexecutions:create", "mcptoolsnapshots:create", "mcptoolsnapshots:update", "capturedmcpchildren:retrieve", "capturedmcpchildren:retrieve-many")
			rights["torii"] = []string{"namespaceparticipations:create", "capturedmcpdispatches:create"}
			rights["apex"] = append(append([]string(nil), reads...), "capturedmcpadmissions:create", "capturedmcpjobexecutions:create", "mcptoolsnapshots:create", "mcptoolsnapshots:update")
			f := newCrossFixtureWithRights(t, ctx, dir, rights)
			for _, role := range []string{"apex", "torii"} {
				crossMust(t, os.WriteFile(filepath.Join(dir, role+".token"), []byte(f.bearer(role, "")), 0600))
			}
			h := f.startMCPPeer(hanniBinary, "hanni", mode, "", "")
			childMode := mode
			if childMode == "missing-child" {
				childMode = "completed"
			}
			torii := f.startMCPPeer(toriiBinary, "torii", childMode, h.URL, h.Nonce)
			ownerToken := f.bearer("owner", "")
			credential := func(context.Context) (string, error) { return ownerToken, nil }
			participants, err := namespacelifecycle.NewHTTPParticipants(h.URL, &http.Client{Timeout: 10 * time.Second}, credential, "hanni")
			crossMust(t, err)
			deletion, err := namespacelifecycle.NewHTTPDeletionParticipants(h.URL, &http.Client{Timeout: 5 * time.Second}, credential, "hanni")
			crossMust(t, err)
			f.owner, err = NewOwnerNamespacesProcessor(f.m, crossNotifications{}, NamespaceOwnerOptions{Store: f.store, Native: f.native, Participants: participants, RequiredParticipants: []string{"hanni"}, DeletionParticipants: deletion, Authorize: f.ownerAuthority})
			crossMust(t, err)
			creator := f.bearer("creator", "")
			body, code := f.post(f.server.URL, "/namespaces", "/", creator, map[string]string{"name": "cross"})
			if code != 200 && code != 201 {
				t.Fatalf("actual owner Create status%d body%s", code, body)
			}
			state, err := f.store.GetByName(ctx, "/cross")
			crossMust(t, err)
			if state.Phase != "open" || state.Creation.Phase != "ready" || len(state.Creation.Enrollments) != 1 || state.Creation.Enrollments[0].RegistryID != state.Namespace.ID {
				t.Fatal("original enrollment not ready")
			}
			getParent := func() crossMCPParentStatus {
				var status crossMCPParentStatus
				f.mcpControl(h, http.MethodGet, "/_cross/mcp/status", &status)
				return status
			}
			getChild := func() crossMCPToriiStatus {
				var status crossMCPToriiStatus
				f.mcpControl(torii, http.MethodGet, "/status", &status)
				return status
			}
			initial := getParent()
			if initial.Registry == nil || initial.Registry.ID != state.Namespace.ID || initial.Registry.Issued != 0 {
				t.Fatal("registry not actual enrollment")
			}
			f.mcpControl(h, http.MethodPost, "/_cross/mcp/start", nil)
			wait := 8 * time.Second
			if mode != "paused" {
				wait = 17 * time.Second
			} // Observe the real bounded operation, never extend its deadline.
			deadline := time.Now().Add(wait)
			for {
				child, parent := getChild(), getParent()
				if mode == "paused" && child.Paused || mode != "paused" && parent.Finished {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("child did not reach boundary parent%+v child%+v", parent, child)
				}
				time.Sleep(20 * time.Millisecond)
			}
			before, childBefore := getParent(), getChild()
			if before.Source == nil || before.Source.Scope.Namespace != state.Namespace || !reflect.DeepEqual(before.Source.Scope.Ancestors, state.Ancestors) || before.Source.OwnerOperationID != state.Creation.OperationID || before.Source.OwnerDigest != before.Registry.Enrollment.Digest || before.Registry.ID != before.Source.Scope.Namespace.ID {
				t.Fatal("source/owner/registry incarnation differs")
			}
			remove := func() ([]byte, int) {
				return f.request(http.MethodDelete, f.server.URL, "/namespaces/"+state.Namespace.ID, "/", creator, nil)
			}
			if mode == "paused" {
				if before.Phase != "attempted" || before.Control == nil || string(before.Control.Active) == "null" || childBefore.ChildPhase != "claimed" || childBefore.ClaimACKs != 1 || childBefore.Snapshots != 0 || childBefore.AnalyzerCalls != 0 {
					t.Fatalf("not genuine post-claim/prewrite boundary parent%+v child%+v", before, childBefore)
				}
				barrier := time.Now()
				body, code = remove()
				closing, err := f.store.Get(ctx, state.Namespace.ID)
				crossMust(t, err)
				held := getParent()
				deletes := f.nativeDeletes()
				f.mcpControl(torii, http.MethodPost, "/release", nil)
				if time.Since(barrier) >= 8*time.Second {
					t.Fatal("DELETE exhausted live child budget")
				}
				if code != 409 || closing.Phase != "closing" || closing.Intent == nil || len(closing.Drains) != 0 || deletes != 0 || held.Control == nil || !reflect.DeepEqual(before.Control.Active, held.Control.Active) || held.Registry.DeletionFence == nil || held.Control.DeletionFence == nil {
					t.Fatalf("real DELETE failed to hold status%d body%s parent%+v", code, body, held)
				}
				deadline = time.Now().Add(5 * time.Second)
				for !getParent().Finished {
					if time.Now().After(deadline) {
						t.Fatal("unresolved invocation did not join")
					}
					time.Sleep(20 * time.Millisecond)
				}
				after, child := getParent(), getChild()
				if after.Result == 200 || after.Phase != "attempted" || after.BirthSHA256 != before.BirthSHA256 || after.AdmissionID != before.AdmissionID || after.Control == nil || string(after.Control.Active) == "null" || child.ChildPhase != "claimed" || child.Snapshots != 0 || child.SnapshotWrites != 0 || child.EnrichmentWrites != 0 || child.TerminalWrites != 0 || child.AnalyzerCalls != 0 {
					t.Fatalf("closing child produced effects parent%+v child%+v", after, child)
				}
				present := api.NewNamespace()
				present.ID = state.Namespace.ID
				crossMust(t, f.m.Retrieve(manipulate.NewContext(ctx, manipulate.ContextOptionNamespace("/")), present))
				if _, code := remove(); code != 409 || f.nativeDeletes() != 0 || getChild().ClaimACKs != 1 {
					t.Fatal("DELETE retry resumed or deleted unresolved child")
				}
				var originalSource json.RawMessage
				f.mcpControl(torii, http.MethodGet, "/source", &originalSource)
				if _, code := f.post(h.URL, "/capturedmcpjobexecutions", "/cross", f.bearer("apex", ""), originalSource); code != 503 || getChild().ClaimACKs != 1 || getChild().SnapshotWrites != 0 {
					t.Fatal("signed source replay regranted a sealed child")
				}
			} else {
				if before.Result != 200 || before.Phase != "completed" || before.Control == nil || string(before.Control.Active) != "null" || childBefore.ChildPhase != "completed" || childBefore.Extractions != 1 || childBefore.AnalyzerCalls != 1 || childBefore.AnalyzerActive != 0 {
					t.Fatalf("unsealed execution not complete parent%+v child%+v", before, childBefore)
				}
				// Real current policy now permits ONLY lifecycle inspection and child
				// retention reads for Hanni. No source/snapshot/action write grant is
				// available to accidentally satisfy closing proof authorization.
				policies := api.AuthorizationsList{}
				mc := manipulate.NewContext(ctx, manipulate.ContextOptionNamespace("/"), manipulate.ContextOptionFilter(elemental.NewFilterComposer().WithKey("name").Equals("cross-hanni").Done()))
				crossMust(t, f.m.RetrieveMany(mc, &policies))
				if len(policies) != 1 {
					t.Fatal("missing owned Hanni policy")
				}
				policies[0].Permissions = []string{"namespaceparticipations:create", "capturedmcpchildren:retrieve", "capturedmcpchildren:retrieve-many"}
				crossMust(t, f.m.Update(manipulate.NewContext(ctx, manipulate.ContextOptionNamespace("/")), policies[0]))
				present := api.NewNamespace()
				present.ID = state.Namespace.ID
				crossMust(t, f.m.Retrieve(manipulate.NewContext(ctx, manipulate.ContextOptionNamespace("/")), present))
				body, code = remove()
				if mode == "missing-child" {
					closing, err := f.store.Get(ctx, state.Namespace.ID)
					crossMust(t, err)
					after, child := getParent(), getChild()
					if code != 409 || closing.Phase != "closing" || len(closing.Drains) != 0 || f.nativeDeletes() != 0 || !after.RemovedAfterSet || after.ProofSets-before.ProofSets != 1 || child.Children != 0 || child.ClaimACKs != 1 || after.Phase != "completed" || after.Control == nil || string(after.Control.Active) != "null" || after.BirthSHA256 != before.BirthSHA256 {
						t.Fatalf("final inspection accepted missing retained child status%d parent%+v child%+v", code, after, child)
					}
					crossMust(t, f.m.Retrieve(manipulate.NewContext(ctx, manipulate.ContextOptionNamespace("/")), present))
					if _, code := remove(); code != 409 || f.nativeDeletes() != 0 || getChild().ClaimACKs != 1 {
						t.Fatal("missing child replay recreated or deleted")
					}
					f.assertNoLegacyDeletion()
					t.Log("PASS actual final-inspection retention loss Hold with Active already nil; no repair/replay/native delete")
					return
				}
				if code != 200 && code != 204 {
					t.Fatalf("completed child DELETE status%d body%s", code, body)
				}
				deleted, err := f.store.Get(ctx, state.Namespace.ID)
				crossMust(t, err)
				child := getChild()
				after := getParent()
				if deleted.Phase != "deleted" || len(deleted.Drains) != 1 || f.nativeDeletes() != 1 || child.ChildPhase != "completed" || child.ClaimACKs != 1 || child.SnapshotWrites != 1 || child.EnrichmentWrites != 1 || child.TerminalWrites != 1 || after.BirthSHA256 != before.BirthSHA256 || after.Parents != 1 || after.Findings != 0 || after.Definitions != 0 {
					t.Fatalf("completed retention/deletion mismatch parent%+v child%+v", after, child)
				}
				id, _ := bson.ObjectIDFromHex(state.Namespace.ID)
				n, err := f.db.Collection(api.NamespaceIdentity.Name).CountDocuments(ctx, bson.M{"_id": id})
				crossMust(t, err)
				if n != 0 {
					t.Fatal("native namespace retained")
				}
				var deletionProfile bson.Raw
				crossMust(t, f.db.Collection("system.profile").FindOne(ctx, bson.M{"op": "remove", "ns": f.db.Name() + "." + api.NamespaceIdentity.Name}).Decode(&deletionProfile))
				q, valid := deletionProfile.Lookup("command", "q").DocumentOK()
				marker, err := namespacelifecycle.CreationMarkerDigest(state)
				crossMust(t, err)
				if !valid || q.Lookup("_id").ObjectID() != id || q.Lookup("name").StringValue() != "/cross" || q.Lookup("namespace").StringValue() != "/" || q.Lookup("creationmarker").StringValue() != marker || q.Lookup("createtime").DateTime() != present.CreateTime.UnixMilli() || q.Lookup("$expr").Type != bson.TypeEmbeddedDocument {
					t.Fatal("native DELETE was not exact original incarnation")
				}
				root, err := f.store.GetByName(ctx, "/")
				crossMust(t, err)
				if len(root.Pins) != 0 {
					t.Fatal("root pins retained")
				}
				if _, code := remove(); code != 204 || f.nativeDeletes() != 1 || getChild().ClaimACKs != 1 {
					t.Fatal("delete replay repeated effects")
				}
				if after.ProofObserves-before.ProofObserves < 2 || after.ProofSets-before.ProofSets < 2 {
					t.Fatal("closing drain skipped repeated actual ACK/set observations", after)
				}
			}
			f.assertNoLegacyDeletion()
			t.Log("PASS actual signed A3S / Hanni / Torii closed-child lifecycle", mode, "; owned standalone profile, no production/shared-writer/remote-billing/positive-detection claim")
		})
	}
}
