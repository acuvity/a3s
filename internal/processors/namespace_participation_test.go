package processors

import (
	"context"
	"crypto"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/a3s/pkgs/authenticator"
	"go.acuvity.ai/a3s/pkgs/namespacelifecycle"
	"go.acuvity.ai/a3s/pkgs/permissions"
	"go.acuvity.ai/a3s/pkgs/token"
	"go.acuvity.ai/bahamut"
	"go.acuvity.ai/elemental"
	"go.acuvity.ai/manipulate"
	"go.acuvity.ai/manipulate/maniptest"
	"go.acuvity.ai/tg/tglib"
)

type participationStoreFixture struct {
	state        namespacelifecycle.State
	gets, claims int
	onGet        func()
	claimError   error
	lose         bool
}

func (s *participationStoreFixture) Get(context.Context, string) (namespacelifecycle.State, error) {
	s.gets++
	if s.onGet != nil {
		s.onGet()
	}
	return s.state, nil
}
func (s *participationStoreFixture) ClaimCreationEnrollment(_ context.Context, expected namespacelifecycle.State, participant, registry string) (namespacelifecycle.State, bool, error) {
	s.claims++
	if s.claimError != nil {
		return namespacelifecycle.State{}, false, s.claimError
	}
	if s.lose {
		return namespacelifecycle.State{}, false, nil
	}
	if expected.Revision != s.state.Revision || participant != "hanni" || registry != s.state.Namespace.ID {
		return namespacelifecycle.State{}, false, errors.New("binding")
	}
	s.state.Creation.Enrollments[0].Phase = "claimed"
	s.state.Revision++
	return s.state, true, nil
}

func participationState(t *testing.T) namespacelifecycle.State {
	t.Helper()
	s := namespacelifecycle.State{Version: "namespace-lifecycle.v2", Namespace: namespacelifecycle.Namespace{ID: strings.Repeat("1", 24), Name: "/target"}, Ancestors: []namespacelifecycle.Namespace{{ID: strings.Repeat("2", 24), Name: "/"}}, Revision: 8, Phase: "forming", Pins: []namespacelifecycle.Pin{}, Drains: []namespacelifecycle.DrainProof{}, Creation: &namespacelifecycle.Creation{Origin: "create", OperationID: "owner-operation", Digest: strings.Repeat("a", 64), CreatedAt: "2026-01-01T00:00:00Z", Participants: []string{"hanni"}, Phase: "applied", Acquisitions: []string{"held"}, Enrollments: []namespacelifecycle.CreationEnrollment{{Participant: "hanni", Phase: "attempted", RegistryID: strings.Repeat("1", 24)}}}}
	digest, err := namespacelifecycle.CreationMarkerDigest(s)
	if err != nil {
		t.Fatal(err)
	}
	s.Creation.ApplicationDigest = digest
	if _, err := namespacelifecycle.SnapshotEnrollment(s, "hanni", s.Namespace.ID); err != nil {
		t.Fatal(err)
	}
	return s
}

type participationRetriever struct {
	permissions.Retriever
	revoked          bool
	calls            int
	afterPermissions func()
}

func (r *participationRetriever) Revoked(_ context.Context, ns, id string, claims []string, iat time.Time) (bool, error) {
	if ns != "/target" || id == "" || len(claims) == 0 || iat.IsZero() {
		return false, errors.New("missing native token binding")
	}
	return r.revoked, nil
}
func (r *participationRetriever) Permissions(ctx context.Context, claims []string, ns string, opts ...permissions.RetrieverOption) (permissions.PermissionMap, error) {
	r.calls++
	out, err := r.Retriever.Permissions(ctx, claims, ns, opts...)
	if r.afterPermissions != nil {
		r.afterPermissions()
	}
	return out, err
}

type participationAuthFixture struct {
	auth      *NamespaceParticipationAuthorizer
	retriever *participationRetriever
	policy    *api.Authorization
	key       crypto.PrivateKey
	kid       string
}

func participationAuth(t *testing.T) participationAuthFixture {
	t.Helper()
	certPEM, keyPEM, err := tglib.Issue(pkix.Name{})
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tglib.ParseCertificate(pem.EncodeToMemory(certPEM))
	if err != nil {
		t.Fatal(err)
	}
	key, err := tglib.PEMToKey(keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	jwks := token.NewJWKS()
	if err := jwks.Append(cert); err != nil {
		t.Fatal(err)
	}
	m := maniptest.NewTestManipulator()
	policy := api.NewAuthorization()
	policy.Subject = [][]string{{"role=enroller"}}
	policy.TargetNamespaces = []string{"/target"}
	policy.Permissions = []string{"namespaceparticipations:create"}
	m.MockCount(t, func(manipulate.Context, elemental.Identity) (int, error) { return 1, nil })
	m.MockRetrieveMany(t, func(_ manipulate.Context, dest elemental.Identifiables) error {
		if list, ok := dest.(*api.AuthorizationsList); ok {
			*list = api.AuthorizationsList{policy}
		}
		return nil
	})
	r := &participationRetriever{Retriever: permissions.NewRetriever(m)}
	a, err := NewNamespaceParticipationAuthorizer(authenticator.New(jwks, "test-issuer", "test-audience", authenticator.OptionIgnoredResources(api.NamespaceParticipationIdentity.Category)), r)
	if err != nil {
		t.Fatal(err)
	}
	return participationAuthFixture{a, r, policy, key, token.Fingerprint(cert)}
}
func (f participationAuthFixture) bearer(t *testing.T, mutate func(*token.IdentityToken)) string {
	t.Helper()
	idt := token.NewIdentityToken(token.Source{Type: "test"})
	idt.Identity = []string{"role=enroller"}
	if mutate != nil {
		mutate(idt)
	}
	value, err := idt.JWT(f.key, f.kid, "test-issuer", jwt.ClaimStrings{"test-audience"}, time.Now().Add(time.Minute), nil)
	if err != nil {
		t.Fatal(err)
	}
	return value
}
func participationContext(t *testing.T, bearer, action string) *bahamut.MockContext {
	t.Helper()
	r := elemental.NewRequest()
	r.Namespace, r.Identity, r.Operation = "/target", api.NamespaceParticipationIdentity, elemental.OperationCreate
	r.ClientIP, r.Password = "127.0.0.1", bearer
	r.Headers = http.Header{"X-Namespace": {"/target"}}
	var err error
	r.Data, err = json.Marshal(namespaceParticipationCommand{Action: action, NamespaceID: strings.Repeat("1", 24), OperationID: "owner-operation", Participant: "hanni", RegistryID: strings.Repeat("1", 24)})
	if err != nil {
		t.Fatal(err)
	}
	b := bahamut.NewMockContext(context.Background())
	b.MockRequest = r
	return b
}

func TestNamespaceParticipationInspectClaimReplay(t *testing.T) {
	f := participationAuth(t)
	store := &participationStoreFixture{state: participationState(t)}
	p, err := NewNamespaceParticipationProcessor(store, f.auth)
	if err != nil {
		t.Fatal(err)
	}
	bearer := f.bearer(t, nil)
	for i, action := range []string{"Inspect", "ClaimEnrollment", "ClaimEnrollment", "Inspect"} {
		b := participationContext(t, bearer, action)
		if err := p.ProcessCreate(b); err != nil {
			t.Fatal(err)
		}
		out := b.OutputData().(namespaceParticipationResult)
		if out.Granted != (i == 1) || out.Snapshot.OperationID != "owner-operation" {
			t.Fatalf("bad output: %+v", out)
		}
	}
	if store.claims != 1 || f.retriever.calls < 4 {
		t.Fatalf("claims=%d permissions=%d", store.claims, f.retriever.calls)
	}
	// A previously authorized token must not retain resource or IP authority.
	f.policy.Subnets = []string{"10.0.0.0/8"}
	if err := p.ProcessCreate(participationContext(t, bearer, "Inspect")); err == nil {
		t.Fatal("cached IP authority")
	}
	f.policy.Subnets = nil
	f.policy.Permissions = []string{"namespaces:create"}
	if err := p.ProcessCreate(participationContext(t, bearer, "Inspect")); err == nil {
		t.Fatal("wrong resource authorized Inspect")
	}
}

func TestNamespaceParticipationDenialsDoNotMutate(t *testing.T) {
	for _, name := range []string{"missing", "claims-only", "bad-signature", "refresh", "revoked", "permission", "restricted-namespace", "restricted-network", "restricted-resource", "scope", "operation", "duplicate", "unknown", "null", "oversize", "parameters", "header", "drift", "revoke-after-read"} {
		t.Run(name, func(t *testing.T) {
			f := participationAuth(t)
			mutate := func(idt *token.IdentityToken) {
				switch name {
				case "refresh":
					idt.Refresh = true
				case "restricted-namespace":
					idt.Restrictions = &permissions.Restrictions{Namespace: "/elsewhere"}
				case "restricted-network":
					idt.Restrictions = &permissions.Restrictions{Networks: []string{"10.0.0.0/8"}}
				case "restricted-resource":
					idt.Restrictions = &permissions.Restrictions{Permissions: []string{"namespaces:create"}}
				}
			}
			b := participationContext(t, f.bearer(t, mutate), "ClaimEnrollment")
			store := &participationStoreFixture{state: participationState(t)}
			switch name {
			case "missing", "claims-only":
				b.Request().Password = ""
				b.SetClaims([]string{"role=enroller"})
			case "bad-signature":
				b.Request().Password += "broken"
			case "revoked":
				f.retriever.revoked = true
			case "permission":
				f.policy.Permissions = []string{"namespaceparticipations:retrieve-many"}
			case "scope":
				b.Request().Namespace = "/other"
				b.Request().Headers.Set("X-Namespace", "/other")
			case "operation":
				b.Request().Data = []byte(strings.ReplaceAll(string(b.Request().Data), "owner-operation", "other-operation"))
			case "duplicate":
				b.Request().Data = append([]byte(`{"action":"Inspect",`), b.Request().Data[1:]...)
			case "unknown":
				b.Request().Data = append([]byte(`{"granted":true,`), b.Request().Data[1:]...)
			case "null":
				b.Request().Data = []byte(strings.ReplaceAll(string(b.Request().Data), `"hanni"`, "null"))
			case "oversize":
				b.Request().Data = []byte(strings.Repeat(" ", namespaceParticipationMaxBytes+1))
			case "parameters":
				b.Request().Parameters = elemental.Parameters{"extra": {}}
			case "header":
				b.Request().Headers.Add("X-Namespace", "/target")
			case "drift":
				f.retriever.afterPermissions = func() { b.Request().ClientIP = "10.1.1.1" }
			case "revoke-after-read":
				store.onGet = func() { f.retriever.revoked = true }
			}
			p, err := NewNamespaceParticipationProcessor(store, f.auth)
			if err != nil {
				t.Fatal(err)
			}
			if err := p.ProcessCreate(b); err == nil || store.claims != 0 {
				t.Fatalf("err=%v mutations=%d", err, store.claims)
			}
		})
	}
}

func TestNamespaceParticipationUnknownAndLostCASNeverGrant(t *testing.T) {
	for _, unknown := range []bool{false, true} {
		f := participationAuth(t)
		store := &participationStoreFixture{state: participationState(t), lose: !unknown}
		if unknown {
			store.claimError = namespacelifecycle.ErrUnknown
		}
		p, err := NewNamespaceParticipationProcessor(store, f.auth)
		if err != nil {
			t.Fatal(err)
		}
		b := participationContext(t, f.bearer(t, nil), "ClaimEnrollment")
		err = p.ProcessCreate(b)
		if unknown && err == nil {
			t.Fatal("unknown acknowledged")
		}
		if !unknown && (err != nil || b.OutputData().(namespaceParticipationResult).Granted) {
			t.Fatal("lost CAS granted", err)
		}
	}
}
