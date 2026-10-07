//go:build integration

package processors

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.acuvity.ai/a3s/internal/mongofixture"
	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/a3s/pkgs/authenticator"
	"go.acuvity.ai/a3s/pkgs/authorizer"
	"go.acuvity.ai/a3s/pkgs/indexes"
	"go.acuvity.ai/a3s/pkgs/namespacelifecycle"
	"go.acuvity.ai/a3s/pkgs/permissions"
	"go.acuvity.ai/a3s/pkgs/token"
	"go.acuvity.ai/bahamut"
	"go.acuvity.ai/elemental"
	"go.acuvity.ai/manipulate"
	"go.acuvity.ai/manipulate/manipmongo"
	"go.acuvity.ai/tg/tglib"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

const crossIssuer = "cross-enrollment-owned-issuer"
const crossAudience = "cross-enrollment-owned-audience"

var crossRights = map[string][]string{
	"creator": {"namespaces:create", "namespaces:delete"},
	"owner":   {"findingpublicationnamespaces:create"},
	"hanni":   {"namespaceparticipations:create"},
	"policy":  {"permissions:create", "revocations:retrieve-many"},
}

// This observer always delegates the actual CAS; it cannot grant enrollment.
type crossClaims struct {
	*namespacelifecycle.Store
	calls, grants atomic.Int64
}

func (s *crossClaims) ClaimCreationEnrollment(ctx context.Context, expected namespacelifecycle.State, participant, registry string) (namespacelifecycle.State, bool, error) {
	s.calls.Add(1)
	next, won, err := s.Store.ClaimCreationEnrollment(ctx, expected, participant, registry)
	if won && err == nil {
		s.grants.Add(1)
	}
	return next, won, err
}

type crossFixture struct {
	t                            *testing.T
	ctx                          context.Context
	dir                          string
	m                            manipulate.Manipulator
	db                           *mongo.Database
	store                        *namespacelifecycle.Store
	native                       *namespacelifecycle.NativeNamespaceStore
	claims                       *crossClaims
	server                       *httptest.Server
	owner                        *NamespacesProcessor // assigned before the first /namespaces request
	ownerAuthority               NamespaceOwnerAuthorityFactory
	key                          crypto.PrivateKey
	kid                          string
	dropClaim                    atomic.Bool
	policyReads, revocationReads atomic.Int64
}

func crossMust(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func crossIdentity(role string) []string {
	return []string{"role=" + role, "@issuer=" + crossIssuer, "@source:type=cross-enrollment", "@source:name=" + role, "@source:namespace=/"}
}

func (f *crossFixture) bearer(role, variant string) string {
	f.t.Helper()
	now := time.Now()
	idt := &token.IdentityToken{
		Identity:         crossIdentity(role),
		Restrictions:     &permissions.Restrictions{Namespace: "/", Networks: []string{"127.0.0.0/8"}, Permissions: crossRights[role]},
		RegisteredClaims: jwt.RegisteredClaims{ID: bson.NewObjectID().Hex(), Issuer: crossIssuer, Audience: jwt.ClaimStrings{crossAudience}, IssuedAt: jwt.NewNumericDate(now.Add(-time.Minute)), ExpiresAt: jwt.NewNumericDate(now.Add(5 * time.Minute))},
	}
	switch variant {
	case "namespace":
		idt.Restrictions.Namespace = "/elsewhere"
	case "resource":
		idt.Restrictions.Permissions = []string{"dsgchecks:create"}
	case "issuer":
		idt.Issuer = "wrong-issuer"
	case "audience":
		idt.Audience = jwt.ClaimStrings{"wrong-audience"}
	case "source":
		idt.Identity[3] = "@source:name=untrusted"
	}
	j := jwt.NewWithClaims(jwt.SigningMethodES256, idt)
	j.Header["kid"] = f.kid
	out, err := j.SignedString(f.key)
	crossMust(f.t, err)
	return out
}

func newCrossFixture(t *testing.T, ctx context.Context, dir string) *crossFixture {
	t.Helper()
	f := &crossFixture{t: t, ctx: ctx, dir: dir, m: mongofixture.New(t)}
	var err error
	f.db, err = manipmongo.GetDatabase(f.m)
	crossMust(t, err)
	// Profile only these fresh owned databases, to count real native inserts
	// (including failed insert attempts), not just final collection cardinality.
	crossMust(t, f.db.RunCommand(ctx, bson.D{{Key: "profile", Value: 2}}).Err())
	crossMust(t, manipmongo.CreateIndex(f.m, api.NamespaceIdentity, indexes.GetIndexes("a3s", api.Manager())[api.NamespaceIdentity]...))
	f.native, err = namespacelifecycle.NewNativeNamespaceStore(f.m)
	crossMust(t, err)
	f.store, err = namespacelifecycle.NewStore(f.m)
	crossMust(t, err)
	root := namespacelifecycle.Namespace{ID: bson.NewObjectID().Hex(), Name: "/"}
	at := time.Now().UTC().Truncate(time.Millisecond)
	marker := "bootstrap:" + root.ID
	prepared, err := namespacelifecycle.PrepareNativeNamespace(api.NewNamespace(), namespacelifecycle.NativeNamespaceIdentity{Namespace: root, Parent: "root", CreatedAt: at, Marker: marker})
	crossMust(t, err)
	evidence, err := f.native.InsertOnce(ctx, prepared)
	crossMust(t, err)
	_, err = f.store.BootstrapRoot(ctx, root, marker, evidence.Digest, at)
	crossMust(t, err)
	// All native namespace IDs come from the prebound adapter/bootstrap and
	// owner Create. manipulator.Create is used only for policy fixture rows.
	for role, rights := range crossRights {
		p := api.NewAuthorization()
		p.Name, p.Namespace = "cross-"+role, "/"
		p.Subject = [][]string{crossIdentity(role)}
		p.FlattenedSubject = crossIdentity(role)
		p.TrustedIssuers = []string{crossIssuer}
		p.TargetNamespaces, p.Permissions = []string{"/", "/cross", "/lost", "/drain"}, rights
		crossMust(t, f.m.Create(manipulate.NewContext(ctx, manipulate.ContextOptionNamespace("/")), p))
	}
	certPEM, keyPEM, err := tglib.Issue(pkix.Name{})
	crossMust(t, err)
	certBytes := pem.EncodeToMemory(certPEM)
	cert, err := tglib.ParseCertificate(certBytes)
	crossMust(t, err)
	f.key, err = tglib.PEMToKey(keyPEM)
	crossMust(t, err)
	f.kid = token.Fingerprint(cert)
	jwks := token.NewJWKS()
	crossMust(t, jwks.Append(cert))
	crossMust(t, os.WriteFile(filepath.Join(dir, "certificate.pem"), certBytes, 0600))
	crossMust(t, os.WriteFile(filepath.Join(dir, "hanni.token"), []byte(f.bearer("hanni", "")), 0600))
	crossMust(t, os.WriteFile(filepath.Join(dir, "policy.token"), []byte(f.bearer("policy", "")), 0600))
	authn := authenticator.New(jwks, crossIssuer, crossAudience)
	retriever := permissions.NewRetriever(f.m)
	f.ownerAuthority, err = NewNamespaceOwnerAuthorizer(authn, retriever)
	crossMust(t, err)
	authz := authorizer.New(ctx, retriever, nil)
	bound, err := NewNamespaceParticipationAuthorizer(authn, retriever)
	crossMust(t, err)
	f.claims = &crossClaims{Store: f.store}
	participation, err := NewNamespaceParticipationProcessor(f.claims, bound)
	crossMust(t, err)
	policy := NewPermissionsProcessor(retriever)
	revocations := NewRevocationsProcessor(f.m, nil)
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, h *http.Request) {
		h.Body = http.MaxBytesReader(w, h.Body, 32*1024)
		r, err := elemental.NewRequestFromHTTPRequest(h, api.Manager())
		if err != nil {
			http.Error(w, "invalid", http.StatusUnprocessableEntity)
			return
		}
		b := bahamut.NewContext(h.Context(), r)
		if action, err := authn.AuthenticateRequest(b); err != nil || action != bahamut.AuthActionContinue {
			http.Error(w, "authn denied", http.StatusForbidden)
			return
		}
		if action, err := authz.IsAuthorized(b); err != nil || action != bahamut.AuthActionOK {
			t.Logf("source fixture authz rejected path=%s namespace=%s operation=%s action=%v error=%v", h.URL.Path, r.Namespace, r.Operation, action, err)
			http.Error(w, "authz denied", http.StatusForbidden)
			return
		}
		switch {
		case h.URL.Path == "/namespaces" && h.Method == http.MethodPost:
			input := api.NewNamespace()
			if err = r.Decode(input); err == nil && f.owner != nil {
				b.SetInputData(input)
				err = f.owner.ProcessCreate(b)
			} else {
				err = fmt.Errorf("owner not composed")
			}
		case r.Identity == api.NamespaceIdentity && r.Operation == elemental.OperationDelete && f.owner != nil:
			err = f.owner.ProcessDelete(b)
			if err != nil {
				t.Logf("source DELETE rejected: namespace=%q object=%q parent=%q recursive=%v propagated=%v override=%v parameters=%v order=%v page=%d pageSize=%d after=%q limit=%d error=%v", r.Namespace, r.ObjectID, r.ParentID, r.Recursive, r.Propagated, r.OverrideProtection, r.Parameters, r.Order, r.Page, r.PageSize, r.After, r.Limit, err)
			}
		case h.URL.Path == "/namespaceparticipations" && h.Method == http.MethodPost:
			err = participation.ProcessCreate(b)
			if out, ok := b.OutputData().(namespaceParticipationResult); err == nil && ok && out.Granted && f.dropClaim.Load() {
				// Real acknowledged CAS, then lost transport acknowledgment. No
				// fake snapshot, grant, registry insert, or source transition.
				conn, _, hijackErr := w.(http.Hijacker).Hijack()
				if hijackErr == nil {
					_ = conn.Close()
					return
				}
				err = hijackErr
			}
		case r.Identity == api.PermissionsIdentity && r.Operation == elemental.OperationCreate:
			f.policyReads.Add(1)
			input := api.NewPermissions()
			if err = r.Decode(input); err == nil {
				b.SetInputData(input)
				err = policy.ProcessCreate(b)
			}
		case r.Identity == api.RevocationIdentity && r.Operation == elemental.OperationRetrieveMany:
			f.revocationReads.Add(1)
			err = revocations.ProcessRetrieveMany(b)
		default:
			http.NotFound(w, h)
			return
		}
		if err != nil {
			http.Error(w, "processor held: "+err.Error(), http.StatusConflict)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		status := b.StatusCode()
		if status == 0 {
			status = 200
		}
		w.WriteHeader(status)
		if status == http.StatusNoContent {
			return
		}
		if err := json.NewEncoder(w).Encode(b.OutputData()); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(f.server.Close)
	return f
}

func (f *crossFixture) post(base, path, namespace, bearer string, input any) ([]byte, int) {
	f.t.Helper()
	return f.request(http.MethodPost, base, path, namespace, bearer, input)
}

func (f *crossFixture) request(method, base, path, namespace, bearer string, input any) ([]byte, int) {
	f.t.Helper()
	data, err := json.Marshal(input)
	crossMust(f.t, err)
	r, err := http.NewRequestWithContext(f.ctx, method, base+path, bytes.NewReader(data))
	crossMust(f.t, err)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Namespace", namespace)
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	client := &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(r)
	crossMust(f.t, err)
	defer response.Body.Close() //nolint:errcheck
	body, err := io.ReadAll(io.LimitReader(response.Body, 32769))
	crossMust(f.t, err)
	if len(body) > 32768 {
		f.t.Fatal("oversize response")
	}
	return body, response.StatusCode
}

func (f *crossFixture) inserts() int64 {
	f.t.Helper()
	n, err := f.db.Collection("system.profile").CountDocuments(f.ctx, bson.M{"op": "insert", "ns": f.db.Name() + "." + api.NamespaceIdentity.Name})
	crossMust(f.t, err)
	return n
}
