package authorizer

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"time"

	"github.com/spaolacci/murmur3"
	"go.acuvity.ai/a3s/pkgs/nscache"
	"go.acuvity.ai/a3s/pkgs/permissions"
	"go.acuvity.ai/a3s/pkgs/token"
	"go.acuvity.ai/bahamut"
	"go.acuvity.ai/elemental"
)

// MetadataKeyAccessibleNamespaces is the bahamut.Context Metadata Key
// that will contain the list of authorized namespaces.
var MetadataKeyAccessibleNamespaces = struct{}{}

// Various Authorizer errors.
var (
	ErrMissingNamespace = elemental.NewError(
		"Forbidden",
		"Missing X-Namespace header",
		"a3s:authorizer",
		http.StatusForbidden,
	)

	ErrInvalidNamespace = elemental.NewError(
		"Forbidden",
		"Invalid X-Namespace header. A namespace must start with /",
		"a3s:authorizer",
		http.StatusForbidden,
	)

	ErrInvalidToken = elemental.NewError(
		"Forbidden",
		"Invalid token.",
		"a3s:authorizer",
		http.StatusForbidden,
	)

	ErrMissingToken = elemental.NewError(
		"Forbidden",
		"Missing token in either Authorization header or X-A3S-Token in cookies",
		"a3s:authorizer",
		http.StatusForbidden,
	)

	ErrRevokedToken = elemental.NewError(
		"Forbidden",
		"Token is marked as revoked",
		"a3s:authorizer",
		http.StatusForbidden,
	)
)

type cachedAuth struct {
	perms      permissions.PermissionMap
	namespaces []string
}

// An Authorizer is a bahamut.Authorizer compliant structure
// that can be used to authorize a session or a request.
type Authorizer interface {
	bahamut.Authorizer

	CheckAuthorization(
		ctx context.Context,
		claims []string,
		op string,
		ns string,
		resource string,
		opts ...OptionCheck,
	) (bool, error)
}

type authorizer struct {
	retriever            permissions.Retriever
	ignoredResources     map[string]struct{}
	operationTransformer OperationTransformer
	authCache            *nscache.NamespacedCache
	revocationCache      *nscache.NamespacedCache
}

// New creates a new Authorizer using the given permissions.Retriever and PubSubClient.
// The authorizer aggressively chache the authentication results and uses the pubsub
// to update the state of cache, by dropping parts of cache affected by a change in namespace
// or Authorization policies.
func New(ctx context.Context, retriever permissions.Retriever, pubsub bahamut.PubSubClient, options ...Option) Authorizer {

	cfg := config{}
	for _, opt := range options {
		opt(&cfg)
	}

	ignored := map[string]struct{}{}
	for _, i := range cfg.ignoredResources {
		ignored[i] = struct{}{}
	}

	authCache := nscache.New(pubsub, 24000)
	revocationCache := nscache.New(pubsub, 24000)
	if pubsub != nil {
		revocationCache.Start(ctx)
		authCache.Start(ctx)
	}

	return &authorizer{
		retriever:            retriever,
		ignoredResources:     ignored,
		operationTransformer: cfg.operationTransformer,
		authCache:            authCache,
		revocationCache:      revocationCache,
	}
}

// IsAuthorized is the main method that returns whether the API call is authorized or not.
func (a *authorizer) IsAuthorized(bctx bahamut.Context) (bahamut.AuthAction, error) {

	req := bctx.Request()

	if _, ok := a.ignoredResources[req.Identity.Category]; ok {
		return bahamut.AuthActionOK, nil
	}

	t := token.FromRequest(req)
	if t == "" {
		return bahamut.AuthActionKO, ErrMissingToken
	}

	idt, err := token.ParseUnverified(t)
	if err != nil {
		return bahamut.AuthActionKO, ErrInvalidToken
	}

	operation := string(req.Operation)
	if a.operationTransformer != nil {
		operation = a.operationTransformer.Transform(req.Operation)
	}

	collectedNamespaces := []string{}
	opts := []OptionCheck{
		OptionCheckTokenID(idt.ID),
		OptionCheckID(req.ObjectID),
		OptionCheckSourceIP(req.ClientIP),
		OptionCollectAccessibleNamespaces(&collectedNamespaces),
	}

	if idt.Restrictions != nil {
		opts = append(opts, OptionCheckRestrictions(*idt.Restrictions))
	}

	ok, err := a.CheckAuthorization(
		bctx.Context(),
		bctx.Claims(),
		operation,
		req.Namespace,
		req.Identity.Category,
		opts...,
	)
	if err != nil {
		return bahamut.AuthActionKO, err
	}

	if ok {
		bctx.SetMetadata(MetadataKeyAccessibleNamespaces, collectedNamespaces)
		return bahamut.AuthActionOK, nil
	}

	return bahamut.AuthActionKO, nil
}

func (a *authorizer) CheckAuthorization(ctx context.Context, claims []string, operation string, ns string, resource string, opts ...OptionCheck) (bool, error) {

	cfg := checkConfig{}
	for _, o := range opts {
		o(&cfg)
	}

	if _, ok := a.ignoredResources[resource]; ok {
		return true, nil
	}

	if ns == "" {
		return false, ErrMissingNamespace
	}

	if ns[0] != '/' {
		return false, ErrInvalidNamespace
	}

	exp := time.Hour + time.Duration(rand.Int63n(60*30))*time.Second
	key := hash(claims, cfg.sourceIP, cfg.id, cfg.restrictions)

	// Handle token revocation
	if r := a.revocationCache.Get(ns, key); r == nil || r.Expired() {
		revoked, err := a.retriever.Revoked(ctx, ns, cfg.tokenID)
		if err != nil {
			return false, err
		}
		a.revocationCache.Set(ns, key, revoked, exp)
	}

	if r := a.revocationCache.Get(ns, key); r != nil && !r.Expired() {
		if r.Value().(bool) {
			return false, ErrRevokedToken
		}
	}

	if r := a.authCache.Get(ns, key); r != nil && !r.Expired() {
		cauth := r.Value().(cachedAuth)
		if cfg.accessibleNamespaces != nil {
			*cfg.accessibleNamespaces = cauth.namespaces
		}
		return cauth.perms.Allows(operation, resource), nil
	}

	ropts := []permissions.RetrieverOption{
		permissions.OptionRetrieverSourceIP(cfg.sourceIP),
		permissions.OptionRetrieverID(cfg.id),
		permissions.OptionRetrieverRestrictions(cfg.restrictions),
		permissions.OptionCollectAccessibleNamespaces(cfg.accessibleNamespaces),
		permissions.OptionFilterLabel(cfg.label),
	}

	perms, err := a.retriever.Permissions(ctx, claims, ns, ropts...)
	if err != nil {
		return false, err
	}

	cauth := cachedAuth{perms: perms}
	if cfg.accessibleNamespaces != nil {
		cauth.namespaces = *cfg.accessibleNamespaces
	}
	a.authCache.Set(ns, key, cauth, exp)

	return perms.Allows(operation, resource), nil
}

func hash(claims []string, remoteaddr string, id string, restrictions permissions.Restrictions) string {
	return fmt.Sprintf("%d",
		murmur3.Sum64(
			[]byte(
				fmt.Sprintf("%s:%s:%s:%s:%s:%s",
					claims,
					remoteaddr,
					id,
					restrictions.Namespace,
					restrictions.Networks,
					restrictions.Permissions,
				),
			),
		),
	)
}
