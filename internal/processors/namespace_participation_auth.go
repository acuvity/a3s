package processors

import (
	"bytes"
	"context"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/a3s/pkgs/authenticator"
	"go.acuvity.ai/a3s/pkgs/namespacelifecycle"
	"go.acuvity.ai/a3s/pkgs/permissions"
	"go.acuvity.ai/a3s/pkgs/token"
	"go.acuvity.ai/bahamut"
	"go.acuvity.ai/elemental"
)

// NamespaceParticipationAuthorizer uses the actual native cryptographic
// authenticator and uncached current native permission/revocation retriever.
// It is an additional processor boundary, not a replacement auth-chain handler.
type NamespaceParticipationAuthorizer struct {
	authenticator *authenticator.Authenticator
	retriever     permissions.Retriever
}

func NewNamespaceParticipationAuthorizer(authn *authenticator.Authenticator, retriever permissions.Retriever) (*NamespaceParticipationAuthorizer, error) {
	if authn == nil || retriever == nil {
		return nil, namespacelifecycle.ErrInvalid
	}
	return &NamespaceParticipationAuthorizer{authenticator: authn, retriever: retriever}, nil
}

func (a *NamespaceParticipationAuthorizer) bind(bctx bahamut.Context, command namespaceParticipationCommand) (func() error, error) {
	original := bctx.Request()
	namespace, ip, bearer := original.Namespace, original.ClientIP, token.FromRequest(original)
	data := bytes.Clone(original.Data)
	bound := func() bool {
		r := bctx.Request()
		if r != original || r.Namespace != namespace || r.ClientIP != ip || token.FromRequest(r) != bearer || !bytes.Equal(r.Data, data) {
			return false
		}
		current, err := participationCommand(r)
		return err == nil && current == command
	}
	check := func() error {
		return a.checkNative(bctx.Context(), namespace, original.ObjectID, ip, bearer, api.NamespaceParticipationIdentity, elemental.OperationCreate, bound)
	}
	if err := check(); err != nil {
		return nil, err
	}
	return check, nil
}

// Operation-specific wrappers select resources/verbs. Every check is uncached
// and retains neither parsed token nor a positive permission decision.
func (a *NamespaceParticipationAuthorizer) checkNative(ctx context.Context, namespace, objectID, ip, bearer string, identity elemental.Identity, operation elemental.Operation, bound func() bool) error {
	denied := participationError(http.StatusForbidden)
	if ctx == nil || ctx.Err() != nil || !bound() {
		return denied
	}
	action, idt, err := a.authenticator.CheckAuthentication(ctx, bearer)
	if err != nil || action != bahamut.AuthActionContinue || !participationTokenValid(idt) {
		return denied
	}
	revoked, err := a.retriever.Revoked(ctx, namespace, idt.ID, idt.Identity, idt.IssuedAt.Time)
	if err != nil || revoked || ctx.Err() != nil || !bound() {
		return denied
	}
	opts := []permissions.RetrieverOption{permissions.OptionRetrieverID(objectID), permissions.OptionRetrieverSourceIP(ip)}
	if idt.Restrictions != nil {
		opts = append(opts, permissions.OptionRetrieverRestrictions(*idt.Restrictions))
	}
	perms, err := a.retriever.Permissions(ctx, idt.Identity, namespace, opts...)
	if err != nil || !perms.Allows(string(operation), identity.Category) || ctx.Err() != nil || !bound() {
		return denied
	}
	// Remote checks cannot extend native cryptographic/token validity.
	action, current, err := a.authenticator.CheckAuthentication(ctx, bearer)
	if err != nil || action != bahamut.AuthActionContinue || !participationTokenValid(current) || current.ID != idt.ID || !current.IssuedAt.Equal(idt.IssuedAt.Time) || !bound() || ctx.Err() != nil {
		return denied
	}
	return nil
}

func participationTokenValid(idt *token.IdentityToken) bool {
	return idt != nil && !idt.Refresh && idt.ID != "" && idt.IssuedAt != nil && !idt.IssuedAt.IsZero() && idt.ExpiresAt != nil &&
		idt.ExpiresAt.After(idt.IssuedAt.Time) && !idt.IssuedAt.After(time.Now()) &&
		jwt.NewValidator(jwt.WithExpirationRequired(), jwt.WithIssuedAt()).Validate(idt) == nil
}
