package processors

import (
	"net/http"

	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/a3s/pkgs/authorizer"
	"go.acuvity.ai/a3s/pkgs/permissions"
	"go.acuvity.ai/a3s/pkgs/token"
	"go.acuvity.ai/bahamut"
	"go.acuvity.ai/elemental"
)

// A AuthzProcessor is a bahamut processor for Authzs.
type AuthzProcessor struct {
	authorizer authorizer.Authorizer
	jwks       *token.JWKS
	issuer     string
	audience   string
}

// NewAuthzProcessor returns a new AuthzProcessor.
func NewAuthzProcessor(authorizer authorizer.Authorizer, jwks *token.JWKS, issuer string, audience string) *AuthzProcessor {
	return &AuthzProcessor{
		authorizer: authorizer,
		jwks:       jwks,
		issuer:     issuer,
		audience:   audience,
	}
}

// ProcessCreate handles the creates requests for Authzs.
func (p *AuthzProcessor) ProcessCreate(bctx bahamut.Context) error {

	req := bctx.InputData().(*api.Authz)

	idt, err := token.Parse(req.Token, p.jwks, p.issuer, req.Audience)
	if err != nil {
		return elemental.NewError(
			"Bad Request",
			err.Error(),
			"a3s:authz",
			http.StatusBadRequest,
		)
	}

	var r permissions.Restrictions
	if idt.Restrictions != nil {
		r = *idt.Restrictions
	}

	ok, err := p.authorizer.CheckAuthorization(
		bctx.Context(),
		idt.Identity,
		req.Action,
		req.Namespace,
		req.Resource,
		authorizer.OptionCheckID(req.ID),
		authorizer.OptionCheckSourceIP(req.IP),
		authorizer.OptionCheckRestrictions(r),
	)
	if err != nil {
		return err
	}

	if ok {
		bctx.SetStatusCode(http.StatusOK)
	} else {
		bctx.SetStatusCode(http.StatusForbidden)
	}

	return nil
}
