package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/karlseguin/ccache/v3"

	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/a3s/pkgs/plugin"
	"go.acuvity.ai/a3s/pkgs/token"
	"go.acuvity.ai/manipulate"
)

// System constants
const (
	namespaceOrgs     = "/orgs"
	emailClaimPrefix  = "email="
	systemClaimPrefix = "@"
	cacheExpiration   = time.Hour * 12
)

// parsedClaims contains information related to the claims
type parsedClaims struct {
	domain string
	email  string
	claims []string
}

// parse returns parsed claims. returns nil in case of error.
func parse(idt *token.IdentityToken) *parsedClaims {

	// HACK: To be reviewed on what needs to be done here.
	if idt.Source.Type == "mtls" {
		return nil
	}

	emailClaim := ""
	p := &parsedClaims{}
	for i := 0; i < len(idt.Identity); i++ {
		if strings.HasPrefix(idt.Identity[i], "email=") {
			p.email = strings.TrimPrefix(idt.Identity[i], "email=")
			p.domain = strings.Split(p.email, "@")[1]
			emailClaim = idt.Identity[i]
		}
	}

	if p.email == "" || p.domain == "" {
		return nil
	}

	// Do not support gmail users
	if p.domain == "gmail.com" {
		return nil
	}

	p.claims = append(p.claims, "@source:namespace="+idt.Source.Namespace)
	p.claims = append(p.claims, "@source:type="+idt.Source.Type)
	p.claims = append(p.claims, "@source:name="+idt.Source.Name)
	p.claims = append(p.claims, emailClaim)

	return p
}

type pluginModifier struct {
	ccache *ccache.Cache[error]
}

func (p *pluginModifier) Token(ctx context.Context, m manipulate.Manipulator, idt *token.IdentityToken, issuer string) (*token.IdentityToken, error) {

	if p.ccache == nil {
		p.ccache = ccache.New(ccache.Configure[error]())
	}

	pc := parse(idt)
	if pc == nil {
		return idt, nil
	}

	item := p.ccache.Get(pc.domain)
	if item != nil {
		// Refresh the expiration
		p.ccache.Set(pc.domain, nil, cacheExpiration)
		return idt, nil
	}

	namespaceName := namespaceOrgs + "/" + pc.domain

	ns := api.NewNamespace()
	ns.Name = namespaceName
	ns.Namespace = namespaceOrgs
	ns.Description = "org: " + pc.domain
	ns.CreateTime = time.Now()
	ns.UpdateTime = ns.CreateTime
	if err := ns.Validate(); err != nil {
		return nil, err
	}

	mctx := manipulate.NewContext(ctx)
	err := m.Create(mctx, ns)
	if err != nil {
		if !manipulate.IsConstraintViolationError(err) {
			return nil, fmt.Errorf("unable to create organization %s namespace: %w", pc, err)
		}
	}

	// Create authorization for the user in the /orgs namespace for org namespace /orgs/b.com
	auth := api.NewAuthorization()
	auth.Namespace = namespaceOrgs
	auth.Name = pc.domain + "-owner-authorization"
	auth.Description = "org: " + pc.domain + " owner: " + pc.email + " ns: " + ns.Namespace
	auth.TrustedIssuers = []string{issuer}
	auth.Subject = [][]string{
		pc.claims,
	}
	auth.FlattenedSubject = auth.Subject[0]
	auth.Permissions = []string{"*:*"}
	auth.TargetNamespaces = []string{namespaceName}
	auth.Hidden = true
	auth.CreateTime = time.Now()
	auth.UpdateTime = auth.CreateTime
	mctx = manipulate.NewContext(ctx)
	err = m.Create(mctx, auth)
	if err != nil {
		if !manipulate.IsConstraintViolationError(err) {
			return nil, fmt.Errorf("unable to create organization %s namespace: %w", pc, err)
		}
	}

	p.ccache.Set(pc.domain, nil, cacheExpiration)
	return idt, nil
}

// MakePlugin is the entry point for the A3S plugin.
func MakePlugin() plugin.Modifier {
	return &pluginModifier{}
}
