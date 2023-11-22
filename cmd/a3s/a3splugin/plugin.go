package main

import (
	"context"
	"fmt"
	"strings"
	"time"

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
)

// parsedClaims contains information related to the claims
type parsedClaims struct {
	domain string
	email  string
	claims []string
}

// parse returns parsed claims. returns nil in case of error.
func parse(idt *token.IdentityToken) *parsedClaims {

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

	p.claims = append(p.claims, "@source:namespace="+idt.Source.Namespace)
	p.claims = append(p.claims, "@source:type="+idt.Source.Type)
	p.claims = append(p.claims, "@source:name="+idt.Source.Name)
	p.claims = append(p.claims, emailClaim)

	return p
}

type pluginModifier struct{}

func (p *pluginModifier) Token(ctx context.Context, m manipulate.Manipulator, idt *token.IdentityToken) (*token.IdentityToken, error) {

	pc := parse(idt)
	if pc == nil {
		return idt, nil
	}

	namespaceName := namespaceOrgs + "/" + pc.domain

	ns := api.NewNamespace()
	ns.Name = namespaceName
	ns.Namespace = namespaceOrgs
	ns.Description = "Namespace for organization " + pc.domain
	ns.CreateTime = time.Now()
	ns.UpdateTime = ns.CreateTime
	if err := ns.Validate(); err != nil {
		return idt, err
	}

	mctx := manipulate.NewContext(ctx)
	err := m.Create(mctx, ns)
	if err != nil {
		if !manipulate.IsConstraintViolationError(err) {
			return idt, fmt.Errorf("unable to create organization %s namespace: %w", pc, err)
		}
		return idt, nil
	}

	// Create authorization for the user in the /orgs namespace for org namespace /orgs/b.com
	auth := api.NewAuthorization()
	auth.Namespace = namespaceOrgs
	auth.Name = pc.email + "-owner-authorization"
	auth.Description = "org: " + pc.domain + " owner: " + pc.email + " ns: " + ns.Namespace
	auth.TrustedIssuers = []string{idt.Issuer}
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
	return idt, m.Create(mctx, auth)
}

// MakePlugin is the entry point for the A3S plugin.
func MakePlugin() plugin.Modifier {
	return &pluginModifier{}
}
