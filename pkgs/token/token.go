package token

import (
	"crypto"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/gofrs/uuid"
	"github.com/golang-jwt/jwt/v5"
	"go.acuvity.ai/a3s/pkgs/permissions"
)

// An Issuer is an object that can issue IdentityToken.
type Issuer interface {
	Issue() *IdentityToken
}

// A Source represents the authentication source info
// used to derive an IdentityToken.
type Source struct {
	Type      string `json:"type"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name,omitempty"`
}

// An IdentityToken represents a normalized identity token.
type IdentityToken struct {

	// The identity claims of the token.
	Identity []string `json:"identity"`

	// If true, the token can be used to get a new token.
	// with a longer expiration time.
	Refresh bool `json:"refresh,omitempty"`

	// Opaque user information transmitted in the token.
	Opaque map[string]string `json:"opaque,omitempty"`

	// Restrictions applied on dynamically computed permissions.
	Restrictions *permissions.Restrictions `json:"restrictions,omitempty"`

	// Information relative to the autentication source used to
	// validate bearer's Identity.
	Source Source `json:"source"`

	jwt.RegisteredClaims
}

// NewIdentityToken returns a new IdentityToken with the
// given Source.
func NewIdentityToken(source Source) *IdentityToken {
	return &IdentityToken{
		Source: source,
	}
}

// Map returns the identity claims as map
func (t *IdentityToken) Map() map[string][]string {

	if len(t.Identity) == 0 {
		return map[string][]string{}
	}

	claimsMap := make(map[string][]string, len(t.Identity))

	for _, claim := range t.Identity {
		parts := strings.SplitN(claim, "=", 2)
		if len(parts) == 2 {
			claimsMap[parts[0]] = append(claimsMap[parts[0]], parts[1])
		}
	}

	return claimsMap
}

// Parse returns a validated IdentityToken from the given token string using the given JWKS, mandatory trusted issuer
// and requiredAudience. The token must contain the "kid" header, and that ID must match an existing key in JWKS.
// The function will populate the identity token's source using the @source* claims.
// The claim @source:type is mandatory and the function will return an error if it is missing.
func Parse(
	tokenString string,
	keychain *JWKS,
	trustedIssuer string,
	requiredAudience string,
	opts ...jwt.ParserOption,
) (*IdentityToken, error) {

	if requiredAudience != "" {
		opts = append(opts, jwt.WithAudience(requiredAudience))
	}

	if trustedIssuer != "" {
		opts = append(opts, jwt.WithIssuer(trustedIssuer))
	}

	idt := &IdentityToken{}
	if _, err := jwt.ParseWithClaims(tokenString, idt, makeKeyFunc(keychain), opts...); err != nil {
		return nil, fmt.Errorf("unable to parse jwt: %w", err)
	}

	if err := finalizeTokenParsing(idt); err != nil {
		return nil, err
	}

	return idt, nil
}

// ParseUnverified returns a non validated IdentityToken from the given tokenString,
// This method does not do any additional check on signature, issuer or audience and should
// only used to peek some data from the token before actually verifying it.
func ParseUnverified(tokenString string) (*IdentityToken, error) {

	idt := &IdentityToken{}
	if _, _, err := jwt.NewParser().ParseUnverified(tokenString, idt); err != nil {
		return nil, fmt.Errorf("unable to parse unverified jwt: %w", err)
	}

	if err := finalizeTokenParsing(idt); err != nil {
		return nil, err
	}

	return idt, nil
}

func finalizeTokenParsing(idt *IdentityToken) error {

	for _, c := range idt.Identity {
		switch {
		case strings.HasPrefix(c, "@source:name="):
			idt.Source.Name = strings.TrimPrefix(c, "@source:name=")
		case strings.HasPrefix(c, "@source:namespace="):
			idt.Source.Namespace = strings.TrimPrefix(c, "@source:namespace=")
		case strings.HasPrefix(c, "@source:type="):
			idt.Source.Type = strings.TrimPrefix(c, "@source:type=")
		}
	}

	if idt.Source.Type == "" {
		return fmt.Errorf("invalid token: missing @source:type in identity claims")
	}

	return nil
}

// JWT returns the signed JWT string signed by the given crypto.PrivateKey.
// The given kid must match the ID of the public key.
// The JWT iss and aud will be set to the provided
// issuer and audience, whatever was any current values.
// The iat field will be set time.Now(), also  ignoring current values.
// The exp field will be set to the provided time.Time. If it is a zero value time.Time,
// then any current value will be kept (potentially ending in an already expired token if the current value is
// also zero).
// cloak, if not empty, will remove any identity claims that are not prefixed with any string from the array.
func (t *IdentityToken) JWT(key crypto.PrivateKey, kid string, issuer string, audience jwt.ClaimStrings, exp time.Time, cloak []string) (string, error) {

	t.ID = uuid.Must(uuid.NewV4()).String()
	t.IssuedAt = jwt.NewNumericDate(time.Now())
	t.Issuer = issuer
	t.Audience = audience

	if !exp.IsZero() {
		t.ExpiresAt = jwt.NewNumericDate(exp)
	}

	if len(cloak) > 0 {
		var cloakedIdentity []string
		for _, claim := range t.Identity {
			for _, c := range cloak {
				if strings.HasPrefix(claim, c) {
					cloakedIdentity = append(cloakedIdentity, claim)
				}
			}
		}
		t.Identity = cloakedIdentity
	}

	if t.Source.Type == "" {
		return "", fmt.Errorf("invalid identity token: missing source type")
	}

	t.Identity = append(t.Identity, fmt.Sprintf("@source:type=%s", t.Source.Type))

	if t.Source.Namespace != "" {
		t.Identity = append(t.Identity, fmt.Sprintf("@source:namespace=%s", t.Source.Namespace))
	}

	if t.Source.Name != "" {
		t.Identity = append(t.Identity, fmt.Sprintf("@source:name=%s", t.Source.Name))
	}

	t.Identity = append(t.Identity, fmt.Sprintf("@issuer=%s", t.Issuer))

	j := jwt.NewWithClaims(jwt.SigningMethodES256, t)

	if kid != "" {
		j.Header["kid"] = kid
	}

	sort.Strings(t.Identity)

	return j.SignedString(key)
}

// Restrict applies the given permissions to the token. If the token is not already restricted
// the restrictions will be applied as is. If it is already restricted, the new restrictions will
// be applied over the existing ones, and the function will return an error if the requested
// restrictions break the limits of the current ones.
func (t *IdentityToken) Restrict(restrictions permissions.Restrictions) (err error) {

	if t.Restrictions == nil {
		t.Restrictions = &permissions.Restrictions{}
	}

	if t.Restrictions.Namespace, err = t.Restrictions.RestrictNamespace(restrictions.Namespace); err != nil {
		return err
	}

	if t.Restrictions.Networks, err = t.Restrictions.RestrictNetworks(restrictions.Networks); err != nil {
		return err
	}

	if t.Restrictions.Permissions, err = t.Restrictions.RestrictPermissions(restrictions.Permissions); err != nil {
		return err
	}

	if t.Restrictions.Zero() {
		t.Restrictions = nil
	}

	return nil
}
