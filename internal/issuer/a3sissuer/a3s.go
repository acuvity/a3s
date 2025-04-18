package a3sissuer

import (
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.acuvity.ai/a3s/pkgs/permissions"
	"go.acuvity.ai/a3s/pkgs/token"
)

// New retrurns new A3S issuer.
func New(
	tokenString string,
	keychain *token.JWKS,
	requiredIssuer string,
	audience jwt.ClaimStrings,
	validity time.Duration,
	skipValidityCap bool,
) (token.Issuer, error) {

	c := newA3SIssuer()
	if err := c.fromToken(
		tokenString,
		keychain,
		requiredIssuer,
		audience,
		validity,
		skipValidityCap,
	); err != nil {
		return nil, err
	}

	return c, nil
}

type a3sIssuer struct {
	token *token.IdentityToken
}

func newA3SIssuer() *a3sIssuer {
	return &a3sIssuer{}
}

func (c *a3sIssuer) fromToken(
	tokenString string,
	keychain *token.JWKS,
	issuer string,
	audience jwt.ClaimStrings,
	validity time.Duration,
	skipValidityCap bool,
) error {

	orest, err := permissions.GetRestrictions(tokenString)
	if err != nil {
		return ErrComputeRestrictions{Err: err}
	}

	if c.token, err = token.Parse(tokenString, keychain, issuer, ""); err != nil {
		return ErrInputToken{Err: err}
	}

	if len(audience) == 0 && len(c.token.Audience) != 0 {
		return ErrInputToken{Err: fmt.Errorf("you cannot request a token with no audience from a token that has one")}
	}

	var audienceFound bool
L:
	for _, aud := range audience {
		for _, iaud := range c.token.Audience {
			if iaud == aud {
				audienceFound = true
				break L
			}
		}
	}

	if !audienceFound {
		return ErrInputToken{Err: fmt.Errorf("requested audience '%v' is not declared in initial token", audience)}
	}

	if !orest.Zero() {
		c.token.Restrictions = &orest
	}

	c.token.ExpiresAt, err = computeNewValidity(c.token.ExpiresAt, validity, c.token.Refresh || skipValidityCap)
	if err != nil {
		return ErrComputeRestrictions{Err: err}
	}

	claims := make([]string, 0, len(c.token.Identity))
	for _, c := range c.token.Identity {
		if !strings.HasPrefix(c, "@") {
			claims = append(claims, c)
		}
	}
	c.token.Identity = claims

	return nil
}

// Issue issues a token.IdentityToken derived from the initial token.
func (c *a3sIssuer) Issue() *token.IdentityToken {

	return c.token
}

func computeNewValidity(originalExpUNIX *jwt.NumericDate, requestedValidity time.Duration, skipCap bool) (*jwt.NumericDate, error) {

	if originalExpUNIX == nil || originalExpUNIX.Unix() == 0 {
		return nil, fmt.Errorf("unable to compute new validity: original expiration is zero")
	}

	if requestedValidity == 0 {
		return originalExpUNIX, nil
	}

	now := time.Now()

	originalExp := originalExpUNIX.Local()
	if now.Add(requestedValidity).After(originalExp) && !skipCap {
		return nil, fmt.Errorf("the request validity is greater than the original non refresh token")
	}

	return jwt.NewNumericDate(now.Add(requestedValidity)), nil
}
