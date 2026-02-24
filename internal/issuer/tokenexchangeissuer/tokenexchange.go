package tokenexchangeissuer

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"

	"go.acuvity.ai/a3s/internal/dsgauth"
	"go.acuvity.ai/a3s/pkgs/token"
)

// New returns a new token exchange issuer.
func New(ctx context.Context, validator dsgauth.Validator, accessToken string) (token.Issuer, error) {

	c := newTokenExchangeIssuer()
	if err := c.fromToken(ctx, validator, accessToken); err != nil {
		return nil, err
	}

	return c, nil
}

// NewFromClaims returns a token exchange issuer from already validated claims.
func NewFromClaims(claims map[string]any) (token.Issuer, error) {
	c := newTokenExchangeIssuer()
	c.token.Identity = computeTokenExchangeClaims(claims)
	return c, nil
}

type tokenExchangeIssuer struct {
	token *token.IdentityToken
}

func newTokenExchangeIssuer() *tokenExchangeIssuer {
	return &tokenExchangeIssuer{
		token: token.NewIdentityToken(token.Source{Type: "tokenexchange"}),
	}
}

// Issue returns the IdentityToken.
func (c *tokenExchangeIssuer) Issue() *token.IdentityToken {

	return c.token
}

func (c *tokenExchangeIssuer) fromToken(ctx context.Context, validator dsgauth.Validator, accessToken string) error {
	if validator == nil {
		return ErrTokenExchange{Err: fmt.Errorf("token exchange validator is not configured")}
	}
	if accessToken == "" {
		return ErrTokenExchange{Err: fmt.Errorf("missing access token")}
	}

	claims, err := validator.ValidateAccessToken(ctx, accessToken)
	if err != nil {
		return ErrTokenExchange{Err: err}
	}

	c.token.Identity = computeTokenExchangeClaims(claims)

	return nil
}

func computeTokenExchangeClaims(claims map[string]any) []string {

	out := []string{}

	for k, v := range claims {
		flattenTokenExchangeClaim(strings.TrimLeft(k, "@"), v, &out)
	}

	// Compatibility aliases for Acuvity tenant resolution and policies.
	// Local UI/backend paths often rely on "@org=..." claims.
	addClaimAliases(&out)

	sort.Strings(out)

	return out
}

func addClaimAliases(out *[]string) {
	claims := *out
	org := ""
	email := ""
	hasEmailClaim := false

	for _, c := range claims {
		parts := strings.SplitN(c, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key, val := parts[0], parts[1]
		if val == "" {
			continue
		}

		switch key {
		case "org", "organization":
			if org == "" {
				org = val
			}
		case "email", "preferred_username", "nameid", "upn":
			if key == "email" {
				hasEmailClaim = true
			}
			if email == "" && isEmailLike(val) {
				email = val
			}
		}

		// Fallback for nested or custom claim keys like "profile.alias".
		if email == "" && isEmailLike(val) {
			email = val
		}
	}

	if org == "" && email != "" {
		emailParts := strings.SplitN(email, "@", 2)
		if len(emailParts) == 2 && emailParts[0] != "" {
			org = emailParts[0]
		}
	}

	if org != "" {
		appendUniqueClaim(out, "@org="+org)
	}
	if email != "" && !hasEmailClaim {
		appendUniqueClaim(out, "email="+email)
	}
}

func isEmailLike(v string) bool {
	if strings.Contains(v, " ") {
		return false
	}
	parts := strings.SplitN(v, "@", 2)
	if len(parts) != 2 {
		return false
	}
	if parts[0] == "" || parts[1] == "" {
		return false
	}
	// Keep it permissive, but avoid obvious non-email values.
	return strings.Contains(parts[1], ".")
}

func appendUniqueClaim(out *[]string, claim string) {
	for _, c := range *out {
		if c == claim {
			return
		}
	}
	*out = append(*out, claim)
}

func flattenTokenExchangeClaim(key string, value any, out *[]string) {
	switch claim := value.(type) {
	case nil:
		return
	case map[string]any:
		for k, v := range claim {
			subKey := strings.TrimLeft(k, "@")
			if key != "" {
				subKey = key + "." + subKey
			}
			flattenTokenExchangeClaim(subKey, v, out)
		}
	case []any:
		for _, item := range claim {
			flattenTokenExchangeClaim(key, item, out)
		}
	case []string:
		for _, item := range claim {
			*out = append(*out, fmt.Sprintf("%s=%s", key, item))
		}
	case []float64:
		for _, item := range claim {
			*out = append(*out, fmt.Sprintf("%s=%s", key, formatFloat64Claim(key, item)))
		}
	case []int:
		for _, item := range claim {
			*out = append(*out, fmt.Sprintf("%s=%d", key, item))
		}
	case []int64:
		for _, item := range claim {
			*out = append(*out, fmt.Sprintf("%s=%d", key, item))
		}
	case json.Number:
		*out = append(*out, fmt.Sprintf("%s=%s", key, formatNumberClaim(key, claim)))
	case float64:
		*out = append(*out, fmt.Sprintf("%s=%s", key, formatFloat64Claim(key, claim)))
	case int:
		*out = append(*out, fmt.Sprintf("%s=%d", key, claim))
	case int64:
		*out = append(*out, fmt.Sprintf("%s=%d", key, claim))
	case string:
		*out = append(*out, fmt.Sprintf("%s=%s", key, claim))
	case bool:
		*out = append(*out, fmt.Sprintf("%s=%t", key, claim))
	default:
		*out = append(*out, fmt.Sprintf("%s=%v", key, claim))
	}
}

func formatFloat64Claim(key string, v float64) string {
	if !math.IsNaN(v) && !math.IsInf(v, 0) && v == math.Trunc(v) {
		return strconv.FormatInt(int64(v), 10)
	}
	if key == "exp" || key == "iat" || key == "nbf" {
		return strconv.FormatInt(int64(v), 10)
	}
	return strconv.FormatFloat(v, 'f', -1, 64)
}

func formatNumberClaim(key string, v json.Number) string {
	if i, err := v.Int64(); err == nil {
		return strconv.FormatInt(i, 10)
	}
	if f, err := strconv.ParseFloat(v.String(), 64); err == nil {
		return formatFloat64Claim(key, f)
	}
	return v.String()
}
