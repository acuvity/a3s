package claims

import (
	"fmt"
	"net/mail"
	"strings"
)

// Filterable is an interface that can
// be used to filter claims.
type Filterable interface {
	GetIncludedKeys() []string
	GetIgnoredKeys() []string
}

// Filter filters the claims based on the filter.
// ignored keys take precedence over included keys.
// A claim is a match if it is prefixed or equal by the ignored/included keys.
func Filter(claims []string, filter Filterable) []string {

	if filter == nil {
		return claims
	}

	inc := make(map[string]struct{}, len(filter.GetIncludedKeys()))
	for _, key := range filter.GetIncludedKeys() {
		inc[strings.ToLower(key)] = struct{}{}
	}

	exc := make(map[string]struct{}, len(filter.GetIgnoredKeys()))
	for _, key := range filter.GetIgnoredKeys() {
		exc[strings.ToLower(key)] = struct{}{}
	}

	out := make([]string, 0, len(claims))
L:
	for _, claim := range claims {

		for prefix := range exc {
			if strings.HasPrefix(claim, prefix) {
				continue L
			}
		}

		if len(inc) > 0 {
			var found bool
			for prefix := range inc {
				if found = found || strings.HasPrefix(claim, prefix); found {
					break
				}
			}
			if !found {
				continue L
			}
		}

		out = append(out, claim)
	}

	return out
}

// A Map represents claims mappings.
type Map map[string][]string

// Set sets the value for the key.
// It will reset any existing value for the key
func (m Map) Set(k string, v string) {
	m[k] = []string{v}
}

// Add adds a value to the given key, appending
// to existing ones
func (m Map) Add(k string, v ...string) {
	m[k] = append(m[k], v...)
}

// Get returns the first value set for the key
func (m Map) Get(k string) string {

	if v, ok := m[k]; ok {
		return v[0]
	}

	return ""
}

// ToClaims converts the Map into the list
// of claims string.
func (m Map) ToClaims() []string {

	out := []string{}
	for k, vs := range m {
		for _, v := range vs {
			out = append(out, k+"="+v)
		}
	}
	return out
}

// Split is an optimized version for spliting claims in the form
// of "key=value"
func Split(tag string, key *string, value *string) (err error) {

	l := len(tag)
	if l < 3 {
		err = fmt.Errorf("invalid tag: invalid length '%s'", tag)
		return
	}

	if tag[0] == '=' {
		err = fmt.Errorf("invalid tag: missing key '%s'", tag)
		return
	}

	for i := range l {
		if tag[i] == '=' {
			if i+1 >= l {
				return fmt.Errorf("invalid tag: missing value '%s'", tag)
			}
			*key = tag[:i]
			*value = tag[i+1:]
			return
		}
	}

	return fmt.Errorf("invalid tag: missing equal symbol '%s'", tag)
}

// ToMap converts the given claim list to a map[string]string.
func ToMap(claims []string) (Map, error) {

	claimsMap := Map{}

	var k, v string

	for _, claim := range claims {
		if err := Split(claim, &k, &v); err != nil {
			return nil, err
		}
		claimsMap[k] = append(claimsMap[k], v)
	}

	return claimsMap, nil
}

// Email tries to find an email in the claims.
func Email(claims Map) string {

	options := []string{
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
		"preferred_username",
		"nameid",
		"email",
	}

	isEmail := func(email string) bool {
		if email == "" {
			return false
		}
		_, err := mail.ParseAddress(email)
		return err == nil
	}

	for _, opt := range options {
		vv := claims[opt]
		for _, v := range vv {
			if isEmail(v) {
				return v
			}
		}
	}

	for _, vv := range claims {
		for _, v := range vv {
			if isEmail(v) {
				return v
			}
		}
	}

	return ""
}
