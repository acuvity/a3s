package oauthserver

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strings"

	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/a3s/pkgs/permissions"
	"go.acuvity.ai/elemental"
)

// applicationRestrictions returns the restrictions of the access tokens of the
// application: its permissions, in its namespace.
func applicationRestrictions(app *api.OAuthApplication) permissions.Restrictions {

	if len(app.Permissions) == 0 {
		return permissions.Restrictions{}
	}

	return permissions.Restrictions{
		Namespace:   app.Namespace,
		Permissions: app.Permissions,
	}
}

// intersectRestrictions returns the restrictions within both the ones of the
// session and the ones of the application. They can only be expressed as one
// if, for the namespace and for the permissions, one contains the other.
func intersectRestrictions(session *permissions.Restrictions, app permissions.Restrictions) (*permissions.Restrictions, error) {

	var r permissions.Restrictions
	if session != nil {
		r = *session
	}

	namespace, err := r.RestrictNamespace(app.Namespace)
	if err != nil {
		if namespace, err = app.RestrictNamespace(r.Namespace); err != nil {
			return nil, err
		}
	}

	perms, err := r.RestrictPermissions(app.Permissions)
	if err != nil {
		if perms, err = app.RestrictPermissions(r.Permissions); err != nil {
			return nil, err
		}
	}

	r.Namespace = namespace
	r.Permissions = perms

	if r.Zero() {
		return nil, nil
	}

	return &r, nil
}

// decodeNamespace converts an encoded namespace path segment into its
// namespace form.
func decodeNamespace(encoded string) (string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("decode namespace: %w", err)
	}

	namespace := string(raw)
	if err := validateNamespace(namespace); err != nil {
		return "", err
	}

	return namespace, nil
}

func validateNamespace(namespace string) error {
	if namespace == "" {
		return errors.New("missing namespace")
	}

	if !strings.HasPrefix(namespace, "/") {
		return fmt.Errorf("invalid namespace %q", namespace)
	}

	if namespace != "/" && strings.HasSuffix(namespace, "/") {
		return fmt.Errorf("invalid namespace %q", namespace)
	}

	if strings.Contains(namespace, "//") {
		return fmt.Errorf("invalid namespace %q", namespace)
	}

	return nil
}

func containsAll(items []string, wanted []string) bool {
	available := make(map[string]struct{}, len(items))
	for _, item := range items {
		available[item] = struct{}{}
	}

	for _, want := range wanted {
		if _, ok := available[want]; !ok {
			return false
		}
	}

	return true
}

func isLoopbackIP(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// SourceAllowed reports whether the oauth application admits the given
// source through its allowedSources filters. An application without filters
// admits any source.
func SourceAllowed(app *api.OAuthApplication, source elemental.AttributeSpecifiable) (bool, error) {
	for _, allowed := range app.AllowedSources {
		filter, err := elemental.NewFilterFromString(allowed)
		if err != nil {
			return false, fmt.Errorf("invalid allowedSources filter %q on oauth application %q: %w", allowed, app.Name, err)
		}

		matched, err := elemental.MatchesFilter(source, filter)
		if err != nil {
			return false, fmt.Errorf("unable to evaluate allowedSources filter %q on oauth application %q: %w", allowed, app.Name, err)
		}
		if matched {
			return true, nil
		}
	}

	return len(app.AllowedSources) == 0, nil
}
