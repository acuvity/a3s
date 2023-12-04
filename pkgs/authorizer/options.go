package authorizer

import "go.acuvity.ai/a3s/pkgs/permissions"

type config struct {
	operationTransformer OperationTransformer
	ignoredResources     []string
}

// An Option can be used to configure various options in the Authorizer.
type Option func(*config)

// OptionIgnoredResources sets the list of identities that should skip authorizations.
func OptionIgnoredResources(identities ...string) Option {
	return func(cfg *config) {
		cfg.ignoredResources = identities
	}
}

// OptionOperationTransformer sets operation transformer to apply to each operation.
func OptionOperationTransformer(t OperationTransformer) Option {
	return func(cfg *config) {
		cfg.operationTransformer = t
	}
}

type checkConfig struct {
	accessibleNamespaces *[]string
	sourceIP             string
	id                   string
	tokenID              string
	restrictions         permissions.Restrictions
}

// An OptionCheck can be used to configure various options when calling CheckPermissions.
type OptionCheck func(*checkConfig)

// OptionCheckSourceIP sets source IP of the request.
func OptionCheckSourceIP(ip string) OptionCheck {
	return func(cfg *checkConfig) {
		cfg.sourceIP = ip
	}
}

// OptionCheckID sets source IP of the request.
func OptionCheckID(id string) OptionCheck {
	return func(cfg *checkConfig) {
		cfg.id = id
	}
}

// OptionCheckRestrictions sets source restrictions to apply.
func OptionCheckRestrictions(r permissions.Restrictions) OptionCheck {
	return func(cfg *checkConfig) {
		cfg.restrictions = r
	}
}

// OptionCheckTokenID sets token ID to check if it got revoked.
func OptionCheckTokenID(id string) OptionCheck {
	return func(cfg *checkConfig) {
		cfg.tokenID = id
	}
}

// OptionCollectAccessibleNamespaces can be used to pass a *[]string
// that will return the list of authorized namespaces.
func OptionCollectAccessibleNamespaces(authorizedNamespaces *[]string) OptionCheck {
	return func(cfg *checkConfig) {
		cfg.accessibleNamespaces = authorizedNamespaces
	}
}
