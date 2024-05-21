package auditor

type config struct {
	trackedIdentities []*TrackedIdentity
	ignoredAttributes []string
}

// An Option can be used to configure various options in the Authenticator.
type Option func(*config)

// OptionTrackedIdentities sets the list of identities to be tracked by the auditor.
func OptionTrackedIdentities(identities ...*TrackedIdentity) Option {
	return func(cfg *config) {
		cfg.trackedIdentities = identities
	}
}

// OptionIgnoredAttributes sets the list of attributes that will be ignored.
func OptionIgnoredAttributes(attributes ...string) Option {
	return func(cfg *config) {
		cfg.ignoredAttributes = attributes
	}
}
