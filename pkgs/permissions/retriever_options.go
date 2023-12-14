package permissions

type config struct {
	accessibleNamespaces           *[]string
	id                             string
	addr                           string
	restrictions                   Restrictions
	offloadPermissionsRestrictions bool
	label                          string
}

// A RetrieverOption represents an option of the retriver.
type RetrieverOption func(*config)

// OptionRetrieverID sets the ID to use to compute permissions.
func OptionRetrieverID(id string) RetrieverOption {
	return func(c *config) {
		c.id = id
	}
}

// OptionRetrieverSourceIP sets the source IP to use to compute permissions.
func OptionRetrieverSourceIP(ip string) RetrieverOption {
	return func(c *config) {
		c.addr = ip
	}
}

// OptionRetrieverRestrictions sets the restrictions to apply on the retrieved permissions.
func OptionRetrieverRestrictions(r Restrictions) RetrieverOption {
	return func(c *config) {
		c.restrictions = r
	}
}

// OptionOffloadPermissionsRestrictions tells the retriever to skip
// permissions restrictions computing and offload to the caller.
func OptionOffloadPermissionsRestrictions(offload bool) RetrieverOption {
	return func(c *config) {
		c.offloadPermissionsRestrictions = offload
	}
}

// OptionCollectAccessibleNamespaces allows to pass a *[]string
// that will be populated with the list of accessible namespaces
// found during permissions computations.
func OptionCollectAccessibleNamespaces(namespaces *[]string) RetrieverOption {
	return func(c *config) {
		c.accessibleNamespaces = namespaces
	}
}

// OptionFilterLabel allows to resolve policies only using those
// having a mathing label. If empty, all policies will be taken into
// account
func OptionFilterLabel(label string) RetrieverOption {
	return func(c *config) {
		c.label = label
	}
}
