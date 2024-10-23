// Code generated by elegen. DO NOT EDIT.
// Source: go.acuvity.ai/elemental (templates/identities_registry.gotpl)

package api

import "go.acuvity.ai/elemental"

var (
	identityNamesMap = map[string]elemental.Identity{
		"a3ssource":        A3SSourceIdentity,
		"authorization":    AuthorizationIdentity,
		"authz":            AuthzIdentity,
		"group":            GroupIdentity,
		"httpsource":       HTTPSourceIdentity,
		"identitymodifier": IdentityModifierIdentity,
		"import":           ImportIdentity,
		"issue":            IssueIdentity,

		"ldapsource":              LDAPSourceIdentity,
		"logout":                  LogoutIdentity,
		"mtlssource":              MTLSSourceIdentity,
		"namespace":               NamespaceIdentity,
		"namespacedeletionrecord": NamespaceDeletionRecordIdentity,
		"oauth2source":            OAuth2SourceIdentity,
		"oidcsource":              OIDCSourceIdentity,
		"permissions":             PermissionsIdentity,
		"revocation":              RevocationIdentity,
		"root":                    RootIdentity,
		"samlsource":              SAMLSourceIdentity,
	}

	identitycategoriesMap = map[string]elemental.Identity{
		"a3ssources":       A3SSourceIdentity,
		"authorizations":   AuthorizationIdentity,
		"authz":            AuthzIdentity,
		"groups":           GroupIdentity,
		"httpsources":      HTTPSourceIdentity,
		"identitymodifier": IdentityModifierIdentity,
		"import":           ImportIdentity,
		"issue":            IssueIdentity,

		"ldapsources":              LDAPSourceIdentity,
		"logout":                   LogoutIdentity,
		"mtlssources":              MTLSSourceIdentity,
		"namespaces":               NamespaceIdentity,
		"namespacedeletionrecords": NamespaceDeletionRecordIdentity,
		"oauth2sources":            OAuth2SourceIdentity,
		"oidcsources":              OIDCSourceIdentity,
		"permissions":              PermissionsIdentity,
		"revocations":              RevocationIdentity,
		"root":                     RootIdentity,
		"samlsources":              SAMLSourceIdentity,
	}

	aliasesMap = map[string]elemental.Identity{}

	indexesMap = map[string][][]string{
		"a3ssource": {
			{":shard", ":unique", "zone", "zHash"},
			{"namespace"},
			{"namespace", "ID"},
			{"namespace", "importLabel"},
			{"namespace", "name"},
		},
		"authorization": {
			{":shard", ":unique", "zone", "zHash"},
			{"namespace"},
			{"namespace", "ID"},
			{"namespace", "flattenedSubject", "disabled"},
			{"namespace", "flattenedSubject", "propagate"},
			{"namespace", "importLabel"},
			{"namespace", "label"},
			{"namespace", "trustedIssuers"},
		},
		"authz": nil,
		"group": {
			{":shard", ":unique", "zone", "zHash"},
			{"namespace"},
			{"namespace", "ID"},
			{"namespace", "flattenedSubject", "disabled"},
			{"namespace", "flattenedSubject", "propagate"},
			{"namespace", "importLabel"},
			{"namespace", "label"},
		},
		"httpsource": {
			{":shard", ":unique", "zone", "zHash"},
			{"namespace"},
			{"namespace", "ID"},
			{"namespace", "importLabel"},
			{"namespace", "name"},
		},
		"identitymodifier": nil,
		"import":           nil,
		"issue":            nil,
		"ldapsource": {
			{":shard", ":unique", "zone", "zHash"},
			{"namespace"},
			{"namespace", "ID"},
			{"namespace", "importLabel"},
			{"namespace", "name"},
		},
		"logout": nil,
		"mtlssource": {
			{":shard", ":unique", "zone", "zHash"},
			{"fingerprints"},
			{"namespace"},
			{"namespace", "ID"},
			{"namespace", "importLabel"},
			{"namespace", "name"},
			{"subjectKeyIDs"},
		},
		"namespace": {
			{":shard", ":unique", "zone", "zHash"},
			{"name"},
			{"namespace"},
			{"namespace", "ID"},
			{"namespace", "importLabel"},
			{"namespace", "label"},
			{"namespace", "name"},
		},
		"namespacedeletionrecord": {
			{":shard", ":unique", "zone", "zHash"},
			{"namespace"},
			{"namespace", "ID"},
		},
		"oauth2source": {
			{":shard", ":unique", "zone", "zHash"},
			{"namespace"},
			{"namespace", "ID"},
			{"namespace", "importLabel"},
			{"namespace", "name"},
		},
		"oidcsource": {
			{":shard", ":unique", "zone", "zHash"},
			{"namespace"},
			{"namespace", "ID"},
			{"namespace", "importLabel"},
			{"namespace", "name"},
		},
		"permissions": nil,
		"revocation": {
			{":shard", ":unique", "zone", "zHash"},
			{"namespace"},
			{"namespace", "ID"},
			{"namespace", "tokenid"},
			{"tokenid"},
		},
		"root": nil,
		"samlsource": {
			{":shard", ":unique", "zone", "zHash"},
			{"namespace"},
			{"namespace", "ID"},
			{"namespace", "importLabel"},
			{"namespace", "name"},
		},
	}
)

// ModelVersion returns the current version of the model.
func ModelVersion() float64 { return 1 }

type modelManager struct{}

func (f modelManager) IdentityFromName(name string) elemental.Identity {

	return identityNamesMap[name]
}

func (f modelManager) IdentityFromCategory(category string) elemental.Identity {

	return identitycategoriesMap[category]
}

func (f modelManager) IdentityFromAlias(alias string) elemental.Identity {

	return aliasesMap[alias]
}

func (f modelManager) IdentityFromAny(any string) (i elemental.Identity) {

	if i = f.IdentityFromName(any); !i.IsEmpty() {
		return i
	}

	if i = f.IdentityFromCategory(any); !i.IsEmpty() {
		return i
	}

	return f.IdentityFromAlias(any)
}

func (f modelManager) Identifiable(identity elemental.Identity) elemental.Identifiable {

	switch identity {

	case A3SSourceIdentity:
		return NewA3SSource()
	case AuthorizationIdentity:
		return NewAuthorization()
	case AuthzIdentity:
		return NewAuthz()
	case GroupIdentity:
		return NewGroup()
	case HTTPSourceIdentity:
		return NewHTTPSource()
	case IdentityModifierIdentity:
		return NewIdentityModifier()
	case ImportIdentity:
		return NewImport()
	case IssueIdentity:
		return NewIssue()
	case LDAPSourceIdentity:
		return NewLDAPSource()
	case LogoutIdentity:
		return NewLogout()
	case MTLSSourceIdentity:
		return NewMTLSSource()
	case NamespaceIdentity:
		return NewNamespace()
	case NamespaceDeletionRecordIdentity:
		return NewNamespaceDeletionRecord()
	case OAuth2SourceIdentity:
		return NewOAuth2Source()
	case OIDCSourceIdentity:
		return NewOIDCSource()
	case PermissionsIdentity:
		return NewPermissions()
	case RevocationIdentity:
		return NewRevocation()
	case RootIdentity:
		return NewRoot()
	case SAMLSourceIdentity:
		return NewSAMLSource()
	default:
		return nil
	}
}

func (f modelManager) SparseIdentifiable(identity elemental.Identity) elemental.SparseIdentifiable {

	switch identity {

	case A3SSourceIdentity:
		return NewSparseA3SSource()
	case AuthorizationIdentity:
		return NewSparseAuthorization()
	case AuthzIdentity:
		return NewSparseAuthz()
	case GroupIdentity:
		return NewSparseGroup()
	case HTTPSourceIdentity:
		return NewSparseHTTPSource()
	case IdentityModifierIdentity:
		return NewSparseIdentityModifier()
	case ImportIdentity:
		return NewSparseImport()
	case IssueIdentity:
		return NewSparseIssue()
	case LDAPSourceIdentity:
		return NewSparseLDAPSource()
	case LogoutIdentity:
		return NewSparseLogout()
	case MTLSSourceIdentity:
		return NewSparseMTLSSource()
	case NamespaceIdentity:
		return NewSparseNamespace()
	case NamespaceDeletionRecordIdentity:
		return NewSparseNamespaceDeletionRecord()
	case OAuth2SourceIdentity:
		return NewSparseOAuth2Source()
	case OIDCSourceIdentity:
		return NewSparseOIDCSource()
	case PermissionsIdentity:
		return NewSparsePermissions()
	case RevocationIdentity:
		return NewSparseRevocation()
	case SAMLSourceIdentity:
		return NewSparseSAMLSource()
	default:
		return nil
	}
}

func (f modelManager) Indexes(identity elemental.Identity) [][]string {

	return indexesMap[identity.Name]
}

func (f modelManager) IdentifiableFromString(any string) elemental.Identifiable {

	return f.Identifiable(f.IdentityFromAny(any))
}

func (f modelManager) Identifiables(identity elemental.Identity) elemental.Identifiables {

	switch identity {

	case A3SSourceIdentity:
		return &A3SSourcesList{}
	case AuthorizationIdentity:
		return &AuthorizationsList{}
	case AuthzIdentity:
		return &AuthzsList{}
	case GroupIdentity:
		return &GroupsList{}
	case HTTPSourceIdentity:
		return &HTTPSourcesList{}
	case IdentityModifierIdentity:
		return &IdentityModifiersList{}
	case ImportIdentity:
		return &ImportsList{}
	case IssueIdentity:
		return &IssuesList{}
	case LDAPSourceIdentity:
		return &LDAPSourcesList{}
	case LogoutIdentity:
		return &LogoutsList{}
	case MTLSSourceIdentity:
		return &MTLSSourcesList{}
	case NamespaceIdentity:
		return &NamespacesList{}
	case NamespaceDeletionRecordIdentity:
		return &NamespaceDeletionRecordsList{}
	case OAuth2SourceIdentity:
		return &OAuth2SourcesList{}
	case OIDCSourceIdentity:
		return &OIDCSourcesList{}
	case PermissionsIdentity:
		return &PermissionsList{}
	case RevocationIdentity:
		return &RevocationsList{}
	case SAMLSourceIdentity:
		return &SAMLSourcesList{}
	default:
		return nil
	}
}

func (f modelManager) SparseIdentifiables(identity elemental.Identity) elemental.SparseIdentifiables {

	switch identity {

	case A3SSourceIdentity:
		return &SparseA3SSourcesList{}
	case AuthorizationIdentity:
		return &SparseAuthorizationsList{}
	case AuthzIdentity:
		return &SparseAuthzsList{}
	case GroupIdentity:
		return &SparseGroupsList{}
	case HTTPSourceIdentity:
		return &SparseHTTPSourcesList{}
	case IdentityModifierIdentity:
		return &SparseIdentityModifiersList{}
	case ImportIdentity:
		return &SparseImportsList{}
	case IssueIdentity:
		return &SparseIssuesList{}
	case LDAPSourceIdentity:
		return &SparseLDAPSourcesList{}
	case LogoutIdentity:
		return &SparseLogoutsList{}
	case MTLSSourceIdentity:
		return &SparseMTLSSourcesList{}
	case NamespaceIdentity:
		return &SparseNamespacesList{}
	case NamespaceDeletionRecordIdentity:
		return &SparseNamespaceDeletionRecordsList{}
	case OAuth2SourceIdentity:
		return &SparseOAuth2SourcesList{}
	case OIDCSourceIdentity:
		return &SparseOIDCSourcesList{}
	case PermissionsIdentity:
		return &SparsePermissionsList{}
	case RevocationIdentity:
		return &SparseRevocationsList{}
	case SAMLSourceIdentity:
		return &SparseSAMLSourcesList{}
	default:
		return nil
	}
}

func (f modelManager) IdentifiablesFromString(any string) elemental.Identifiables {

	return f.Identifiables(f.IdentityFromAny(any))
}

func (f modelManager) Relationships() elemental.RelationshipsRegistry {

	return relationshipsRegistry
}

func (f modelManager) AllIdentities() []elemental.Identity {
	return AllIdentities()
}

var manager = modelManager{}

// Manager returns the model elemental.ModelManager.
func Manager() elemental.ModelManager { return manager }

// AllIdentities returns all existing identities.
func AllIdentities() []elemental.Identity {

	return []elemental.Identity{
		A3SSourceIdentity,
		AuthorizationIdentity,
		AuthzIdentity,
		GroupIdentity,
		HTTPSourceIdentity,
		IdentityModifierIdentity,
		ImportIdentity,
		IssueIdentity,
		LDAPSourceIdentity,
		LogoutIdentity,
		MTLSSourceIdentity,
		NamespaceIdentity,
		NamespaceDeletionRecordIdentity,
		OAuth2SourceIdentity,
		OIDCSourceIdentity,
		PermissionsIdentity,
		RevocationIdentity,
		RootIdentity,
		SAMLSourceIdentity,
	}
}

// AliasesForIdentity returns all the aliases for the given identity.
func AliasesForIdentity(identity elemental.Identity) []string {

	switch identity {
	case A3SSourceIdentity:
		return []string{}
	case AuthorizationIdentity:
		return []string{}
	case AuthzIdentity:
		return []string{}
	case GroupIdentity:
		return []string{}
	case HTTPSourceIdentity:
		return []string{}
	case IdentityModifierIdentity:
		return []string{}
	case ImportIdentity:
		return []string{}
	case IssueIdentity:
		return []string{}
	case LDAPSourceIdentity:
		return []string{}
	case LogoutIdentity:
		return []string{}
	case MTLSSourceIdentity:
		return []string{}
	case NamespaceIdentity:
		return []string{}
	case NamespaceDeletionRecordIdentity:
		return []string{}
	case OAuth2SourceIdentity:
		return []string{}
	case OIDCSourceIdentity:
		return []string{}
	case PermissionsIdentity:
		return []string{}
	case RevocationIdentity:
		return []string{}
	case RootIdentity:
		return []string{}
	case SAMLSourceIdentity:
		return []string{}
	}

	return nil
}
