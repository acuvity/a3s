// Code generated by elegen. DO NOT EDIT.
// Source: go.acuvity.ai/elemental (templates/relationships_registry.gotpl)

package api

import "go.acuvity.ai/elemental"

var relationshipsRegistry elemental.RelationshipsRegistry

func init() {

	relationshipsRegistry = elemental.RelationshipsRegistry{}

	relationshipsRegistry[A3SSourceIdentity] = &elemental.Relationship{
		Create: map[string]*elemental.RelationshipInfo{
			"root": {},
		},
		Update: map[string]*elemental.RelationshipInfo{
			"root": {},
		},
		Patch: map[string]*elemental.RelationshipInfo{
			"root": {},
		},
		Delete: map[string]*elemental.RelationshipInfo{
			"root": {},
		},
		Retrieve: map[string]*elemental.RelationshipInfo{
			"root": {},
		},
		RetrieveMany: map[string]*elemental.RelationshipInfo{
			"root": {
				Parameters: []elemental.ParameterDefinition{
					{
						Name: "q",
						Type: "string",
					},
				},
			},
		},
		Info: map[string]*elemental.RelationshipInfo{
			"root": {
				Parameters: []elemental.ParameterDefinition{
					{
						Name: "q",
						Type: "string",
					},
				},
			},
		},
	}

	relationshipsRegistry[AuthorizationIdentity] = &elemental.Relationship{
		Create: map[string]*elemental.RelationshipInfo{
			"root": {},
		},
		Update: map[string]*elemental.RelationshipInfo{
			"root": {
				Parameters: []elemental.ParameterDefinition{
					{
						Name: "q",
						Type: "string",
					},
				},
			},
		},
		Patch: map[string]*elemental.RelationshipInfo{
			"root": {
				Parameters: []elemental.ParameterDefinition{
					{
						Name: "q",
						Type: "string",
					},
				},
			},
		},
		Delete: map[string]*elemental.RelationshipInfo{
			"root": {
				Parameters: []elemental.ParameterDefinition{
					{
						Name: "q",
						Type: "string",
					},
				},
			},
		},
		Retrieve: map[string]*elemental.RelationshipInfo{
			"root": {
				Parameters: []elemental.ParameterDefinition{
					{
						Name: "q",
						Type: "string",
					},
				},
			},
		},
		RetrieveMany: map[string]*elemental.RelationshipInfo{
			"root": {
				Parameters: []elemental.ParameterDefinition{
					{
						Name: "q",
						Type: "string",
					},
				},
			},
		},
		Info: map[string]*elemental.RelationshipInfo{
			"root": {
				Parameters: []elemental.ParameterDefinition{
					{
						Name: "q",
						Type: "string",
					},
				},
			},
		},
	}

	relationshipsRegistry[AuthzIdentity] = &elemental.Relationship{
		Create: map[string]*elemental.RelationshipInfo{
			"root": {},
		},
	}

	relationshipsRegistry[GroupIdentity] = &elemental.Relationship{
		Create: map[string]*elemental.RelationshipInfo{
			"root": {},
		},
		Update: map[string]*elemental.RelationshipInfo{
			"root": {
				Parameters: []elemental.ParameterDefinition{
					{
						Name: "q",
						Type: "string",
					},
				},
			},
		},
		Patch: map[string]*elemental.RelationshipInfo{
			"root": {
				Parameters: []elemental.ParameterDefinition{
					{
						Name: "q",
						Type: "string",
					},
				},
			},
		},
		Delete: map[string]*elemental.RelationshipInfo{
			"root": {
				Parameters: []elemental.ParameterDefinition{
					{
						Name: "q",
						Type: "string",
					},
				},
			},
		},
		Retrieve: map[string]*elemental.RelationshipInfo{
			"root": {
				Parameters: []elemental.ParameterDefinition{
					{
						Name: "q",
						Type: "string",
					},
				},
			},
		},
		RetrieveMany: map[string]*elemental.RelationshipInfo{
			"root": {
				Parameters: []elemental.ParameterDefinition{
					{
						Name: "q",
						Type: "string",
					},
				},
			},
		},
		Info: map[string]*elemental.RelationshipInfo{
			"root": {
				Parameters: []elemental.ParameterDefinition{
					{
						Name: "q",
						Type: "string",
					},
				},
			},
		},
	}

	relationshipsRegistry[HTTPSourceIdentity] = &elemental.Relationship{
		Create: map[string]*elemental.RelationshipInfo{
			"root": {},
		},
		Update: map[string]*elemental.RelationshipInfo{
			"root": {},
		},
		Patch: map[string]*elemental.RelationshipInfo{
			"root": {},
		},
		Delete: map[string]*elemental.RelationshipInfo{
			"root": {},
		},
		Retrieve: map[string]*elemental.RelationshipInfo{
			"root": {},
		},
		RetrieveMany: map[string]*elemental.RelationshipInfo{
			"root": {
				Parameters: []elemental.ParameterDefinition{
					{
						Name: "q",
						Type: "string",
					},
				},
			},
		},
		Info: map[string]*elemental.RelationshipInfo{
			"root": {
				Parameters: []elemental.ParameterDefinition{
					{
						Name: "q",
						Type: "string",
					},
				},
			},
		},
	}

	relationshipsRegistry[IdentityModifierIdentity] = &elemental.Relationship{}

	relationshipsRegistry[ImportIdentity] = &elemental.Relationship{
		Create: map[string]*elemental.RelationshipInfo{
			"root": {
				Parameters: []elemental.ParameterDefinition{
					{
						Name: "delete",
						Type: "boolean",
					},
				},
			},
		},
	}

	relationshipsRegistry[IssueIdentity] = &elemental.Relationship{
		Create: map[string]*elemental.RelationshipInfo{
			"root": {},
		},
	}

	relationshipsRegistry[LDAPSourceIdentity] = &elemental.Relationship{
		Create: map[string]*elemental.RelationshipInfo{
			"root": {},
		},
		Update: map[string]*elemental.RelationshipInfo{
			"root": {},
		},
		Patch: map[string]*elemental.RelationshipInfo{
			"root": {},
		},
		Delete: map[string]*elemental.RelationshipInfo{
			"root": {},
		},
		Retrieve: map[string]*elemental.RelationshipInfo{
			"root": {},
		},
		RetrieveMany: map[string]*elemental.RelationshipInfo{
			"root": {
				Parameters: []elemental.ParameterDefinition{
					{
						Name: "q",
						Type: "string",
					},
				},
			},
		},
		Info: map[string]*elemental.RelationshipInfo{
			"root": {
				Parameters: []elemental.ParameterDefinition{
					{
						Name: "q",
						Type: "string",
					},
				},
			},
		},
	}

	relationshipsRegistry[LogoutIdentity] = &elemental.Relationship{
		Create: map[string]*elemental.RelationshipInfo{
			"root": {},
		},
	}

	relationshipsRegistry[MTLSSourceIdentity] = &elemental.Relationship{
		Create: map[string]*elemental.RelationshipInfo{
			"root": {},
		},
		Update: map[string]*elemental.RelationshipInfo{
			"root": {},
		},
		Patch: map[string]*elemental.RelationshipInfo{
			"root": {},
		},
		Delete: map[string]*elemental.RelationshipInfo{
			"root": {},
		},
		Retrieve: map[string]*elemental.RelationshipInfo{
			"root": {},
		},
		RetrieveMany: map[string]*elemental.RelationshipInfo{
			"root": {
				Parameters: []elemental.ParameterDefinition{
					{
						Name: "q",
						Type: "string",
					},
				},
			},
		},
		Info: map[string]*elemental.RelationshipInfo{
			"root": {
				Parameters: []elemental.ParameterDefinition{
					{
						Name: "q",
						Type: "string",
					},
				},
			},
		},
	}

	relationshipsRegistry[NamespaceIdentity] = &elemental.Relationship{
		Create: map[string]*elemental.RelationshipInfo{
			"root": {},
		},
		Update: map[string]*elemental.RelationshipInfo{
			"root": {
				Parameters: []elemental.ParameterDefinition{
					{
						Name: "q",
						Type: "string",
					},
				},
			},
		},
		Patch: map[string]*elemental.RelationshipInfo{
			"root": {
				Parameters: []elemental.ParameterDefinition{
					{
						Name: "q",
						Type: "string",
					},
				},
			},
		},
		Delete: map[string]*elemental.RelationshipInfo{
			"root": {
				Parameters: []elemental.ParameterDefinition{
					{
						Name: "q",
						Type: "string",
					},
				},
			},
		},
		Retrieve: map[string]*elemental.RelationshipInfo{
			"root": {
				Parameters: []elemental.ParameterDefinition{
					{
						Name: "q",
						Type: "string",
					},
				},
			},
		},
		RetrieveMany: map[string]*elemental.RelationshipInfo{
			"root": {
				Parameters: []elemental.ParameterDefinition{
					{
						Name: "q",
						Type: "string",
					},
				},
			},
		},
		Info: map[string]*elemental.RelationshipInfo{
			"root": {
				Parameters: []elemental.ParameterDefinition{
					{
						Name: "q",
						Type: "string",
					},
				},
			},
		},
	}

	relationshipsRegistry[NamespaceDeletionRecordIdentity] = &elemental.Relationship{
		RetrieveMany: map[string]*elemental.RelationshipInfo{
			"root": {
				Parameters: []elemental.ParameterDefinition{
					{
						Name: "q",
						Type: "string",
					},
				},
			},
		},
		Info: map[string]*elemental.RelationshipInfo{
			"root": {
				Parameters: []elemental.ParameterDefinition{
					{
						Name: "q",
						Type: "string",
					},
				},
			},
		},
	}

	relationshipsRegistry[OAuth2SourceIdentity] = &elemental.Relationship{
		Create: map[string]*elemental.RelationshipInfo{
			"root": {},
		},
		Update: map[string]*elemental.RelationshipInfo{
			"root": {},
		},
		Patch: map[string]*elemental.RelationshipInfo{
			"root": {},
		},
		Delete: map[string]*elemental.RelationshipInfo{
			"root": {},
		},
		Retrieve: map[string]*elemental.RelationshipInfo{
			"root": {},
		},
		RetrieveMany: map[string]*elemental.RelationshipInfo{
			"root": {
				Parameters: []elemental.ParameterDefinition{
					{
						Name: "q",
						Type: "string",
					},
				},
			},
		},
		Info: map[string]*elemental.RelationshipInfo{
			"root": {
				Parameters: []elemental.ParameterDefinition{
					{
						Name: "q",
						Type: "string",
					},
				},
			},
		},
	}

	relationshipsRegistry[OIDCSourceIdentity] = &elemental.Relationship{
		Create: map[string]*elemental.RelationshipInfo{
			"root": {},
		},
		Update: map[string]*elemental.RelationshipInfo{
			"root": {},
		},
		Patch: map[string]*elemental.RelationshipInfo{
			"root": {},
		},
		Delete: map[string]*elemental.RelationshipInfo{
			"root": {},
		},
		Retrieve: map[string]*elemental.RelationshipInfo{
			"root": {},
		},
		RetrieveMany: map[string]*elemental.RelationshipInfo{
			"root": {
				Parameters: []elemental.ParameterDefinition{
					{
						Name: "q",
						Type: "string",
					},
				},
			},
		},
		Info: map[string]*elemental.RelationshipInfo{
			"root": {
				Parameters: []elemental.ParameterDefinition{
					{
						Name: "q",
						Type: "string",
					},
				},
			},
		},
	}

	relationshipsRegistry[PermissionsIdentity] = &elemental.Relationship{
		Create: map[string]*elemental.RelationshipInfo{
			"root": {},
		},
	}

	relationshipsRegistry[RevocationIdentity] = &elemental.Relationship{
		Create: map[string]*elemental.RelationshipInfo{
			"root": {},
		},
		Delete: map[string]*elemental.RelationshipInfo{
			"root": {},
		},
		Retrieve: map[string]*elemental.RelationshipInfo{
			"root": {},
		},
		RetrieveMany: map[string]*elemental.RelationshipInfo{
			"root": {
				Parameters: []elemental.ParameterDefinition{
					{
						Name: "q",
						Type: "string",
					},
				},
			},
		},
		Info: map[string]*elemental.RelationshipInfo{
			"root": {
				Parameters: []elemental.ParameterDefinition{
					{
						Name: "q",
						Type: "string",
					},
				},
			},
		},
	}

	relationshipsRegistry[RootIdentity] = &elemental.Relationship{}

	relationshipsRegistry[SAMLSourceIdentity] = &elemental.Relationship{
		Create: map[string]*elemental.RelationshipInfo{
			"root": {},
		},
		Update: map[string]*elemental.RelationshipInfo{
			"root": {},
		},
		Patch: map[string]*elemental.RelationshipInfo{
			"root": {},
		},
		Delete: map[string]*elemental.RelationshipInfo{
			"root": {},
		},
		Retrieve: map[string]*elemental.RelationshipInfo{
			"root": {},
		},
		RetrieveMany: map[string]*elemental.RelationshipInfo{
			"root": {
				Parameters: []elemental.ParameterDefinition{
					{
						Name: "q",
						Type: "string",
					},
				},
			},
		},
		Info: map[string]*elemental.RelationshipInfo{
			"root": {
				Parameters: []elemental.ParameterDefinition{
					{
						Name: "q",
						Type: "string",
					},
				},
			},
		},
	}

}
