# Model
model:
  rest_name: import
  resource_name: import
  entity_name: Import
  friendly_name: Import
  package: a3s
  group: core/import
  description: Import multiple resource at once.

# Attributes
attributes:
  v1:
  - name: A3SSources
    friendly_name: A3SSources
    description: A3S sources to import.
    type: refList
    exposed: true
    subtype: a3ssource
    omit_empty: true

  - name: HTTPSources
    friendly_name: HTTPSources
    description: HTTP sources to import.
    type: refList
    exposed: true
    subtype: httpsource
    omit_empty: true

  - name: LDAPSources
    friendly_name: LDAPSources
    description: LDAP sources to import.
    type: refList
    exposed: true
    subtype: ldapsource
    omit_empty: true

  - name: MTLSSources
    friendly_name: MTLSSources
    description: MTLS sources to import.
    type: refList
    exposed: true
    subtype: mtlssource
    omit_empty: true

  - name: OAuth2Sources
    friendly_name: OAuth2Sources
    description: OAuth2 sources to import.
    type: refList
    exposed: true
    subtype: oauth2source
    omit_empty: true

  - name: OIDCSources
    friendly_name: OIDCSources
    description: OIDC sources to import.
    type: refList
    exposed: true
    subtype: oidcsource
    omit_empty: true

  - name: SAMLSources
    friendly_name: SAMLSources
    description: SAML sources to import.
    type: refList
    exposed: true
    subtype: samlsource
    omit_empty: true

  - name: authorizations
    friendly_name: Authorizations
    description: Authorizations to import.
    type: refList
    exposed: true
    subtype: authorization
    omit_empty: true

  - name: label
    friendly_name: Label
    description: |-
      Import label that will be used to identify all the resources imported by this
      resource.
    type: string
    exposed: true
    required: true
    example_value: my-super-import
