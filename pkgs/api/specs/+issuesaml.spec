# Model
model:
  rest_name: issuesaml
  resource_name: issuesaml
  entity_name: IssueSAML
  friendly_name: IssueSAML
  package: a3s
  group: authn/issue
  description: Additional issuing information for the SAML source.
  detached: true

# Attributes
attributes:
  v1:
  - name: SAMLResponse
    friendly_name: RedirectURL
    description: OIDC redirect url.
    type: string
    exposed: true
    omit_empty: true

  - name: authURL
    friendly_name: AuthURL
    description: Contains the auth URL is noAuthRedirect is set to true.
    type: string
    exposed: true
    read_only: true
    omit_empty: true

  - name: noAuthRedirect
    friendly_name: NoAuthRedirect
    description: |-
      If set, instruct the server to return the OIDC auth url in authURL instead of
      performing an HTTP redirection.
    type: boolean
    exposed: true

  - name: redirectErrorURL
    friendly_name: RedirectErrorURL
    description: OIDC redirect url in case of error.
    type: string
    exposed: true

  - name: redirectURL
    friendly_name: RedirectURL
    description: OIDC redirect url.
    type: string
    exposed: true

  - name: relayState
    friendly_name: Relay State
    description: OIDC ceremony state.
    type: string
    exposed: true
    omit_empty: true
