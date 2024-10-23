# Model
model:
  rest_name: issueoauth2
  resource_name: issueoauth2
  entity_name: IssueOAuth2
  friendly_name: IssueOAuth2
  package: a3s
  group: authn/issue
  description: Additional issuing information for the OAuth2 source.
  detached: true

# Attributes
attributes:
  v1:
  - name: authURL
    friendly_name: AuthURL
    description: Contains the auth URL is noAuthRedirect is set to true.
    type: string
    exposed: true
    read_only: true
    omit_empty: true

  - name: code
    friendly_name: Code
    description: OAuth code.
    type: string
    exposed: true

  - name: noAuthRedirect
    friendly_name: NoAuthRedirect
    description: |-
      If set, instruct the server to return the OAuth2 auth url in authURL instead of
      performing an HTTP redirection.
    type: boolean
    exposed: true

  - name: redirectErrorURL
    friendly_name: RedirectErrorURL
    description: OAuth2 redirect url in case of error.
    type: string
    exposed: true

  - name: redirectURL
    friendly_name: RedirectURL
    description: OAuth2 redirect url.
    type: string
    exposed: true

  - name: state
    friendly_name: State
    description: OAuth state.
    type: string
    exposed: true
