# Model
model:
  rest_name: oauthclient
  resource_name: oauthclients
  entity_name: OAuthClient
  friendly_name: OAuth Client
  package: a3s
  group: authn/app
  description: |-
    An OAuth Client is a namespace-scoped client registration linked to an OAuth
    application.
  get:
    description: Get a particular oauthclient object.
  update:
    description: Update a particular oauthclient object.
  delete:
    description: Delete a particular oauthclient object.
  extends:
  - '@sharded'
  - '@identifiable'
  - '@importable'
  - '@timed'

# Indexes
indexes:
- - :unique
  - namespace
  - clientID

# Attributes
attributes:
  v1:
  - name: description
    friendly_name: Description
    description: The description of the object.
    type: string
    exposed: true
    stored: true

  - name: oauthApplicationID
    friendly_name: OAuth Application ID
    description: Identifier of the referenced OAuth application.
    type: string
    exposed: true
    stored: true
    required: true
    example_value: 67f7b5f3f1f2d1c1b0a99887

  - name: oauthApplicationNamespace
    friendly_name: OAuth Application Namespace
    description: Namespace of the referenced OAuth application.
    type: string
    exposed: true
    stored: true
    required: true
    example_value: /my/ns

  - name: clientID
    friendly_name: Client ID
    description: Client identifier used in OAuth requests.
    type: string
    exposed: true
    stored: true
    required: true
    example_value: my-client

  - name: clientSecret
    friendly_name: Client Secret
    description: Client secret associated with the client ID.
    type: string
    exposed: true
    stored: true
    required: false
    secret: true
    transient: true
    encrypted: true
    example_value: s3cr3t

  - name: redirectURIs
    friendly_name: Redirect URIs
    description: List of allowed redirect URIs for the client.
    type: list
    exposed: true
    stored: true
    subtype: string
    required: true
    example_value:
    - https://client.example.com/callback
    validations:
    - $url_list

  - name: scopes
    friendly_name: Scopes
    description: Scopes allowed for the client.
    type: list
    exposed: true
    stored: true
    subtype: string
    example_value:
    - openid
    - profile

  - name: tokenEndpointAuthMethod
    friendly_name: Token Endpoint Auth Method
    description: How the client authenticates to the token endpoint.
    type: enum
    exposed: true
    stored: true
    required: true
    allowed_choices:
    - ClientSecretBasic
    - ClientSecretPost
    - None
    example_value: ClientSecretBasic
