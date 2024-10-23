# Model
model:
  rest_name: oauth2source
  resource_name: oauth2sources
  entity_name: OAuth2Source
  friendly_name: OAuth2 Source
  package: a3s
  group: authn/source
  description: |-
    An Oauth Auth source can be used to issue tokens based on supported OAuth2
    providers. accounts.
  get:
    description: Get a particular oidcsource object.
  update:
    description: Update a particular oidcsource object.
  delete:
    description: Delete a particular oidcsource object.
  extends:
  - '@sharded'
  - '@identifiable'
  - '@importable'
  - '@timed'

# Indexes
indexes:
- - namespace
  - name

# Attributes
attributes:
  v1:
  - name: CA
    friendly_name: CA
    description: |-
      The Certificate authority to use to validate the authenticity of the OAuth
      server. If left empty, the system trust store will be used. In most of the
      cases, you don't need to set this.
    type: string
    exposed: true
    stored: true
    validations:
    - $pem

  - name: clientID
    friendly_name: Client ID
    description: Unique client ID.
    type: string
    exposed: true
    stored: true
    required: true
    example_value: x009296

  - name: clientSecret
    friendly_name: Client Secret
    description: Client secret associated with the client ID.
    type: string
    exposed: true
    stored: true
    required: true
    example_value: Ytgbfjtj4652jHDFGls99jF
    secret: true
    encrypted: true

  - name: description
    friendly_name: Description
    description: The description of the object.
    type: string
    exposed: true
    stored: true

  - name: modifier
    friendly_name: Modifier
    description: |-
      Contains optional information about a remote service that can be used to modify
      the claims that are about to be delivered using this authentication source.
    type: ref
    exposed: true
    subtype: identitymodifier
    stored: true
    omit_empty: true
    extensions:
      noInit: true
      refMode: pointer

  - name: name
    friendly_name: Name
    description: The name of the source.
    type: string
    exposed: true
    stored: true
    required: true
    example_value: myoidc

  - name: provider
    friendly_name: Provider
    description: Select a supported OAuth2 provider.
    type: enum
    exposed: true
    stored: true
    required: true
    allowed_choices:
    - Github
    - Gitlab
    example_value: Github

  - name: scopes
    friendly_name: Scopes
    description: List of scopes to request.
    type: list
    exposed: true
    subtype: string
    stored: true
    example_value:
    - email
    - profile
