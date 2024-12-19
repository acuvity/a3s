# Model
model:
  rest_name: oidcsource
  resource_name: oidcsources
  entity_name: OIDCSource
  friendly_name: OIDC Source
  package: a3s
  group: authn/source
  description: An OIDC Auth source can be used to issue tokens based on existing OIDC
    accounts.
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
  - '@claimfilter'

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
      The Certificate authority to use to validate the authenticity of the OIDC
      server. If left empty, the system trust stroe will be used. In most of the
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
    example_value: 12345677890.apps.googleusercontent.com

  - name: clientSecret
    friendly_name: Client Secret
    description: Client secret associated with the client ID.
    type: string
    exposed: true
    stored: true
    required: true
    example_value: Ytgbfjtj4652jHDFGls99jF
    secret: true
    transient: true
    encrypted: true

  - name: description
    friendly_name: Description
    description: The description of the object.
    type: string
    exposed: true
    stored: true

  - name: endpoint
    friendly_name: Endpoint
    description: |-
      OIDC [discovery
      endpoint](https://openid.net/specs/openid-connect-discovery-1_0.html#IssuerDiscovery).
    type: string
    exposed: true
    stored: true
    required: true
    example_value: https://accounts.google.com

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

  - name: scopes
    friendly_name: Scopes
    description: List of scopes to allow.
    type: list
    exposed: true
    subtype: string
    stored: true
    example_value:
    - email
    - profile
